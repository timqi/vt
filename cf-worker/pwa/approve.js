// vt-passkey v2 approve ceremony.
//
// v2 change from v1: instead of sealing master_key (32 bytes), derive one
// DEK per salt received from the challenge, seal all DEKs concatenated
// ([DEK_0 || ... || DEK_n-1]) to the daemon's X25519 pubkey. The daemon
// opens the sealed box and gets the DEKs directly without ever holding
// master_key.

'use strict';

(function () {
    var data = vt.bootData();
    if (!data) return;
    var b64uDec = vt.b64uDec, b64uEnc = vt.b64uEnc, setStatus = vt.setStatus;

    function renderMeta(meta) {
        var dl = document.getElementById('meta');
        dl.innerHTML = '';
        if (!meta) return;
        var fields = [
            ['host', 'host'], ['ip', 'IP'], ['command', '命令'],
            ['reason', '原因'], ['op_kind', '类型']
        ];
        for (var i = 0; i < fields.length; i++) {
            var key = fields[i][0], label = fields[i][1];
            if (meta[key] == null || meta[key] === '') continue;
            var row = document.createElement('div');
            var dt = document.createElement('dt'); dt.textContent = label;
            var dd = document.createElement('dd'); dd.textContent = String(meta[key]);
            row.appendChild(dt); row.appendChild(dd);
            dl.appendChild(row);
        }
    }
    renderMeta(data.metadata);

    async function runApprove() {
        var k = null, kWrap = null, masterKey = null, deks = null;
        try {
            setStatus('正在等待 libsodium 初始化…');
            if (typeof sodium === 'undefined' || !sodium.ready) throw new Error('libsodium 未加载');
            await sodium.ready;

            // PRF input = SHA-256("vt-passkey-prf-v1")
            var PRF_INPUT = new Uint8Array(await crypto.subtle.digest(
                'SHA-256', new TextEncoder().encode('vt-passkey-prf-v1')));

            var evalByCredential = {};
            for (var i = 0; i < data.allow_credentials.length; i++) {
                evalByCredential[data.allow_credentials[i].id_b64u] = { first: PRF_INPUT };
            }

            setStatus('请触摸 Passkey 完成验证…');
            var assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: b64uDec(data.challenge_b64u),
                    rpId: data.rp_id,
                    allowCredentials: data.allow_credentials.map(function (c) {
                        return { type: 'public-key', id: b64uDec(c.id_b64u) };
                    }),
                    userVerification: 'required',
                    extensions: { prf: { evalByCredential: evalByCredential } },
                },
            });

            var usedId = b64uEnc(new Uint8Array(assertion.rawId));
            var entry = null;
            for (var j = 0; j < data.allow_credentials.length; j++) {
                if (data.allow_credentials[j].id_b64u === usedId) { entry = data.allow_credentials[j]; break; }
            }
            if (!entry) throw new Error('used credential not in allow list');

            var ext = assertion.getClientExtensionResults && assertion.getClientExtensionResults();
            var prfResult = ext && ext.prf && ext.prf.results && ext.prf.results.first;
            if (!prfResult) {
                setStatus('Passkey 不支持 PRF——请用 1Password / YubiKey 重试', 'error');
                return;
            }
            k = new Uint8Array(prfResult);

            // Derive K_wrap, decrypt master_key
            kWrap = await vt.deriveKWrap(k);
            var kBytes = b64uDec(entry.k_b64u);
            if (kBytes.length !== 12 + 32 + 16) throw new Error('encrypted_master_key wrong length: ' + kBytes.length);
            var iv = kBytes.slice(0, 12);
            var ctTag = kBytes.slice(12);
            var hBytes = b64uDec(entry.h_b64u);
            var aad = new Uint8Array(16 + hBytes.length);
            aad.set(new TextEncoder().encode('vt-master-key-v1'), 0);
            aad.set(hBytes, 16);
            var kWrapKey = await crypto.subtle.importKey('raw', kWrap, { name: 'AES-GCM' }, false, ['decrypt']);
            var masterKeyBuf;
            try {
                masterKeyBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, kWrapKey, ctTag);
            } catch (e) {
                throw new Error('AES-GCM 解密失败：可能是 PRF 输出与 entry 不匹配');
            }
            masterKey = new Uint8Array(masterKeyBuf);
            if (masterKey.length !== 32) throw new Error('master_key 长度异常: ' + masterKey.length);

            // --- v2: derive one DEK per salt, seal all to daemon pubkey ---
            var salts = data.salts_b64u || [];
            deks = new Uint8Array(Math.max(salts.length, 1) * 32);
            if (salts.length === 0) {
                // Auth-only: no DEKs needed. Use a zero DEK placeholder so
                // sealed box is non-empty but well-defined.
                // The daemon discards it for auth-only operations.
                deks.fill(0);
            } else {
                for (var s = 0; s < salts.length; s++) {
                    var saltBytes = b64uDec(salts[s]);
                    var dek = await vt.deriveDek(masterKey, saltBytes);
                    deks.set(dek, s * 32);
                    dek.fill(0);
                }
            }
            masterKey.fill(0); kWrap.fill(0); k.fill(0);
            masterKey = null; kWrap = null; k = null;

            var daemonPk = b64uDec(data.daemon_pubkey_b64u);
            if (daemonPk.length !== 32) throw new Error('daemon_pubkey 长度异常');
            var sealedDeks = sodium.crypto_box_seal(deks, daemonPk);
            deks.fill(0); deks = null;

            setStatus('正在提交审批…');
            var resp = await fetch(vt.apiPath('/api/approve'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    approve_token: data.approve_token,
                    credential_id_b64u: usedId,
                    sealed_deks_b64u: b64uEnc(sealedDeks),
                    client_data_json_b64u: b64uEnc(new Uint8Array(assertion.response.clientDataJSON)),
                    authenticator_data_b64u: b64uEnc(new Uint8Array(assertion.response.authenticatorData)),
                    signature_b64u: b64uEnc(new Uint8Array(assertion.response.signature)),
                }),
            });
            if (!resp.ok) throw new Error('审批失败（HTTP ' + resp.status + '）');
            setStatus('审批成功，可关闭页面', 'ok');
            document.getElementById('approve').disabled = true;
            document.getElementById('reject').disabled = true;
        } catch (e) {
            setStatus('错误：' + (e.message || e), 'error');
            console.error(e);
        } finally {
            vt.zeroize(k); vt.zeroize(kWrap); vt.zeroize(masterKey); vt.zeroize(deks);
        }
    }

    async function runReject() {
        var approveBtn = document.getElementById('approve');
        var rejectBtn = document.getElementById('reject');
        approveBtn.disabled = true; rejectBtn.disabled = true;
        try {
            setStatus('请触摸 Passkey 完成拒绝…');
            var assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: b64uDec(data.challenge_b64u),
                    rpId: data.rp_id,
                    allowCredentials: data.allow_credentials.map(function (c) {
                        return { type: 'public-key', id: b64uDec(c.id_b64u) };
                    }),
                    userVerification: 'required',
                },
            });
            var usedId = b64uEnc(new Uint8Array(assertion.rawId));
            setStatus('正在提交拒绝…');
            var resp = await fetch(vt.apiPath('/api/reject'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    approve_token: data.approve_token,
                    credential_id_b64u: usedId,
                    client_data_json_b64u: b64uEnc(new Uint8Array(assertion.response.clientDataJSON)),
                    authenticator_data_b64u: b64uEnc(new Uint8Array(assertion.response.authenticatorData)),
                    signature_b64u: b64uEnc(new Uint8Array(assertion.response.signature)),
                }),
            });
            if (!resp.ok) {
                if (resp.status === 410) setStatus('请求已失效（可能已审批或超时）', 'error');
                else setStatus('拒绝失败（HTTP ' + resp.status + '）', 'error');
                approveBtn.disabled = false; rejectBtn.disabled = false;
                return;
            }
            setStatus('已拒绝，请关闭页面', 'ok');
        } catch (e) {
            setStatus('错误：' + (e.message || e), 'error');
            console.error(e);
            approveBtn.disabled = false; rejectBtn.disabled = false;
        }
    }

    document.getElementById('approve').addEventListener('click', runApprove);
    document.getElementById('reject').addEventListener('click', runReject);
})();
