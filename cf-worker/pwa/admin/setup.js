'use strict';

// Pure client-side CREDENTIALS_JSON generator. master_key never leaves this
// page and is never POSTed anywhere — the user copies the output and deploys it
// manually via `wrangler secret put CREDENTIALS_JSON`.
//
// Byte formats MUST match cf-worker/pwa/approve.js + src/webauthn.ts:
//   PRF input = SHA-256("vt-passkey-prf-v1")            (common.js)
//   K_wrap    = HKDF-SHA256(K, info="vt-master-wrap-v1") (vt.deriveKWrap)
//   k         = b64u( iv(12) || ct(32) || tag(16) )      (AES-GCM)
//   AAD       = utf8("vt-master-key-v1")(16) || SHA-256(credId)(32 RAW bytes)
//   p         = COSE public key bytes extracted from authData
//   h         = b64u(SHA-256(credId))

(function () {
  var data = vt.bootData();
  if (!data || !data.rp_id) { vt.setStatus('页面初始化失败：缺少 rp_id', 'error'); return; }
  var RP_ID = data.rp_id;
  var ENC = new TextEncoder();

  // Pre-warm the PRF input (a SHA-256) so the WebAuthn calls land on a resolved
  // promise inside the user-gesture window (iOS Safari is strict).
  var prfInputReady = vt.sha256(ENC.encode('vt-passkey-prf-v1'));

  function randomBytes(n) { var a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }
  function bytesEq(a, b) {
    if (a.length !== b.length) return false;
    var d = 0; for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
  }

  // ── WebAuthn ──────────────────────────────────────────────────────────────

  async function createPasskey(label) {
    var cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: RP_ID, name: 'vt-passkey' },
        user: { id: randomBytes(16), name: label || 'vt', displayName: label || 'vt' },
        challenge: randomBytes(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        extensions: { prf: {} },
      },
    });
    if (!cred) throw new Error('注册被取消');
    var credId = new Uint8Array(cred.rawId);
    var att = new Uint8Array(cred.response.attestationObject);
    return { credId: credId, cose: extractCose(att) };
  }

  // Two-step: attestationObject is CBOR; authData inside it is FLAT binary
  // (FIDO2 §6.1); only the trailing COSE key is CBOR. Delimit by the CBOR map's
  // consumed length, NOT to end-of-authData — extension data (ED flag, set when
  // we request prf) would otherwise be appended to p.
  function extractCose(att) {
    var top = window.vtCbor.read(att, 0).value;
    if (!(top instanceof Map)) throw new Error('attestationObject 非 CBOR map');
    var authData = top.get('authData');
    if (!(authData instanceof Uint8Array)) throw new Error('attestationObject 缺少 authData');
    if (authData.length < 55) throw new Error('authData 过短');
    var flags = authData[32];
    if (!(flags & 0x40)) throw new Error('authData 未含 attestedCredentialData (AT 未置位)');
    var off = 37 + 16; // rpIdHash(32)+flags(1)+signCount(4)=37, + aaguid(16)
    var credIdLen = (authData[off] << 8) | authData[off + 1]; off += 2;
    off += credIdLen;
    if (off > authData.length) throw new Error('credIdLen 越界');
    var parsed = window.vtCbor.read(authData, off); // exactly one COSE map
    return authData.slice(off, parsed.end);
  }

  // Run an assertion with the PRF extension over the given credential ids.
  async function assertPrf(allowIds) {
    var PRF_INPUT = await prfInputReady;
    var assertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        rpId: RP_ID,
        allowCredentials: allowIds.map(function (id) { return { type: 'public-key', id: id }; }),
        userVerification: 'required',
        extensions: { prf: { eval: { first: PRF_INPUT } } },
      },
    });
    if (!assertion) throw new Error('验证被取消');
    var ext = assertion.getClientExtensionResults && assertion.getClientExtensionResults();
    var prf = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!prf) throw new Error('此 Passkey 不支持 PRF 扩展，请换用 1Password / YubiKey / 新版系统');
    return { rawId: new Uint8Array(assertion.rawId), K: new Uint8Array(prf) };
  }

  // ── master_key wrap / unwrap (byte-exact with approve.js) ──────────────────

  async function aad(credId) {
    var hRaw = await vt.sha256(credId);
    return { aad: concat(ENC.encode('vt-master-key-v1'), hRaw), hRaw: hRaw };
  }

  async function wrapMasterKey(K, credId, masterKey) {
    var kWrap = await vt.deriveKWrap(K);
    var a = await aad(credId);
    var iv = randomBytes(12);
    var key = await crypto.subtle.importKey('raw', kWrap, { name: 'AES-GCM' }, false, ['encrypt']);
    var ctTag = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, additionalData: a.aad }, key, masterKey));
    vt.zeroize(kWrap);
    if (ctTag.length !== 48) throw new Error('密文长度异常: ' + ctTag.length);
    return { k: vt.b64uEnc(concat(iv, ctTag)), h: vt.b64uEnc(a.hRaw) };
  }

  async function unwrapMasterKey(K, credId, kStr) {
    var kWrap = await vt.deriveKWrap(K);
    var kb = vt.b64uDec(kStr);
    if (kb.length !== 60) { vt.zeroize(kWrap); throw new Error('k 长度异常: ' + kb.length); }
    var iv = kb.slice(0, 12), ctTag = kb.slice(12);
    var a = await aad(credId);
    var key = await crypto.subtle.importKey('raw', kWrap, { name: 'AES-GCM' }, false, ['decrypt']);
    var mk;
    try {
      mk = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv, additionalData: a.aad }, key, ctTag));
    } catch (e) {
      vt.zeroize(kWrap);
      throw new Error('AES-GCM 解密失败：PRF 输出与记录不匹配');
    }
    vt.zeroize(kWrap);
    if (mk.length !== 32) throw new Error('master_key 长度异常: ' + mk.length);
    return mk;
  }

  function buildEntry(credId, cose, k, h, label) {
    return {
      h: h,
      i: vt.b64uEnc(credId),
      k: k,
      p: vt.b64uEnc(cose),
      l: label || '',
      t: Math.floor(Date.now() / 1000),
    };
  }

  function parseExisting() {
    var raw = document.getElementById('existing').value.trim();
    if (!raw) throw new Error('请粘贴现有 CREDENTIALS_JSON');
    var blob;
    try { blob = JSON.parse(raw); } catch (e) { throw new Error('JSON 解析失败: ' + (e.message || e)); }
    if (blob.v !== 1 || !Array.isArray(blob.c)) throw new Error('CREDENTIALS_JSON 格式不符 (需 v=1, c[])');
    return blob;
  }

  // ── Flows ──────────────────────────────────────────────────────────────────

  var lastBlob = null;

  async function runBootstrap(label) {
    var masterKey = randomBytes(32);
    try {
      vt.setStatus('① 注册新 Passkey…（请完成生物识别）');
      var pk = await createPasskey(label);
      vt.setStatus('② 读取 PRF…（请再次完成生物识别）');
      var pr = await assertPrf([pk.credId]);
      var w = await wrapMasterKey(pr.K, pk.credId, masterKey);
      vt.zeroize(pr.K);
      var blob = { v: 1, epoch: 1, c: [buildEntry(pk.credId, pk.cose, w.k, w.h, label)] };
      return blob;
    } finally { vt.zeroize(masterKey); }
  }

  async function runAdd(label) {
    var blob = parseExisting();
    var masterKey = null;
    try {
      vt.setStatus('① 用现有 Passkey 解出 master_key…');
      var ids = blob.c.map(function (e) { return vt.b64uDec(e.i); });
      var a = await assertPrf(ids);
      var used = vt.b64uEnc(a.rawId);
      var old = null;
      for (var i = 0; i < blob.c.length; i++) { if (blob.c[i].i === used) { old = blob.c[i]; break; } }
      if (!old) { vt.zeroize(a.K); throw new Error('使用的 Passkey 不在现有列表中'); }
      masterKey = await unwrapMasterKey(a.K, a.rawId, old.k);
      vt.zeroize(a.K);

      vt.setStatus('② 注册新 Passkey…（请完成生物识别）');
      var pk = await createPasskey(label);
      vt.setStatus('③ 读取新 Passkey 的 PRF…（请再次完成生物识别）');
      var pr = await assertPrf([pk.credId]);
      var w = await wrapMasterKey(pr.K, pk.credId, masterKey);
      vt.zeroize(pr.K);
      blob.c.push(buildEntry(pk.credId, pk.cose, w.k, w.h, label)); // existing entries untouched
      return blob;
    } finally { if (masterKey) vt.zeroize(masterKey); }
  }

  function runRevoke() {
    var blob = parseExisting();
    var sel = document.getElementById('revoke-pick');
    var idx = parseInt(sel.value, 10);
    if (!(idx >= 0 && idx < blob.c.length)) throw new Error('请选择要吊销的条目');
    blob.c.splice(idx, 1);
    blob.epoch = (typeof blob.epoch === 'number' ? blob.epoch : 1) + 1;
    return blob;
  }

  async function selfCheck(blob) {
    if (!blob || !blob.c.length) throw new Error('无可校验条目');
    var ref = null;
    try {
      for (var i = 0; i < blob.c.length; i++) {
        var e = blob.c[i];
        vt.setStatus('自检 ' + (i + 1) + '/' + blob.c.length + '：' + (e.l || e.i.slice(0, 8)) + '…');
        var a = await assertPrf([vt.b64uDec(e.i)]);
        var mk = await unwrapMasterKey(a.K, a.rawId, e.k);
        vt.zeroize(a.K);
        if (ref === null) { ref = mk; }
        else {
          var same = bytesEq(ref, mk); vt.zeroize(mk);
          if (!same) throw new Error('条目 “' + (e.l || i) + '” 解出的 master_key 与其它条目不一致');
        }
      }
      vt.setStatus('✓ 自检通过：所有 ' + blob.c.length + ' 个条目解出同一 master_key', 'ok');
    } finally { if (ref) vt.zeroize(ref); }
  }

  // ── UI wiring ───────────────────────────────────────────────────────────────

  function mode() {
    var r = document.querySelector('input[name="mode"]:checked');
    return r ? r.value : 'bootstrap';
  }

  function refreshModeUI() {
    var m = mode();
    document.getElementById('existing-section').hidden = (m === 'bootstrap');
    document.getElementById('label-section').hidden = (m === 'revoke');
    document.getElementById('revoke-section').hidden = (m !== 'revoke');
    if (m === 'revoke') populateRevoke();
  }

  function populateRevoke() {
    var sel = document.getElementById('revoke-pick');
    sel.innerHTML = '';
    try {
      var blob = parseExisting();
      blob.c.forEach(function (e, i) {
        var o = document.createElement('option');
        o.value = String(i);
        o.textContent = (e.l || '(无标签)') + ' — ' + e.i.slice(0, 12) + '…';
        sel.appendChild(o);
      });
    } catch (e) { /* ignore until valid JSON pasted */ }
  }

  function output(blob) {
    lastBlob = blob;
    document.getElementById('output').value = JSON.stringify(blob, null, 2);
    document.getElementById('output-section').hidden = false;
    document.getElementById('selfcheck').hidden = false;
  }

  document.querySelectorAll('input[name="mode"]').forEach(function (r) {
    r.addEventListener('change', refreshModeUI);
  });
  document.getElementById('existing').addEventListener('input', function () {
    if (mode() === 'revoke') populateRevoke();
  });

  document.getElementById('run').addEventListener('click', async function () {
    var btn = this; btn.disabled = true;
    try {
      var label = (document.getElementById('label').value || '').trim();
      var m = mode();
      var blob;
      if (m === 'bootstrap') blob = await runBootstrap(label);
      else if (m === 'add') blob = await runAdd(label);
      else blob = runRevoke();
      output(blob);
      vt.setStatus('✓ 已生成。请复制并 `wrangler secret put CREDENTIALS_JSON`。' +
        (m === 'revoke' ? '' : ' 建议点“自检”逐条验证。'), 'ok');
    } catch (e) {
      var msg = (e && e.message) ? e.message : String(e);
      if (/NotAllowed|not allowed/i.test(msg)) msg = '未找到匹配 Passkey 或操作被取消';
      vt.setStatus('错误：' + msg, 'error');
      console.error(e);
    } finally { btn.disabled = false; }
  });

  document.getElementById('selfcheck').addEventListener('click', async function () {
    var btn = this; btn.disabled = true;
    try { await selfCheck(lastBlob); }
    catch (e) {
      var msg = (e && e.message) ? e.message : String(e);
      if (/NotAllowed|not allowed/i.test(msg)) msg = '取消或未匹配 Passkey（自检中止）';
      vt.setStatus('自检失败：' + msg, 'error');
      console.error(e);
    } finally { btn.disabled = false; }
  });

  document.getElementById('copy').addEventListener('click', function () {
    var ta = document.getElementById('output');
    ta.select();
    navigator.clipboard.writeText(ta.value).then(
      function () { vt.setStatus('已复制到剪贴板', 'ok'); },
      function () { vt.setStatus('复制失败，请手动选择文本', 'error'); }
    );
  });

  refreshModeUI();
})();
