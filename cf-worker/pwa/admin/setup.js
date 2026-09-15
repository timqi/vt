'use strict';

// Passkey ceremonies of the admin shell: the setup view (bootstrap, the first
// credential) and the Settings tab's Passkeys block (add / revoke / self-check).
// The master never leaves this page: only a credential entry — wrapped master, public key, ids,
// label — is POSTed, to /api/admin/bootstrap or /api/admin/credentials-add.
//
// Byte formats MUST match cf-worker/pwa/approve.js + src/webauthn.ts:
//   PRF input = SHA-256("vt-passkey-prf-v1")            (common.js)
//   K_wrap    = HKDF-SHA256(K, info="vt-master-wrap-v1") (vt.deriveKWrap)
//   k         = b64u( iv(12) || ct(32) || tag(16) )      (AES-GCM)
//   AAD       = utf8("vt-master-key-v1")(16) || SHA-256(credId)(32 RAW bytes)
//   p         = COSE public key bytes extracted from authData
//   h         = b64u(SHA-256(credId))

// The WebAuthn + wrap helpers, bound to the RP id the Worker reported.
function vtPasskeyCeremony(RP_ID) {
  var ENC = new TextEncoder();

  // Pre-warm the PRF input (a SHA-256) so the WebAuthn calls land on a resolved
  // promise inside the user-gesture window (iOS Safari is strict).
  var prfInputReady = vt.sha256(ENC.encode('vt-passkey-prf-v1'));

  function randomBytes(n) { var a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }

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
    if (!cred) throw new Error('Registration cancelled');
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
    if (!(top instanceof Map)) throw new Error('attestationObject is not a CBOR map');
    var authData = top.get('authData');
    if (!(authData instanceof Uint8Array)) throw new Error('attestationObject lacks authData');
    if (authData.length < 55) throw new Error('authData too short');
    var flags = authData[32];
    if (!(flags & 0x40)) throw new Error('authData has no attestedCredentialData (AT flag unset)');
    var off = 37 + 16; // rpIdHash(32)+flags(1)+signCount(4)=37, + aaguid(16)
    var credIdLen = (authData[off] << 8) | authData[off + 1]; off += 2;
    off += credIdLen;
    if (off > authData.length) throw new Error('credIdLen out of bounds');
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
    if (!assertion) throw new Error('Verification cancelled');
    var ext = assertion.getClientExtensionResults && assertion.getClientExtensionResults();
    var prf = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!prf) throw new Error('This Passkey lacks the PRF extension; use 1Password / YubiKey / a newer OS');
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
    if (ctTag.length !== 48) throw new Error('unexpected ciphertext length: ' + ctTag.length);
    return { k: vt.b64uEnc(concat(iv, ctTag)), h: vt.b64uEnc(a.hRaw) };
  }

  async function unwrapMasterKey(K, credId, kStr) {
    var kWrap = await vt.deriveKWrap(K);
    var kb = vt.b64uDec(kStr);
    if (kb.length !== 60) { vt.zeroize(kWrap); throw new Error('unexpected k length: ' + kb.length); }
    var iv = kb.slice(0, 12), ctTag = kb.slice(12);
    var a = await aad(credId);
    var key = await crypto.subtle.importKey('raw', kWrap, { name: 'AES-GCM' }, false, ['decrypt']);
    var mk;
    try {
      mk = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv, additionalData: a.aad }, key, ctTag));
    } catch (e) {
      vt.zeroize(kWrap);
      throw new Error('AES-GCM decrypt failed: PRF output does not match the record');
    }
    vt.zeroize(kWrap);
    if (mk.length !== 32) throw new Error('unexpected master_key length: ' + mk.length);
    return mk;
  }

  // Recover the macOS mac_key from a `vt secret export` blob. Byte format MUST
  // match src/server_macos/admin.rs::export_secret + core/crypto.rs::encrypt:
  //   blob   = b64u( nonce(12) || ct(32) || tag(16) )   (60 bytes, no AAD)
  //   key    = SHA-256(SHA-256(utf8(passphrase)))
  //   mac_key = AES-GCM-decrypt(key, nonce, ct||tag)     (32 bytes)
  // The recovered mac_key becomes the passkey-domain master, so v2 records made
  // on macOS and via the phone ceremony cross-decrypt.
  async function importMasterFromExport(blobB64u, passphrase) {
    var blob = vt.b64uDec((blobB64u || '').trim());
    if (blob.length !== 60) {
      throw new Error('unexpected export blob length: ' + blob.length + ' bytes (expected 60; copy the whole `vt secret export` output)');
    }
    var iv = blob.slice(0, 12);
    var ctTag = blob.slice(12); // 48 = ct(32) || tag(16)
    var h1 = await vt.sha256(ENC.encode(passphrase || ''));
    var keyBytes = await vt.sha256(h1);
    var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    var mk;
    try {
      mk = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ctTag));
    } catch (e) {
      vt.zeroize(keyBytes); vt.zeroize(h1);
      throw new Error('Decrypt failed: wrong passphrase or export blob');
    }
    vt.zeroize(keyBytes); vt.zeroize(h1);
    if (mk.length !== 32) { vt.zeroize(mk); throw new Error('unexpected mac_key length: ' + mk.length); }
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

  return {
    createPasskey: createPasskey, assertPrf: assertPrf, wrapMasterKey: wrapMasterKey,
    unwrapMasterKey: unwrapMasterKey, importMasterFromExport: importMasterFromExport,
    buildEntry: buildEntry,
  };
}

function vtPasskeyError(e, cancelled) {
  var msg = (e && e.message) ? e.message : String(e);
  if (/NotAllowed|not allowed/i.test(msg)) msg = cancelled;
  return msg;
}

// ── Setup view: bootstrap ────────────────────────────────────────────────────

vt.views.setup = function (view, data) {
  var $ = function (sel) { return view.querySelector(sel); };
  var setStatus = vt.statusLine($('.status'));
  var pk = vtPasskeyCeremony(data.rp_id);
  $('#setup-reset').hidden = !data.reset;

  // First setup MUST bind to the macOS mac_key — never a fresh random master,
  // otherwise the passkey domain would be a separate vault that can't decrypt
  // macOS-created records.
  async function buildFirstEntry(label) {
    var blobB64 = $('#master-blob').value;
    var pass = $('#master-pass').value;
    if (!(blobB64 || '').trim()) throw new Error('Run `vt secret export` on the Mac first and paste its output');
    if (!pass) throw new Error('Enter the passphrase set at `vt secret export`');
    var masterKey = await pk.importMasterFromExport(blobB64, pass);
    try {
      setStatus('① Registering the Passkey… (complete the biometric prompt)');
      var c = await pk.createPasskey(label);
      setStatus('② Reading PRF… (complete the prompt again)');
      var pr = await pk.assertPrf([c.credId]);
      var w = await pk.wrapMasterKey(pr.K, c.credId, masterKey);
      vt.zeroize(pr.K);
      return pk.buildEntry(c.credId, c.cose, w.k, w.h, label);
    } finally { vt.zeroize(masterKey); }
  }

  $('#bootstrap-run').addEventListener('click', async function () {
    var btn = this; btn.disabled = true;
    $('#setup-taken').hidden = true;
    try {
      var entry = await buildFirstEntry(($('#bootstrap-label').value || '').trim());
      setStatus('③ Submitting…');
      var resp = await vt.postJson('bootstrap', { entry: entry });
      if (resp.status === 204) { setStatus('✓ Registered and logged in', 'ok'); location.reload(); return; }
      if (resp.status === 409) {
        // Unexpected prior registration requires reset (docs/cf-worker-deploy.md#bootstrap).
        var info = await resp.json();
        var taken = $('#setup-taken');
        taken.textContent = 'This service was initialized at ' + vt.fmtTime(info.ms) + ' from IP ' + (info.ip || '?') +
          '. If that was not you: set a new SECRET (wrangler secret put SECRET) and reopen this page; the old config is then void.';
        taken.hidden = false;
        setStatus('Already initialized', 'error');
        return;
      }
      throw new Error('HTTP ' + resp.status + ' ' + (await resp.text()));
    } catch (e) {
      setStatus('Error: ' + vtPasskeyError(e, 'No matching Passkey, or the prompt was cancelled'), 'error');
      console.error(e);
    } finally { btn.disabled = false; }
  });
};

// ── Passkeys block (Settings tab): add / revoke / self-check ───────────────

vt.tabs.setup = function (panel, data) {
  var $ = function (sel) { return panel.querySelector(sel); };
  var setStatus = vt.statusLine($('.status'));
  var pk = vtPasskeyCeremony(data.rp_id);
  var entries = [];
  var epoch = 0;

  function bytesEq(a, b) {
    if (a.length !== b.length) return false;
    var d = 0; for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
  }

  async function load() {
    var resp = await vt.apiFetch(vt.api('credentials'), { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) { setStatus('Load failed: HTTP ' + resp.status, 'error'); return; }
    var json = await resp.json();
    entries = json.credentials || [];
    epoch = json.epoch;
    renderCurrent();
    populateRevoke();
  }

  // Unwrap the master with one of the existing passkeys, register the new one,
  // wrap for it and post only the entry.
  async function runAdd(label) {
    if (!entries.length) throw new Error('No existing Passkey');
    var masterKey = null;
    try {
      setStatus('① Unlocking master_key with an existing Passkey…');
      var a = await pk.assertPrf(entries.map(function (e) { return vt.b64uDec(e.i); }));
      var used = vt.b64uEnc(a.rawId);
      var old = entries.filter(function (e) { return e.i === used; })[0];
      if (!old) { vt.zeroize(a.K); throw new Error('The Passkey used is not in the current list'); }
      masterKey = await pk.unwrapMasterKey(a.K, a.rawId, old.k);
      vt.zeroize(a.K);
      setStatus('② Registering the new Passkey… (complete the biometric prompt)');
      var c = await pk.createPasskey(label);
      setStatus('③ Reading the new Passkey\'s PRF… (complete the prompt again)');
      var pr = await pk.assertPrf([c.credId]);
      var w = await pk.wrapMasterKey(pr.K, c.credId, masterKey);
      vt.zeroize(pr.K);
      var resp = await vt.postJson('credentials-add', { entry: pk.buildEntry(c.credId, c.cose, w.k, w.h, label) });
      if (resp.status === 409) throw new Error('This Passkey is already registered');
      if (!resp.ok) throw new Error('HTTP ' + resp.status + ' ' + (await resp.text()));
    } finally { if (masterKey) vt.zeroize(masterKey); }
  }

  async function runRevoke() {
    var h = $('#revoke-pick').value;
    var e = entries.filter(function (x) { return x.h === h; })[0];
    if (!e) throw new Error('Pick a Passkey to revoke');
    if (!confirm('Revoke "' + (e.l || e.i.slice(0, 12)) + '"? Every session, including this one, ends immediately.')) return false;
    var resp = await vt.postJson('credentials-revoke', { h: h });
    if (resp.status === 409) throw new Error('This is the last Passkey; it cannot be revoked');
    if (resp.status !== 204) throw new Error('HTTP ' + resp.status + ' ' + (await resp.text()));
    return true;
  }

  async function selfCheck() {
    if (!entries.length) throw new Error('Nothing to verify');
    var ref = null;
    try {
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        setStatus('Self-check ' + (i + 1) + '/' + entries.length + ': ' + (e.l || e.i.slice(0, 8)) + '…');
        var a = await pk.assertPrf([vt.b64uDec(e.i)]);
        var mk = await pk.unwrapMasterKey(a.K, a.rawId, e.k);
        vt.zeroize(a.K);
        if (ref === null) { ref = mk; }
        else {
          var same = bytesEq(ref, mk); vt.zeroize(mk);
          if (!same) throw new Error('Entry "' + (e.l || i) + '" unlocks a different master_key than the others');
        }
      }
      setStatus('✓ Self-check passed: all ' + entries.length + ' entries unlock the same master_key', 'ok');
    } finally { if (ref) vt.zeroize(ref); }
  }

  // ── UI wiring ───────────────────────────────────────────────────────────────

  function mode() {
    var r = $('input[name="mode"]:checked');
    return r ? r.value : 'add';
  }

  function refreshModeUI() {
    var m = mode();
    $('#label-section').hidden = (m === 'revoke');
    $('#revoke-section').hidden = (m !== 'revoke');
  }

  function populateRevoke() {
    var sel = $('#revoke-pick');
    sel.innerHTML = '';
    entries.forEach(function (e) {
      var o = document.createElement('option');
      o.value = e.h;
      o.textContent = (e.l || '(no label)') + ' — ' + e.i.slice(0, 12) + '…';
      sel.appendChild(o);
    });
  }

  panel.querySelectorAll('input[name="mode"]').forEach(function (r) {
    r.addEventListener('change', refreshModeUI);
  });

  $('#run').addEventListener('click', async function () {
    var btn = this; btn.disabled = true;
    try {
      if (mode() === 'add') {
        await runAdd(($('#label').value || '').trim());
        setStatus('✓ Added. Run Self-check to verify each entry.', 'ok');
        await load();
      } else if (await runRevoke()) {
        // The epoch bump ended this session too; the 401 on the next request
        // shows the login view, so go there now.
        vt.showLogin('Revoked; all sessions ended, please log in again');
      }
    } catch (e) {
      setStatus('Error: ' + vtPasskeyError(e, 'No matching Passkey, or the prompt was cancelled'), 'error');
      console.error(e);
    } finally { btn.disabled = false; }
  });

  $('#selfcheck').addEventListener('click', async function () {
    var btn = this; btn.disabled = true;
    try { await selfCheck(); }
    catch (e) {
      setStatus('Self-check failed: ' + vtPasskeyError(e, 'cancelled or no matching Passkey (aborted)'), 'error');
      console.error(e);
    } finally { btn.disabled = false; }
  });

  // textContent everywhere (labels are operator-controlled at registration).
  var list = vt.list($('#creds').parentNode);   // rows on a phone, the table on desktop
  function renderCurrent() {
    $('#current-meta').textContent = entries.length + ' total · epoch ' + epoch;
    list.clear();
    entries.forEach(function (e) {
      var name = e.l || '(no label)';
      var id = String(e.i || '').slice(0, 12) + '…';
      var when = '';
      if (typeof e.t === 'number' && e.t > 0) {
        try { when = new Date(e.t * 1000).toISOString().slice(0, 10); } catch (_) {}
      }
      list.body().appendChild(list.item({
        cells: function () {
          return [vt.el('td', null, name), vt.el('td', 'mono', id), vt.el('td', null, when)];
        },
        row: function () { return { main: name, sub: id + (when ? ' · ' + when : '') }; },
      }));
    });
    if (!entries.length) list.empty('No Passkeys');
  }
  vt.onLayout(renderCurrent);

  vt.seg($('#modes'));
  refreshModeUI();
  load();
};
