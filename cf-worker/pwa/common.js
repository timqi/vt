'use strict';

(function () {
    var vt = {};

    vt.b64uDec = function (s) {
        var pad = s.length % 4 === 0 ? s : s + '='.repeat(4 - (s.length % 4));
        var bin = atob(pad.replace(/-/g, '+').replace(/_/g, '/'));
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    };

    vt.b64uEnc = function (bytes) {
        var bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };

    // ── DOM + formatting helpers shared by both shells (docs/design/ui-ux.md) ──

    vt.el = function (tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    };

    // One status line per surface: returns a setter that keeps the element's
    // own classes and swaps only the kind ('' | 'ok' | 'error').
    vt.statusLine = function (el) {
        var base = el.className;
        return function (text, kind) {
            el.textContent = text || '';
            el.className = kind ? base + ' ' + kind : base;
        };
    };

    // Segmented control (.seg): radios inside labels; the thumb slides by
    // transform to the checked option. --n / --i go through CSSOM (allowed under
    // `style-src 'self'`), so the CSS never measures anything.
    vt.seg = function (seg) {
        var thumb = vt.el('span', 'seg-thumb');
        thumb.setAttribute('aria-hidden', 'true');
        seg.insertBefore(thumb, seg.firstChild);
        function sync() {
            var inputs = seg.querySelectorAll('input');
            var i = 0;
            inputs.forEach(function (x, k) { if (x.checked) i = k; });
            seg.style.setProperty('--n', String(inputs.length));
            seg.style.setProperty('--i', String(i));
        }
        seg.addEventListener('change', sync);
        sync();
        return sync;
    };

    // Parse the #vt-data block; null (and a console error) when absent/invalid.
    vt.bootData = function () {
        var raw = document.getElementById('vt-data');
        if (!raw) { console.error('page init failed: vt-data block missing'); return null; }
        try { return JSON.parse(raw.textContent); }
        catch (e) { console.error('page data parse failed', e); return null; }
    };

    // Absolute local time, YYYY-MM-DD HH:MM:SS; '' for anything but a positive ms.
    vt.fmtTime = function (ms) {
        if (typeof ms !== 'number' || ms <= 0) return '';
        var d = new Date(ms);
        var p = function (n) { return (n < 10 ? '0' : '') + n; };
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
            ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    };

    // Coarse remaining-time label; callers re-render on a ticker, so minute
    // granularity is honest (never a second-precision value that is stale).
    vt.fmtRemaining = function (ms) {
        if (ms <= 0) return 'expired';
        var mins = Math.floor(ms / 60000);
        if (mins < 1) return '< 1 min';
        if (mins < 60) return mins + ' min';
        // Roll over to days past 24h: with a one-week ceiling, "167 h 47 min" is
        // a number an operator has to do arithmetic on before judging the risk.
        if (mins >= 1440) {
            var d = Math.floor(mins / 1440), dh = Math.floor((mins % 1440) / 60);
            return d + ' d' + (dh ? ' ' + dh + ' h' : '');
        }
        var h = Math.floor(mins / 60), m = mins % 60;
        return h + ' h' + (m ? ' ' + m + ' min' : '');
    };

    vt.ttlLabel = function (s) {
        if (s === 0) return 'No cache';
        if (s % 604800 === 0) return (s / 604800) + ' w';
        if (s % 86400 === 0) return (s / 86400) + ' d';
        if (s % 3600 === 0) return (s / 3600) + ' h';
        if (s % 60 === 0) return (s / 60) + ' min';
        return s + ' s';
    };

    var PRF_INFO_BYTES = new TextEncoder().encode('vt-master-wrap-v1');
    var DEK_INFO_BYTES = new TextEncoder().encode('vt-dek-v2');

    vt.sha256 = async function (data) {
        return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    };

    // HKDF-SHA256(ikm, salt, info, L=32). salt defaults to empty.
    vt.hkdfSha256 = async function (ikm, info, lenBytes, salt) {
        var key = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
        return new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: salt || new Uint8Array(0), info: info },
            key, (lenBytes || 32) * 8));
    };

    // K_wrap = HKDF-SHA256(K, salt=empty, info="vt-master-wrap-v1", L=32)
    vt.deriveKWrap = function (k) { return vt.hkdfSha256(k, PRF_INFO_BYTES, 32); };

    // DEK[i] = HKDF-SHA256(master_key, salt=saltBytes, info="vt-dek-v2", L=32)
    vt.deriveDek = function (masterKey, saltBytes) {
        return vt.hkdfSha256(masterKey, DEK_INFO_BYTES, 32, saltBytes);
    };

    vt.hmacSha256 = async function (keyBytes, data) {
        var key = await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
    };

    // ── Sealed box v1 (docs/sealed-box-v1.md): X25519 → HKDF → AES-256-GCM ──
    // Same bytes as cf-worker/src/cache_crypto.ts and src/cf.rs. No fallback:
    // a browser without X25519 in crypto.subtle (Safari < 17, Chrome < 133,
    // Firefox < 130) fails here, before any WebAuthn prompt.

    var X25519 = { name: 'X25519' };
    var SEALED_BOX_INFO = new TextEncoder().encode('vt-sealed-box-v1');

    // { privateKey (non-extractable CryptoKey), pk (32 raw bytes) }.
    vt.x25519Keypair = async function () {
        var kp;
        try {
            kp = await crypto.subtle.generateKey(X25519, false, ['deriveBits']);
        } catch (_) {
            throw new Error('This browser lacks X25519 (needs Safari 17 / Chrome 133 / Firefox 130 or newer)');
        }
        return { privateKey: kp.privateKey, pk: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) };
    };

    // X25519(privateKey, peerPk) → 32 bytes; the all-zero result (low-order
    // peer point) is refused.
    vt.x25519 = async function (privateKey, peerPk) {
        var pub = await crypto.subtle.importKey('raw', peerPk, X25519, false, []);
        var ss = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, privateKey, 256));
        if (ss.every(function (b) { return b === 0; })) throw new Error('X25519 shared secret is zero');
        return ss;
    };

    // seal(m, recipientPk) → epk(32) ‖ AES-256-GCM(HKDF(ss, salt=epk‖rpk,
    // info), nonce 0^12, m, aad=epk‖rpk). One ephemeral key per message; the
    // AES key is derived straight into a non-extractable CryptoKey.
    vt.sealBox = async function (m, recipientPk) {
        if (recipientPk.length !== 32) throw new Error('unexpected recipient key length');
        var eph = await vt.x25519Keypair();
        var header = new Uint8Array(64);
        header.set(eph.pk, 0);
        header.set(recipientPk, 32);
        var ss = await vt.x25519(eph.privateKey, recipientPk);
        var key;
        try {
            var ikm = await crypto.subtle.importKey('raw', ss, 'HKDF', false, ['deriveKey']);
            key = await crypto.subtle.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt: header, info: SEALED_BOX_INFO },
                ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        } finally {
            ss.fill(0);
        }
        var ct = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: new Uint8Array(12), additionalData: header }, key, m));
        var out = new Uint8Array(32 + ct.length);
        out.set(eph.pk, 0);
        out.set(ct, 32);
        return out;
    };

    vt.zeroize = function (arr) { if (!arr) return; try { arr.fill(0); } catch (_) {} };

    // Notification hand-off (sw.js): the worker holds the approval a tap should
    // land on and hands it to the page, which navigates itself — an iOS
    // home-screen app answers a tap by showing its start page whatever the
    // worker navigates. Only an approval path is followed, never an arbitrary URL.
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.addEventListener('message', function (e) {
            if (!e.data || e.data.type !== 'vt-navigate' || typeof e.data.url !== 'string') return;
            var u = new URL(e.data.url, location.origin);
            if (u.origin !== location.origin || u.pathname.lastIndexOf('/a/', 0) !== 0) return;
            // An approval already on screen owns the page: navigating away mid
            // ceremony aborts the WebAuthn prompt (it surfaces as "cancelled").
            if (document.querySelector('.vt-approve')) return;
            if (u.pathname === location.pathname) return;
            // The loaded console mounts the request in its sheet instead
            // (audit.js); everything else loads the standalone page.
            var token = u.pathname.slice('/a/'.length);
            if (vt.openApprovalSheet && vt.openApprovalSheet(token)) return;
            location.replace(u.href);
        });
        var cleaningNotifications = false;
        async function cleanNotifications() {
            if (document.visibilityState !== 'visible' || cleaningNotifications) return;
            cleaningNotifications = true;
            try {
                var reg = await navigator.serviceWorker.ready;
                if (!reg.getNotifications) return;
                var notifications = await reg.getNotifications();
                for (var notification of notifications) {
                    // Only approval/enrollment tags; cache-hit and test notices stay.
                    if (!/^a:[A-Za-z0-9_-]{16}$/.test(notification.tag)) continue;
                    try {
                        var res = await fetch('/api/page/' + notification.tag.slice(2), {
                            cache: 'no-store', redirect: 'error',
                        });
                        if (res.status !== 404 && res.status !== 410) continue;
                        var data = await res.json();
                        if ((res.status === 410 && data.error === 'gone') ||
                            (res.status === 404 && data.error === 'not_found')) notification.close();
                    } catch (_) { /* unknown state: retain the notification for the next visit */ }
                }
            } catch (_) { /* notification access is best-effort */ }
            finally { cleaningNotifications = false; }
        }
        document.addEventListener('visibilitychange', cleanNotifications);
        window.addEventListener('pageshow', cleanNotifications);
        navigator.serviceWorker.ready.then(function (reg) {
            cleanNotifications();
            var sw = navigator.serviceWorker.controller || reg.active;
            if (sw) sw.postMessage({ type: 'vt-pending' });
        }).catch(function () { /* no worker registered: notifications are off anyway */ });
    }

    window.vt = vt;
})();
