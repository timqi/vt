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

    vt.setStatus = function (text, kind) {
        var el = document.getElementById('status');
        if (!el) return;
        el.textContent = text;
        el.className = kind || '';
    };

    vt.bootData = function () {
        var bootStatus = document.getElementById('status');
        var raw = document.getElementById('vt-data');
        if (!raw) {
            if (bootStatus) { bootStatus.textContent = '页面初始化失败：缺少 vt-data 块'; bootStatus.className = 'error'; }
            return null;
        }
        try { return JSON.parse(raw.textContent); }
        catch (e) {
            console.error('页面数据解析失败', e);
            if (bootStatus) { bootStatus.textContent = '页面数据解析失败：' + (e.message || e); bootStatus.className = 'error'; }
            return null;
        }
    };

    // Secret path prefix = first segment of the current page URL.
    // The page is served at /{prefix}/a/{token}, so split('/')[1] = prefix.
    vt.PATH_PREFIX = '/' + location.pathname.split('/')[1];
    vt.apiPath = function (suffix) { return vt.PATH_PREFIX + suffix; };

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

    vt.zeroize = function (arr) { if (!arr) return; try { arr.fill(0); } catch (_) {} };

    window.vt = vt;
})();
