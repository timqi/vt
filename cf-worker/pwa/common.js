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

    vt.PRF_INFO_BYTES = new TextEncoder().encode('vt-master-wrap-v1');

    // K_wrap = HKDF-SHA256(K, salt=empty, info="vt-master-wrap-v1", L=32)
    vt.deriveKWrap = async function (k) {
        var kKey = await crypto.subtle.importKey('raw', k, { name: 'HKDF' }, false, ['deriveBits']);
        return new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: vt.PRF_INFO_BYTES },
            kKey, 256));
    };

    // DEK[i] = HKDF-SHA256(master_key, salt=saltBytes, info="vt-dek-v2", L=32)
    vt.deriveDek = async function (masterKey, saltBytes) {
        var mKey = await crypto.subtle.importKey('raw', masterKey, { name: 'HKDF' }, false, ['deriveBits']);
        return new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: new TextEncoder().encode('vt-dek-v2') },
            mKey, 256));
    };

    vt.zeroize = function (arr) { if (!arr) return; try { arr.fill(0); } catch (_) {} };

    window.vt = vt;
})();
