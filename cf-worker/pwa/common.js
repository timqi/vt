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

    // Parse the #vt-data block; null (and a console error) when absent/invalid.
    vt.bootData = function () {
        var raw = document.getElementById('vt-data');
        if (!raw) { console.error('页面初始化失败：缺少 vt-data 块'); return null; }
        try { return JSON.parse(raw.textContent); }
        catch (e) { console.error('页面数据解析失败', e); return null; }
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
        if (ms <= 0) return '已过期';
        var mins = Math.floor(ms / 60000);
        if (mins < 1) return '< 1 分钟';
        if (mins < 60) return mins + ' 分钟';
        // Roll over to days past 24h: with a one-week ceiling, "167 小时 47 分" is
        // a number an operator has to do arithmetic on before judging the risk.
        if (mins >= 1440) {
            var d = Math.floor(mins / 1440), dh = Math.floor((mins % 1440) / 60);
            return d + ' 天' + (dh ? ' ' + dh + ' 小时' : '');
        }
        var h = Math.floor(mins / 60), m = mins % 60;
        return h + ' 小时' + (m ? ' ' + m + ' 分' : '');
    };

    vt.ttlLabel = function (s) {
        if (s === 0) return '不缓存';
        if (s % 604800 === 0) return (s / 604800) + ' 周';
        if (s % 86400 === 0) return (s / 86400) + ' 天';
        if (s % 3600 === 0) return (s / 3600) + ' 小时';
        if (s % 60 === 0) return (s / 60) + ' 分钟';
        return s + ' 秒';
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

    vt.zeroize = function (arr) { if (!arr) return; try { arr.fill(0); } catch (_) {} };

    window.vt = vt;
})();
