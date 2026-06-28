'use strict';

// Minimal CBOR reader for WebAuthn attestationObject + COSE keys.
//
// Unlike src/webauthn.ts:decodeCborMap, this reader (a) returns the number of
// bytes consumed so the caller can delimit a COSE key embedded inside a larger
// buffer, and (b) supports 2-byte (0x58/0x59…) and 4-byte (0x5a…) length forms
// needed for byte strings > 255 bytes (e.g. attStmt / large authData).
//
// read(buf, off) -> { value, end }
//   value: number | Uint8Array | string | Array | Map
//   end:   offset just past the decoded item
//
// Supported major types: 0 (uint), 1 (negint), 2 (bytes), 3 (text),
// 4 (array), 5 (map). 64-bit lengths (additional info 27) are rejected.

(function () {
  function readLen(buf, off, ai) {
    if (ai < 24) return { n: ai, off: off };
    if (ai === 24) {
      if (off + 1 > buf.length) throw new Error('CBOR: truncated len8');
      return { n: buf[off], off: off + 1 };
    }
    if (ai === 25) {
      if (off + 2 > buf.length) throw new Error('CBOR: truncated len16');
      return { n: (buf[off] << 8) | buf[off + 1], off: off + 2 };
    }
    if (ai === 26) {
      if (off + 4 > buf.length) throw new Error('CBOR: truncated len32');
      // Build unsigned 32-bit without sign issues.
      var n = (buf[off] * 0x1000000) + (buf[off + 1] << 16) + (buf[off + 2] << 8) + buf[off + 3];
      return { n: n >>> 0, off: off + 4 };
    }
    throw new Error('CBOR: 64-bit length unsupported');
  }

  function read(buf, off) {
    if (off >= buf.length) throw new Error('CBOR: out of bounds');
    var ib = buf[off++];
    var major = ib >> 5;
    var ai = ib & 0x1f;

    if (major === 0) {                          // unsigned int
      var r = readLen(buf, off, ai);
      return { value: r.n, end: r.off };
    }
    if (major === 1) {                          // negative int
      var r1 = readLen(buf, off, ai);
      return { value: -1 - r1.n, end: r1.off };
    }
    if (major === 2 || major === 3) {           // byte string / text string
      var rs = readLen(buf, off, ai);
      var start = rs.off;
      var endb = start + rs.n;
      if (endb > buf.length) throw new Error('CBOR: truncated string');
      var bytes = buf.slice(start, endb);
      return { value: major === 3 ? new TextDecoder().decode(bytes) : bytes, end: endb };
    }
    if (major === 4) {                          // array
      var ra = readLen(buf, off, ai);
      var curA = ra.off;
      var arr = [];
      for (var i = 0; i < ra.n; i++) { var ia = read(buf, curA); arr.push(ia.value); curA = ia.end; }
      return { value: arr, end: curA };
    }
    if (major === 5) {                          // map
      var rm = readLen(buf, off, ai);
      var curM = rm.off;
      var m = new Map();
      for (var j = 0; j < rm.n; j++) {
        var k = read(buf, curM); curM = k.end;
        var v = read(buf, curM); curM = v.end;
        var key = (typeof k.value === 'object') ? JSON.stringify(k.value) : k.value;
        m.set(key, v.value);
      }
      return { value: m, end: curM };
    }
    throw new Error('CBOR: unsupported major type ' + major);
  }

  window.vtCbor = { read: read };
})();
