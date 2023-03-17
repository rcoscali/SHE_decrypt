#!/usr/bin/env node

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */

    const SHE = require('./SHE_decrypt.js');

    test('SHE_decrypt: KDF', () =>
        {
	    var she = new SHE();
	    var bufferKey = Buffer.from('0153f7000099ed9f320451aa8a7d9707', 'hex');
	    expect(she.KDF(bufferKey).toString('hex')).toBe('0937e1e1690a81c388dd50ac10965b2f');
        }
    );

    test('SHE_decrypt: decrypt_M2', () =>
        {
	    var she = new SHE();
	    var bufferM2 = Buffer.from('000000000000000000000000000000413e38f7c374d4a3f39547b556893861d251195ce2f6f3f989d6460408bda42c33ecc5c11b04af0c85f0f857b6b235a2bd', 'hex');
	    var bufferKey = Buffer.from('0153f7000099ed9f320451aa8a7d9707', 'hex');
	    var decM2 = she.decrypt_M2(bufferM2, bufferKey).subarray(16,48);
	    expect(decM2.toString('hex')).toBe('0000001100000000000000000000004110357f020289ad8f512662ba988f1111');
	    var cid = decM2.subarray(0, 4).toString('hex').substring(0, 7);
	    expect(cid).toBe('0000001');
	    var fid = ((decM2[3] & 0x0F) << 1) + ((decM2[4] >> 7) & 0x01);
	    expect(fid).toBe(2);
	    var key = decM2.subarray(16).toString('hex');
	    expect(key.toString('hex')).toBe('10357f020289ad8f512662ba988f1111');
        }
    );
    test('SHE_decrypt: getCID', () =>
        {
	    var she = new SHE();
	    var bufferM2 = Buffer.from('000000000000000000000000000000413e38f7c374d4a3f39547b556893861d251195ce2f6f3f989d6460408bda42c33ecc5c11b04af0c85f0f857b6b235a2bd', 'hex');
	    var bufferKey = Buffer.from('0153f7000099ed9f320451aa8a7d9707', 'hex');
	    var CID = she.getCID(bufferM2, bufferKey);
	    expect(CID).toBe('0000001');
        }
    );
    test('SHE_decrypt: getFID', () =>
        {
	    var she = new SHE();
	    var bufferM2 = Buffer.from('000000000000000000000000000000413e38f7c374d4a3f39547b556893861d251195ce2f6f3f989d6460408bda42c33ecc5c11b04af0c85f0f857b6b235a2bd', 'hex');
	    var bufferKey = Buffer.from('0153f7000099ed9f320451aa8a7d9707', 'hex');
	    var FID = she.getFID(bufferM2, bufferKey);
	    expect(FID).toBe(2);
        }
    );
    test('SHE_decrypt: getKEY', () =>
        {
	    var she = new SHE();
	    var bufferM2 = Buffer.from('000000000000000000000000000000413e38f7c374d4a3f39547b556893861d251195ce2f6f3f989d6460408bda42c33ecc5c11b04af0c85f0f857b6b235a2bd', 'hex');
	    var bufferKey = Buffer.from('0153f7000099ed9f320451aa8a7d9707', 'hex');
	    var KEY = she.getKEY(bufferM2, bufferKey).toString('hex');
	    expect(KEY).toBe('10357f020289ad8f512662ba988f1111');
        }
    );
})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
