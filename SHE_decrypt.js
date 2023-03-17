#!/usr/bin/env node
/** @fileOverview Javascript cryptography implementation 
 * for MiyaguchiPreneel Compression function.
 *
 *
 */

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */
    
    var aesjs = require('aes-js');
    var MP = require('miyaguchipreneel');
    
    SHE_decrypt.prototype.KDF = (k) =>
    {
        var kb, key;
        if (k instanceof Buffer)
	    kb = Buffer.from(k);
        else
	    kb = Buffer.from(k, 'hex');
        key = Buffer.concat([kb, SHE_decrypt.prototype.KeyUpdateEncCte]);
        var dk = SHE_decrypt.prototype.mp.comp(SHE_decrypt.prototype.bufferIV, key);
        return(dk);
    }

    SHE_decrypt.prototype.decrypt_M2 = (msg, key) =>
    {
        var dk = SHE_decrypt.prototype.KDF(key);
        var aesCbc = new aesjs.ModeOfOperation.cbc(aesjs.utils.hex.toBytes(dk.toString('hex')), aesjs.utils.hex.toBytes(SHE_decrypt.prototype.bufferIV.toString('hex')));
        var m2Str = aesCbc.decrypt(aesjs.utils.hex.toBytes(msg.toString('hex')));
        var bufM2 = Buffer.from(m2Str);
        return(bufM2);
    }

    function SHE_decrypt()
    {
        const KeyUpdateEncCte = Buffer.from('010153484500800000000000000000b0', 'hex');
        const bufferIV = Buffer.from('00000000000000000000000000000000', 'hex');
        const mp = new MP();
        
        this.KeyUpdateEncCte = KeyUpdateEncCte;
        this.bufferIV = bufferIV;
        this.mp = mp;
        SHE_decrypt.prototype.KeyUpdateEncCte = KeyUpdateEncCte;
        SHE_decrypt.prototype.bufferIV = bufferIV;
        SHE_decrypt.prototype.mp = mp;
        SHE_decrypt.prototype.KDF = this.KDF;
        SHE_decrypt.prototype.decrypt_M2 = this.decrypt_M2;

        SHE_decrypt.prototype.getCID = (msg, key) =>
        {
            var dk = SHE_decrypt.prototype.KDF(key);
            var aesCbc = new aesjs.ModeOfOperation.cbc(aesjs.utils.hex.toBytes(dk.toString('hex')), aesjs.utils.hex.toBytes(SHE_decrypt.prototype.bufferIV.toString('hex')));
            var m2Str = aesCbc.decrypt(aesjs.utils.hex.toBytes(msg.toString('hex')));
            var bufM2 = Buffer.from(m2Str);
            var CID = bufM2.subarray(16,20).toString('hex').substring(0, 7);
            return(CID);           
        }
        SHE_decrypt.prototype.getFID = (msg, key) =>
        {
            var dk = SHE_decrypt.prototype.KDF(key);
            var aesCbc = new aesjs.ModeOfOperation.cbc(aesjs.utils.hex.toBytes(dk.toString('hex')), aesjs.utils.hex.toBytes(SHE_decrypt.prototype.bufferIV.toString('hex')));
            var m2Str = aesCbc.decrypt(aesjs.utils.hex.toBytes(msg.toString('hex')));
            var bufM2 = Buffer.from(m2Str);
            var FID = ((bufM2[19] & 0x0F) << 1) + ((bufM2[20] >> 7) & 0x01);
            return(FID);
        }
        SHE_decrypt.prototype.getKEY = (msg, key) =>
        {
            var dk = SHE_decrypt.prototype.KDF(key);
            var aesCbc = new aesjs.ModeOfOperation.cbc(aesjs.utils.hex.toBytes(dk.toString('hex')), aesjs.utils.hex.toBytes(SHE_decrypt.prototype.bufferIV.toString('hex')));
            var m2Str = aesCbc.decrypt(aesjs.utils.hex.toBytes(msg.toString('hex')));
            var bufM2 = Buffer.from(m2Str);
            var KEY = bufM2.subarray(32,48);
            return(KEY);
        }
        return(this);
    }
    
    // NodeJS
    if (typeof exports !== 'undefined')
    {
	exports.SHE_decrypt = SHE_decrypt;
	exports.KDF = SHE_decrypt.prototype.KDF;
	exports.decrypt_M2 = SHE_decrypt.prototype.decrypt_M2;
	module.exports = SHE_decrypt;
    }
    // RequireJS/AMD
    // http://www.requirejs.org/docs/api.html
    // https://github.com/amdjs/amdjs-api/wiki/AMD
    else if (typeof(define) === 'function' && define.amd)
    {
	define([], function() { return SHE_decrypt; });
    }
    // Web Browsers
    else
    {
	
	root.SHE_decrypt = SHE_decrypt;
    }
})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
