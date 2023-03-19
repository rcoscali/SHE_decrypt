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

    /*
     * dk = KDF(k)
     *
     * Key Derivation Function used in the SHE protocol specification
     * 
     */
    SHE_decrypt.prototype.KDF = (k) =>
    {
        return(
            SHE_decrypt.prototype.mp.comp(
                SHE_decrypt.prototype.bufferIV,
                Buffer.concat(
                    [
                        (k instanceof Buffer ?
                         Buffer.from(k) :
                         Buffer.from(k, 'hex')
                        ),
                        SHE_decrypt.prototype.KeyUpdateEncCte
                    ]
                )
            )
        );
    }

    /*
     * bufM2 = decrypt_M2(msg, key)
     *
     * This method will decipher the SHE command M2 argument register 
     * provided for a Key Provisionning.
     * This register will also allows, when deciphered, to get CID, FID 
     * and Key. 
     * (see SHE protocol specification on AUTOSAR web site for details)
     *
     * Arguments:
     *   msg: The message ciphered transfered in a CAN/Eth frame
     *   key: The kMasterEcu key used for ciphering the frame
     *
     * Returns:
     *   The deciphered M2 register value for SHE (Secure Hardware Extension)
     */
    SHE_decrypt.prototype.decrypt_M2 = (msg, key) =>
    {
        var aesCbc =
            new aesjs.ModeOfOperation.cbc(
                aesjs.utils.hex.toBytes(SHE_decrypt.prototype.KDF(key).toString('hex')),
                aesjs.utils.hex.toBytes(SHE_decrypt.prototype.bufferIV.toString('hex'))
            );
        var m2Str = aesCbc.decrypt(
            aesjs.utils.hex.toBytes(msg.toString('hex'))
        );
        return(Buffer.from(m2Str));
    }

    /*
     * SHE_decrypt constructor
     *
     */
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

        /*
         * cid = getCID(m2)
         *
         * Extract CID from the SHE command M2 argument register
         *
         * Arguments:
         *   m2: The M2 argument register of the SHE command
         *
         * Returns:
         *   CID extracted from the M2 SHE command register
         */
        SHE_decrypt.prototype.getCID = (m2) =>
        {
            return(m2.subarray(16,48).subarray(0, 4).toString('hex').substring(0, 7));           
        }

        /*
         * fid = getFID(m2)
         *
         * Extract FID from the SHE command M2 argument register
         *
         * Arguments:
         *   m2: The M2 argument register of the SHE command
         *
         * Returns:
         *   FID extracted from the M2 SHE command register
         */
        SHE_decrypt.prototype.getFID = (m2) =>
        {
            var decM2 = m2.subarray(16,48);
            return(((decM2[3] & 0x0F) << 1) + ((decM2[4] >> 7) & 0x01));
        }

        /*
         * key = getKEY(m2)
         *
         * Extract KEY provisionned from the SHE command M2 argument register
         *
         * Arguments:
         *   m2: The M2 argument register of the SHE command
         *
         * Returns:
         *   KEY extracted from the M2 SHE command register
         */
        SHE_decrypt.prototype.getKEY = (m2) =>
        {
            var decM2 = m2.subarray(16,48);
            return(decM2.subarray(16,48).swap16());
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
