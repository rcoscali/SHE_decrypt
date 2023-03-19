# SHE_decrypt
Pure JavaScript implem for SHE commands args deciphering of MAC key provisionning CAN/Ethernet frames.
This implementation relies on the MiyaguchiPreneel compression function implemented in the (also pure)
JavaScript implementation of the miyaguchipreneel npm module.

## Install

```
npm install she_decrypt
```

## Usage

SHE_decrypt exposes an API using node:Buffer. It allows really straigth forward CAN/Eth frame
manipulation.

```
   const she = require('she_decrypt');

   var frameBuf = Buffer.from(<get your can frames, a way or another>, 'hex');
   var frameKey = Buffer.from(<get your key the same way or another>, 'hex);
   
   var she_decrypt = new she();
   
   var decM2 = she_decrypt.decrypt_M2(frameBuf, frameKey);
   
   var cid = she_decrypt.getCID(decM2);
   var fid = she_decrypt.getFID(decM2);
   var key = she_decrypt.getKEY(decM2);
```
