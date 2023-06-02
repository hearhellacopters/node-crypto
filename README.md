# encryption-for-node

14 vanilla JavaScript, 0 dependencies portable encryption libraries.
Great for **Node** servers or **Browsers**.

## Encryptions

- AES
- Aria
- Blowfish
- Camellia
- Cast128
- ChaCha20
- Triple DES
- IDEA
- MARS
- MISTY1
- SEED
- Serpent
- SM4
- Twofish

## Installation

```npm install encryption-for-node```

## Features

- Barebones, small size, no bulk encryption methods
- Runs ECB or CBC modes
- Accepts Buffers or UInt8 Arrays
- Easily modifiable to fit any needs
- Import all 10 or just the one you need

## Require or Import

```sh
- For Node:
const Blowfish = require('encryption-for-node/lib/BLOWFISH');
const {CAST128} = require('encryption-for-node');
const NodeCrypto = require('encryption-for-node');
const MISTY1 = NodeCrypto.MISTY1;
- For Browser:
import Blowfish from 'encryption-for-node/lib/BLOWFISH';
import {CAST128} from 'encryption-for-node';
import NodeCrypto from 'encryption-for-node';
const MISTY1 = NodeCrypto.MISTY1;
```

## Use

All encryptions follow the same format. Use ```cipher.set_key``` then ```cipher.set_iv``` for **CBC** mode. If ```cipher.set_iv``` is not set, runs in **ECB** mode.

```sh
 - encrypt:
const cipher = new Blowfish;
cipher.set_key(UInt8ArrayOrBufferKey);
cipher.set_iv(UInt8ArrayOrBufferIV);
const CipherText = cipher.encrypt(UInt8ArrayOrBufferText);
 - decrypt
const cipher = new Blowfish;
cipher.set_key(UInt8ArrayOrBufferKey);
cipher.set_iv(UInt8ArrayOrBufferIV);
const DecryptedUInt8ArrayOrBuffer = cipher.decrypt(ciphertext);
```

**Note:** Most encryptions once setup with a key can be run multiple times, but need their IV reset for CBC mode before each use.

## Tech

|Encryption |Key Length                |IV Length  |
| :---      |    :----:                |  :---     |
|AES        |16, 24 or 32 byte key     |16 byte IV |
|Aria       |16, 24 or 32 byte key     |same as key|
|Blowfish   |Up to 56 byte key         |8 byte IV  |
|Camellia   |16, 24 or 32 byte key     |16 byte IV |
|CAST128    |16 byte key               |8 byte IV  |
|*ChaCha20  |32 byte key, 12 byte nonce|16 byte IV |
|DES3       |8 byte key                |8 byte IV  |
|IDEA       |16 byte key               |8 byte IV  |
|MARS       |16, 24 or 32 byte key     |16 byte IV |
|MISTY1     |16 byte key               |8 byte IV  |
|SEED       |16 byte key               |16 byte IV |
|Serpent    |16, 24 or 32 byte key     |16 byte IV |
|SM4        |16 byte key               |16 byte IV |
|TWOFISH    |16 byte key               |16 byte IV |
*key must be reset after each use

## License

MIT

## Disclaimer

This library spawned from a project where issues with different Node versions meant not having the same access to some of these encryptions. I created these vanilla JavaScript versions of these encryptions so we could implement them in different environments and have them all match. I do not know how they hold up speed or performance wise against something more direct like a C++ source code, as the goal here was flexible. Some encryptions were limited in key length as it would have required extra coding outside of the function of the project. All libraries are presented *as is*, I take no responsibility for outside use.

**If you plan to implement these encryption libraries for anything other than personal or educational use, please be sure you have the appropriate permissions from the original owner of the cipher.**
