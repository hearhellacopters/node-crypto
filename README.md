# node-crypto

10 vanilla JavaScript, 0 dependencies portable encryption libraries.
Great for **Node** servers or **Browsers**.

## Encryptions

- AES
- Blowfish
- Camellia
- Cast128
- IDEA
- MARS
- MISTY1
- SEED
- Serpent
- Twofish

## Installation

```npm install node-crypto```

## Features

- Barebones, small size, no bulk encryption methods
- Runs ECB or CBC modes
- Accepts Buffers or UInt8 Arrays
- Easily modifiable to fit any needs
- Import all 10 or just the one you need

## Require or Import

```sh
- For Node:
const Blowfish = require('node-crypto/lib/BLOWFISH');
const {CAST128} = require('node-crypto');
const NodeCrypto = require('node-crypto');
const MISTY1 = NodeCrypto.MISTY1;
- For Browser:
import Blowfish from 'node-crypto/lib/BLOWFISH';
import {CAST128} from 'node-crypto';
import NodeCrypto from 'node-crypto';
const MISTY1 = NodeCrypto.MISTY1;
```

## Use

All encryptions follow the same format. Use ```cipher.set_key``` then ```cipher.set_iv``` for **CBC** mode. If ```cipher.set_iv``` is not set, runs in **ECB** mode.

```sh
const cipher = new Blowfish;
cipher.set_key(UInt8ArrayOrBufferKey);
cipher.set_iv(UInt8ArrayOrBufferIV);
const CipherText = cipher.encrypt(UInt8ArrayOrBufferText);
--
cipher.set_iv(UInt8ArrayOrBufferIV);
const DecryptedUInt8ArrayOrBuffer = cipher.decrypt(ciphertext);
```

**Note:** Once an encryption is setup with a key, you can run it as many times as you want, but it does need the IV reset for CBC mode before each use.

## Tech

|Encryption |Key Length            |IV Length |
| :---      |    :----:            |  :---    |
|AES        |16, 24 or 32 byte key |16 byte IV|
|Blowfish   |Up to 56 byte key     |8 byte IV |
|Camellia   |16, 24 or 32 byte key |16 byte IV|
|CAST128    |16 byte key           |8 byte IV |
|IDEA       |16 byte key           |8 byte IV |
|MARS       |16, 24 or 32 byte key |16 byte IV|
|MISTY1     |16 byte key           |8 byte IV |
|SEED       |16 byte key           |16 byte IV|
|Serpent    |16, 24 or 32 byte key |16 byte IV|
|TWOFISH    |16 byte key           |16 byte IV|

## License

MIT

## Disclaimer

This library spawned from a project where issues with different Node versions meant not having the same access to some of these encryptions. I created these vanilla JavaScript versions of these encryptions so we could implement them in different environments and have them all match. I do not know how they hold up speed or performance wise against something more direct like a C++ source code, as the goal here was flexable. Some encryptions were limited in key length as it would have required extra coding outside of the function of the project. All libraries are presented *as is*, I take no responsibility for outside use. **If you plan to implement these encryption libraries for anything other than personal or educational use, please be sure you have the appropriate permissions from the original owner of the cipher.**
