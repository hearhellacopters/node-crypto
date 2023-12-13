# encryption-for-node

14 vanilla TypeScript, 0 dependencies portable encryption libraries.
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

- Barebones, small size, no bulk encryption methods.
- Runs ECB or CBC modes.
- Static or PKCS padding.
- Accepts ``Buffer`` or ``Uint8Array``. Returns the same type.
- Easily modifiable to fit any needs.

## Require or Import

```javascript
//For Node:
const {CAST128} = require('encryption-for-node');
//For Browser:
import {CAST128} from 'encryption-for-node';
```

## Use

All encryptions classes follow the same format. Use ```cipher.set_key``` then ```cipher.set_iv``` for **CBC** mode. If ```cipher.set_iv``` is not set, runs in **ECB** mode. If static padding number is not set, uses PKCS padding on last block if needed.

```javascript
//encrypt:
const cipher = new Blowfish();
cipher.set_key(Uint8ArrayOrBufferKey);
cipher.set_iv(Uint8ArrayOrBufferIV);
var paddingNumber = 0xFF; //If padding number is not set, uses PKCS padding.
const CipherText = cipher.encrypt(Uint8ArrayOrBufferText, paddingNumber);
//decrypt
const cipher = new Blowfish();
cipher.set_key(Uint8ArrayOrBufferKey);
cipher.set_iv(Uint8ArrayOrBufferIV);
var paddingNumberOrTrue = 0xFF; //Will check the last block and remove if padded is ``number``. Will remove PKCS if ``true``.
const DecryptedUInt8ArrayOrBuffer = cipher.decrypt(ciphertext, paddingNumberOrTrue);
```

**Note:** Most encryptions can be run multiple times once setup with a key. IV will need to be reset for CBC mode before each use.

## Tech

|Encryption |Key Length                |IV Length  |
| :---      |    :----:                |  :---     |
|AES        |16, 24 or 32 byte key     |16 byte IV |
|ARIA       |16, 24 or 32 byte key     |same as key|
|BLOWFISH   |Up to 56 byte key         |8 byte IV  |
|CAMELLIA   |16, 24 or 32 byte key     |16 byte IV |
|CAST128    |16 byte key               |8 byte IV  |
|*CHACHA20  |32 byte key, 12 byte nonce|16 byte IV |
|DES3       |8 byte key                |8 byte IV  |
|IDEA       |16 byte key               |8 byte IV  |
|MARS       |16, 24 or 32 byte key     |16 byte IV |
|MISTY1     |16 byte key               |8 byte IV  |
|SEED       |16 byte key               |16 byte IV |
|SERPENT    |16, 24 or 32 byte key     |16 byte IV |
|SM4        |16 byte key               |16 byte IV |
|TWOFISH    |16 byte key               |16 byte IV |

*key must be reset after each use

## License

MIT

## Disclaimer

This library spawned from a project where issues with different Node versions meant not having the same access to some of these encryptions. I created these vanilla JavaScript versions of these encryptions so we could implement them in different environments and have them all match. I do not know how they hold up speed or performance wise against something more direct like a C++ source code, as the goal here was flexible. Some encryptions were limited in key length as it would have required extra coding outside of the function of the project. All libraries are presented *as is*, I take no responsibility for outside use.

**If you plan to implement these encryption libraries for anything other than personal or educational use, please be sure you have the appropriate permissions from the original owner of the cipher.**
