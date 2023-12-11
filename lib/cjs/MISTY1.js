"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MISTY1 = void 0;
const common_js_1 = require("./common.js");
const ShortSwitch = (a1) => {
    const value1 = (a1 >> 8) & 0xff;
    const value2 = a1 & 0xff;
    const return_buffer = (0, common_js_1.readUInt16LE)(new Uint8Array([value1, value2]), 0);
    return return_buffer;
};
/**
 * Misty1 encryption.
 *
 * Key must be 16 bytes, 8 byte IV
 *
 * Example:
 * ```
 * const cipher = new MISTY1();
 * // Key for browser
 * const encoder_key = new TextEncoder();
 * const key = encoder_key.encode("0123456789ABCDEF");
 * cipher.set_key(key)
 * // Key for node
 * const key = Buffer.from("0123456789ABCDEF");
 * cipher.set_key(key)
 * // set IV for browser
 * const encoder_IV = new TextEncoder();
 * const IV = encoder_IV.encode("01234567");
 * cipher.set_iv(IV)
 * // set IV for node
 * const IV = Buffer.from("01234567");
 * cipher.set_iv(IV)
 * // Encrypt for browser
 * const encoder_text = new TextEncoder();
 * const text = encoder_text.encode("test text");
 * const text_length = text.length
 * const ciphertext = cipher.encrypt(text)
 * // Encrypt for node
 * const text = Buffer.from("test text");
 * const text_length = text.length
 * const ciphertext = cipher.encrypt(text)
 * // Decrypt for browser
 * cipher.set_key(key)
 * cipher.set_iv(IV)
 * const ciphertext = new Uint8Array(data.length)
 * ciphertext.set(data)
 * const decrypt_text = cipher.decrypt(ciphertext)
 * const decoded_text = new TextDecoder();
 * const string_data = decoded_text.decode(decrypt_text.subarray(0,text_length));
 * // Decrypt for Node
 * cipher.set_key(key)
 * cipher.set_iv(IV)
 * const ciphertext = Buffer.from(data);
 * const decrypt_text = cipher.decrypt(ciphertext)
 * const final_text = ciphertext.subarray(0,message_len)
 * const string_data = final_text.toString()
 * ```
 */
class MISTY1 {
    constructor() {
        this.key_set = false;
        this.iv_set = false;
        this.Misty1_setup = [
            0x1b, 0x32, 0x33, 0x5a, 0x3b, 0x10, 0x17, 0x54,
            0x5b, 0x1a, 0x72, 0x73, 0x6b, 0x2c, 0x66, 0x49,
            0x1f, 0x24, 0x13, 0x6c, 0x37, 0x2e, 0x3f, 0x4a,
            0x5d, 0x0f, 0x40, 0x56, 0x25, 0x51, 0x1c, 0x04,
            0x0b, 0x46, 0x20, 0x0d, 0x7b, 0x35, 0x44, 0x42,
            0x2b, 0x1e, 0x41, 0x14, 0x4b, 0x79, 0x15, 0x6f,
            0x0e, 0x55, 0x09, 0x36, 0x74, 0x0c, 0x67, 0x53,
            0x28, 0x0a, 0x7e, 0x38, 0x02, 0x07, 0x60, 0x29,
            0x19, 0x12, 0x65, 0x2f, 0x30, 0x39, 0x08, 0x68,
            0x5f, 0x78, 0x2a, 0x4c, 0x64, 0x45, 0x75, 0x3d,
            0x59, 0x48, 0x03, 0x57, 0x7c, 0x4f, 0x62, 0x3c,
            0x1d, 0x21, 0x5e, 0x27, 0x6a, 0x70, 0x4d, 0x3a,
            0x01, 0x6d, 0x6e, 0x63, 0x18, 0x77, 0x23, 0x05,
            0x26, 0x76, 0x00, 0x31, 0x2d, 0x7a, 0x7f, 0x61,
            0x50, 0x22, 0x11, 0x06, 0x47, 0x16, 0x52, 0x4e,
            0x71, 0x3e, 0x69, 0x43, 0x34, 0x5c, 0x58, 0x7d
        ];
        this.Misty1Const = [
            0x1c3, 0x0cb, 0x153, 0x19f, 0x1e3, 0x0e9, 0x0fb, 0x035,
            0x181, 0x0b9, 0x117, 0x1eb, 0x133, 0x009, 0x02d, 0x0d3,
            0x0c7, 0x14a, 0x037, 0x07e, 0x0eb, 0x164, 0x193, 0x1d8,
            0x0a3, 0x11e, 0x055, 0x02c, 0x01d, 0x1a2, 0x163, 0x118,
            0x14b, 0x152, 0x1d2, 0x00f, 0x02b, 0x030, 0x13a, 0x0e5,
            0x111, 0x138, 0x18e, 0x063, 0x0e3, 0x0c8, 0x1f4, 0x01b,
            0x001, 0x09d, 0x0f8, 0x1a0, 0x16d, 0x1f3, 0x01c, 0x146,
            0x07d, 0x0d1, 0x082, 0x1ea, 0x183, 0x12d, 0x0f4, 0x19e,
            0x1d3, 0x0dd, 0x1e2, 0x128, 0x1e0, 0x0ec, 0x059, 0x091,
            0x011, 0x12f, 0x026, 0x0dc, 0x0b0, 0x18c, 0x10f, 0x1f7,
            0x0e7, 0x16c, 0x0b6, 0x0f9, 0x0d8, 0x151, 0x101, 0x14c,
            0x103, 0x0b8, 0x154, 0x12b, 0x1ae, 0x017, 0x071, 0x00c,
            0x047, 0x058, 0x07f, 0x1a4, 0x134, 0x129, 0x084, 0x15d,
            0x19d, 0x1b2, 0x1a3, 0x048, 0x07c, 0x051, 0x1ca, 0x023,
            0x13d, 0x1a7, 0x165, 0x03b, 0x042, 0x0da, 0x192, 0x0ce,
            0x0c1, 0x06b, 0x09f, 0x1f1, 0x12c, 0x184, 0x0fa, 0x196,
            0x1e1, 0x169, 0x17d, 0x031, 0x180, 0x10a, 0x094, 0x1da,
            0x186, 0x13e, 0x11c, 0x060, 0x175, 0x1cf, 0x067, 0x119,
            0x065, 0x068, 0x099, 0x150, 0x008, 0x007, 0x17c, 0x0b7,
            0x024, 0x019, 0x0de, 0x127, 0x0db, 0x0e4, 0x1a9, 0x052,
            0x109, 0x090, 0x19c, 0x1c1, 0x028, 0x1b3, 0x135, 0x16a,
            0x176, 0x0df, 0x1e5, 0x188, 0x0c5, 0x16e, 0x1de, 0x1b1,
            0x0c3, 0x1df, 0x036, 0x0ee, 0x1ee, 0x0f0, 0x093, 0x049,
            0x09a, 0x1b6, 0x069, 0x081, 0x125, 0x00b, 0x05e, 0x0b4,
            0x149, 0x1c7, 0x174, 0x03e, 0x13b, 0x1b7, 0x08e, 0x1c6,
            0x0ae, 0x010, 0x095, 0x1ef, 0x04e, 0x0f2, 0x1fd, 0x085,
            0x0fd, 0x0f6, 0x0a0, 0x16f, 0x083, 0x08a, 0x156, 0x09b,
            0x13c, 0x107, 0x167, 0x098, 0x1d0, 0x1e9, 0x003, 0x1fe,
            0x0bd, 0x122, 0x089, 0x0d2, 0x18f, 0x012, 0x033, 0x06a,
            0x142, 0x0ed, 0x170, 0x11b, 0x0e2, 0x14f, 0x158, 0x131,
            0x147, 0x05d, 0x113, 0x1cd, 0x079, 0x161, 0x1a5, 0x179,
            0x09e, 0x1b4, 0x0cc, 0x022, 0x132, 0x01a, 0x0e8, 0x004,
            0x187, 0x1ed, 0x197, 0x039, 0x1bf, 0x1d7, 0x027, 0x18b,
            0x0c6, 0x09c, 0x0d0, 0x14e, 0x06c, 0x034, 0x1f2, 0x06e,
            0x0ca, 0x025, 0x0ba, 0x191, 0x0fe, 0x013, 0x106, 0x02f,
            0x1ad, 0x172, 0x1db, 0x0c0, 0x10b, 0x1d6, 0x0f5, 0x1ec,
            0x10d, 0x076, 0x114, 0x1ab, 0x075, 0x10c, 0x1e4, 0x159,
            0x054, 0x11f, 0x04b, 0x0c4, 0x1be, 0x0f7, 0x029, 0x0a4,
            0x00e, 0x1f0, 0x077, 0x04d, 0x17a, 0x086, 0x08b, 0x0b3,
            0x171, 0x0bf, 0x10e, 0x104, 0x097, 0x15b, 0x160, 0x168,
            0x0d7, 0x0bb, 0x066, 0x1ce, 0x0fc, 0x092, 0x1c5, 0x06f,
            0x016, 0x04a, 0x0a1, 0x139, 0x0af, 0x0f1, 0x190, 0x00a,
            0x1aa, 0x143, 0x17b, 0x056, 0x18d, 0x166, 0x0d4, 0x1fb,
            0x14d, 0x194, 0x19a, 0x087, 0x1f8, 0x123, 0x0a7, 0x1b8,
            0x141, 0x03c, 0x1f9, 0x140, 0x02a, 0x155, 0x11a, 0x1a1,
            0x198, 0x0d5, 0x126, 0x1af, 0x061, 0x12e, 0x157, 0x1dc,
            0x072, 0x18a, 0x0aa, 0x096, 0x115, 0x0ef, 0x045, 0x07b,
            0x08d, 0x145, 0x053, 0x05f, 0x178, 0x0b2, 0x02e, 0x020,
            0x1d5, 0x03f, 0x1c9, 0x1e7, 0x1ac, 0x044, 0x038, 0x014,
            0x0b1, 0x16b, 0x0ab, 0x0b5, 0x05a, 0x182, 0x1c8, 0x1d4,
            0x018, 0x177, 0x064, 0x0cf, 0x06d, 0x100, 0x199, 0x130,
            0x15a, 0x005, 0x120, 0x1bb, 0x1bd, 0x0e0, 0x04f, 0x0d6,
            0x13f, 0x1c4, 0x12a, 0x015, 0x006, 0x0ff, 0x19b, 0x0a6,
            0x043, 0x088, 0x050, 0x15f, 0x1e8, 0x121, 0x073, 0x17e,
            0x0bc, 0x0c2, 0x0c9, 0x173, 0x189, 0x1f5, 0x074, 0x1cc,
            0x1e6, 0x1a8, 0x195, 0x01f, 0x041, 0x00d, 0x1ba, 0x032,
            0x03d, 0x1d1, 0x080, 0x0a8, 0x057, 0x1b9, 0x162, 0x148,
            0x0d9, 0x105, 0x062, 0x07a, 0x021, 0x1ff, 0x112, 0x108,
            0x1c0, 0x0a9, 0x11d, 0x1b0, 0x1a6, 0x0cd, 0x0f3, 0x05c,
            0x102, 0x05b, 0x1d9, 0x144, 0x1f6, 0x0ad, 0x0a5, 0x03a,
            0x1cb, 0x136, 0x17f, 0x046, 0x0e1, 0x01e, 0x1dd, 0x0e6,
            0x137, 0x1fa, 0x185, 0x08c, 0x08f, 0x040, 0x1b5, 0x0be,
            0x078, 0x000, 0x0ac, 0x110, 0x15e, 0x124, 0x002, 0x1bc,
            0x0a2, 0x0ea, 0x070, 0x1fc, 0x116, 0x15c, 0x04c, 0x1c2
        ];
    }
    /**
     * Key for encryption.
     *
     * Key must be 16 bytes!
     *
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     */
    set_key(key) {
        if (!(0, common_js_1.isBufferOrUint8Array)(key)) {
            throw Error("key must be Buffer or Uint8Array");
        }
        var keyLen = key.length;
        if (keyLen != 16) {
            throw Error("key must be 16 bytes");
        }
        this.buffer = new Uint8Array(128);
        let i = 0;
        // shortswitch
        let value = 0;
        for (i = 0; i < 8; i++) {
            const element1 = key[i * 2];
            const element2 = key[(i * 2) + 1];
            value = (element1 * 256) + element2;
            (0, common_js_1.writeUInt16LE)(this.buffer, value, i * 2);
        }
        let result = value;
        let v5 = (0, common_js_1.readUInt16LE)(this.buffer, 0);
        let v6 = (0, common_js_1.readUInt16LE)(this.buffer, 2);
        let v7 = this.Misty1Const[v6 & 511 ^ (this.Misty1Const[v5 >> 7] ^ v5 & 127)];
        let v8 = this.Misty1Const[v6 >> 7];
        let v9 = (this.Misty1Const[v5 >> 7] ^ v5 & 127) & 127 ^ this.Misty1_setup[v5 & 127] ^ (v6 >> 9);
        let v10 = v6 & 127;
        let v11 = this.Misty1_setup[v6 & 127];
        let v12 = v9 ^ v7;
        (0, common_js_1.writeUInt16LE)(this.buffer, v9 & 0xFFFF, 48);
        v9 = (v12 ^ (v9 << 9)) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v12 & 0xFFFF, 32);
        let v13 = v8 ^ v10;
        let v14 = v13 & 127 ^ v11;
        let v15 = (0, common_js_1.readUInt16LE)(this.buffer, 4);
        let v16 = v14 ^ (v15 >> 9);
        v13 = this.Misty1Const[v15 & 511 ^ v13] & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v9 & 0xFFFF, 16);
        v9 = (v16 ^ v13) & 0xFFFF;
        v13 = (v16 ^ v13 ^ (v16 << 9)) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v16 & 0xFFFF, 50);
        let v17 = this.Misty1Const[v15 >> 7];
        (0, common_js_1.writeUInt16LE)(this.buffer, v9 & 0xFFFF, 34);
        let v18 = v17 ^ v15 & 127;
        let v19 = v18 & 127 ^ this.Misty1_setup[v15 & 127];
        let v20 = (0, common_js_1.readUInt16LE)(this.buffer, 6);
        let v21 = v19 ^ (v20 >> 9);
        (0, common_js_1.writeUInt16LE)(this.buffer, result & 0xFFFF, 14);
        (0, common_js_1.writeUInt16LE)(this.buffer, v13 & 0xFFFF, 18);
        v18 = (v21 ^ this.Misty1Const[v20 & 511 ^ v18]) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v21 & 0xFFFF, 52);
        (0, common_js_1.writeUInt16LE)(this.buffer, v18 & 0xFFFF, 36);
        (0, common_js_1.writeUInt16LE)(this.buffer, (v18 ^ (v21 << 9)) & 0xFFFF, (62 * 2) - 104);
        let v22 = this.Misty1Const[v20 >> 7] ^ v20 & 127;
        let v23 = (0, common_js_1.readUInt16LE)(this.buffer, (56 * 2) - 104);
        let v24 = v22 & 127 ^ this.Misty1_setup[v20 & 127] ^ (v23 >> 9);
        v22 = (v24 ^ this.Misty1Const[v23 & 511 ^ v22]) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v24 & 0xFFFF, (79 * 2) - 104);
        (0, common_js_1.writeUInt16LE)(this.buffer, v22 & 0xFFFF, (71 * 2) - 104);
        v22 = (v22 ^ (v24 << 9)) & 0xFFFF;
        let v25 = this.Misty1Const[v23 >> 7];
        (0, common_js_1.writeUInt16LE)(this.buffer, v22 & 0xFFFF, (63 * 2) - 104);
        let v26 = v25 ^ v23 & 127;
        let v27 = v26 & 127 ^ this.Misty1_setup[v23 & 127];
        let v28 = (0, common_js_1.readUInt16LE)(this.buffer, (57 * 2) - 104);
        let v29 = v27 ^ (v28 >> 9);
        v26 = (v29 ^ this.Misty1Const[v28 & 511 ^ v26]) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v29 & 0xFFFF, (80 * 2) - 104);
        (0, common_js_1.writeUInt16LE)(this.buffer, v26 & 0xFFFF, (72 * 2) - 104);
        (0, common_js_1.writeUInt16LE)(this.buffer, (v26 ^ (v29 << 9)) & 0xFFFF, (64 * 2) - 104);
        let v30 = this.Misty1Const[v28 >> 7] ^ v28 & 127;
        let v31 = (0, common_js_1.readUInt16LE)(this.buffer, (58 * 2) - 104);
        let v32 = v30 & 127 ^ this.Misty1_setup[v28 & 127] ^ (v31 >> 9);
        (0, common_js_1.writeUInt16LE)(this.buffer, v32 & 0xFFFF, (81 * 2) - 104);
        v30 = (v32 ^ this.Misty1Const[v31 & 511 ^ v30]) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v30 & 0xFFFF, (73 * 2) - 104);
        (0, common_js_1.writeUInt16LE)(this.buffer, (v30 ^ (v32 << 9)) & 0xFFFF, (65 * 2) - 104);
        let v33 = this.Misty1Const[v31 >> 7] ^ v31 & 127;
        let v34 = this.Misty1_setup[v31 & 127] ^ (((result) >>> 0) >> 9) ^ v33 & 127;
        (0, common_js_1.writeUInt16LE)(this.buffer, v34 & 0xFFFF, (82 * 2) - 104);
        v33 = (v34 ^ this.Misty1Const[result & 511 ^ (v33 >>> 0)]) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v33 & 0xFFFF, (74 * 2) - 104);
        (0, common_js_1.writeUInt16LE)(this.buffer, (v33 ^ ((v34 & 0xFFFF) << 9)) & 0xFFFF, 28);
        v33 = (this.Misty1Const[((result) >>> 0) >> 7] ^ result & 127) & 0xFFFF;
        let v35 = this.Misty1_setup[result & 127] ^ (v5 >> 9) ^ v33 & 127;
        (0, common_js_1.writeUInt16LE)(this.buffer, (this.Misty1_setup[result & 127] ^ ((v5 >> 9) & 0xFFFF) ^ v33 & 127) & 0xFFFF, 62);
        v5 = (v35 ^ this.Misty1Const[v5 & 511 ^ (v33 & 0xFFFF)]) & 0xFFFF;
        (0, common_js_1.writeUInt16LE)(this.buffer, v5 & 0xFFFF, 46);
        (0, common_js_1.writeUInt16LE)(this.buffer, (v5 ^ (v35 << 9)) & 0xFFFF, 30);
        this.key_set = true;
    }
    ;
    encrypt_block(block) {
        //check if IV is set, if so runs CBC
        let start_chunk = block;
        if (this.iv_set == true) {
            start_chunk = (0, common_js_1.xor)(block, this.iv);
        }
        let letter = "a";
        let i;
        for (i = 0; i < 4; i++) {
            const element1 = start_chunk[i * 2];
            const element2 = start_chunk[(i * 2) + 1];
            var value = (element1 * 256) + element2;
            this[letter] = value;
            letter = String.fromCharCode(letter.charCodeAt(0) + 1);
        }
        let v8 = (0, common_js_1.readUInt16LE)(this.buffer, (52 * 2) - 104);
        let v9 = v8 & this.a ^ this.b;
        let v139 = (0, common_js_1.readUInt16LE)(this.buffer, (62 * 2) - 104); // correct
        let v10 = v139 & this.c ^ this.d;
        let v11 = ((0, common_js_1.readUInt16LE)(this.buffer, (66 * 2) - 104) | v9) ^ this.a;
        let v12 = (0, common_js_1.readUInt16LE)(this.buffer, (56 * 2) - 104);
        let v13 = ((v11 & 0xff) ^ (v8 & 0xff)) & 127 ^ this.Misty1Const[((v11 ^ v8) & 0xFFFF) >> 7];
        let v14 = v13 ^ this.Misty1_setup[((v11 & 0xFF) ^ (v8 & 0xFF)) & 127];
        this.a = (0, common_js_1.readUInt16LE)(this.buffer, (73 * 2) - 104);
        let v15 = (0, common_js_1.readUInt16LE)(this.buffer, (81 * 2) - 104);
        let v16 = this.Misty1Const[(v13 ^ this.a) & 0xFFFF] ^ v9 ^ (v15 ^ v14) & 127 ^ ((v15 ^ v14) << 9);
        let v17 = (0, common_js_1.readUInt16LE)(this.buffer, (54 * 2) - 104);
        let v18 = (v17 ^ v9) & 127;
        let v19 = v18 ^ this.Misty1Const[((v17 ^ v9) & 0xFFFF) >> 7];
        let v20 = v19 ^ this.Misty1_setup[v18];
        let v137 = (0, common_js_1.readUInt16LE)(this.buffer, (69 * 2) - 104);
        let v136 = (0, common_js_1.readUInt16LE)(this.buffer, (77 * 2) - 104);
        let v21 = v16 ^ this.Misty1Const[(v19 ^ v137) & 0xFFFF] ^ (v136 ^ v20) & 127 ^ ((v136 ^ v20) << 9);
        let v22 = (0, common_js_1.readUInt16LE)(this.buffer, (59 * 2) - 104);
        v16 = (v22 ^ v16) & 0xFFFF;
        let v23 = (v16 & 0xFFFF) >> 7;
        let v24 = v16 & 127;
        let v25 = v24 ^ this.Misty1Const[v23];
        let v26 = v25 ^ this.Misty1_setup[v24];
        let v132 = (0, common_js_1.readUInt16LE)(this.buffer, (79 * 2) - 104);
        let v133 = (0, common_js_1.readUInt16LE)(this.buffer, (71 * 2) - 104);
        let v27 = v10 & ~v12 ^ this.c ^ v21;
        let v28 = v21 ^ v10 ^ this.Misty1Const[(v25 ^ v133) & 0xFFFF] ^ (v132 ^ v26) & 127 ^ ((v132 ^ v26) << 9);
        let v29 = (0, common_js_1.readUInt16LE)(this.buffer, (53 * 2) - 104);
        let v30 = (v29 ^ v27) & 127;
        let v31 = this.Misty1_setup[v30];
        let v32 = v30 ^ this.Misty1Const[((v29 ^ v27) & 0xFFFF) >> 7];
        let v33 = (0, common_js_1.readUInt16LE)(this.buffer, (74 * 2) - 104);
        let v34 = (0, common_js_1.readUInt16LE)(this.buffer, (82 * 2) - 104);
        let v35 = this.Misty1Const[(v32 ^ v33) & 0xFFFF] ^ v28 ^ (v34 ^ v32 ^ v31) & 127 ^ ((v34 ^ v32 ^ v31) << 9);
        let v36 = (0, common_js_1.readUInt16LE)(this.buffer, (55 * 2) - 104);
        let v37 = (v36 ^ v28) & 127;
        let v38 = v37 ^ this.Misty1Const[((v36 ^ v28) & 0xFFFF) >> 7];
        let v39 = v38 ^ this.Misty1_setup[v37];
        let v135 = (0, common_js_1.readUInt16LE)(this.buffer, (70 * 2) - 104);
        let v134 = (0, common_js_1.readUInt16LE)(this.buffer, (78 * 2) - 104);
        let v40 = this.Misty1Const[((v38 ^ v135) & 0xFFFF)] ^ v35 ^ (v134 ^ v39) & 127 ^ ((v134 ^ v39) << 9);
        v35 = (v35 ^ v8) & 0xFFFF;
        let v41 = (v35 & 0xFFFF) >> 7;
        let v42 = v35 & 127;
        let v43 = v42 ^ this.Misty1Const[v41];
        let v44 = (0, common_js_1.readUInt16LE)(this.buffer, (72 * 2) - 104);
        let v45 = (0, common_js_1.readUInt16LE)(this.buffer, (80 * 2) - 104);
        let v46 = v45 ^ v43 ^ this.Misty1_setup[v42];
        let v47 = (0, common_js_1.readUInt16LE)(this.buffer, (57 * 2) - 104);
        let v48 = v40 ^ v11 ^ v47;
        let v49 = this.Misty1Const[((v44 ^ v43) & 0xFFFF)] ^ v9 ^ v40 ^ v46 & 127 ^ (v46 << 9) ^ v48 & v29;
        let v50 = ((0, common_js_1.readUInt16LE)(this.buffer, (63 * 2) - 104) & v27 & 0xFFFF) ^ v28;
        let v51 = (v49 | (0, common_js_1.readUInt16LE)(this.buffer, (67 * 2) - 104)) ^ v48;
        let v52 = (v51 ^ v17) & 127;
        let v53 = v52 ^ this.Misty1Const[((v51 ^ v17) & 0xFFFF) >> 7];
        let v54 = v53 ^ this.Misty1_setup[v52];
        this.d = (0, common_js_1.readUInt16LE)(this.buffer, (75 * 2) - 104);
        let v55 = (0, common_js_1.readUInt16LE)(this.buffer, (83 * 2) - 104);
        let v56 = this.Misty1Const[(v53 ^ this.d) & 0xFFFF] ^ v49 ^ (v55 ^ v54) & 127 ^ ((v55 ^ v54) << 9);
        let v57 = (v49 ^ v12) & 127;
        let v58 = this.Misty1Const[((v49 ^ v12) & 0xFFFF) >> 7] ^ v57;
        let v59 = v58 ^ this.Misty1_setup[v57];
        let v60 = (v50 | v47) ^ v27;
        let v61 = (v132 ^ v59) & 127 ^ this.Misty1Const[(v58 ^ v133) & 0xFFFF] ^ ((v132 ^ v59) << 9) ^ v56;
        v56 = (v56 ^ v29 & 0xFFFF);
        let v62 = (v56 & 0xFFFF) >> 7;
        let v63 = v56 & 127;
        let v64 = v63 ^ this.Misty1Const[v62];
        let v65 = v64 ^ this.Misty1_setup[v63];
        let v66 = this.Misty1Const[(v64 ^ this.a) & 0xfFFFF] ^ v50;
        let v67 = (0, common_js_1.readUInt16LE)(this.buffer, (58 * 2) - 104);
        let v68 = v60 ^ v67 ^ v61;
        let v69 = v66 ^ v61 ^ (v15 ^ v65) & 127 ^ ((v15 ^ v65) << 9);
        let v70 = (v68 ^ v36) & 127;
        let v71 = v70 ^ this.Misty1Const[((v68 ^ v36) & 0xFFFF) >> 7];
        let v72 = v71 ^ this.Misty1_setup[v70];
        v12 = (0, common_js_1.readUInt16LE)(this.buffer, (68 * 2) - 104);
        v9 = (v71 ^ v12) & 0xFFFF;
        let v73 = (0, common_js_1.readUInt16LE)(this.buffer, (76 * 2) - 104);
        let v74 = v69 ^ this.Misty1Const[(v9 & 0xFFFF)] ^ (v73 ^ v72) & 127 ^ ((v73 ^ v72) << 9);
        let v75 = (v69 ^ v47) & 127;
        let v76 = v75 ^ this.Misty1Const[((v69 ^ v47) & 0xFFFF) >> 7];
        let v77 = v76 ^ this.Misty1_setup[v75];
        let v78 = v74 ^ this.Misty1Const[(v76 ^ v44) & 0xFFFF] ^ (v45 ^ v77) & 127 ^ ((v45 ^ v77) << 9);
        v74 = (v74 ^ v17) & 0xFFFF;
        let v2 = (v74 & 0xFFFF) >> 7;
        let v79 = v74 & 127;
        v2 = v79 ^ this.Misty1Const[v2];
        let v80 = v51 ^ v22 ^ v78;
        let v81 = v34 ^ v2 ^ this.Misty1_setup[v79];
        let v82 = this.Misty1Const[(v2 & 0xFFFF) ^ v33] ^ v49 ^ v78 ^ v81 & 127 ^ (v81 << 9) ^ v80 & v17;
        let v83 = v69 ^ (((0, common_js_1.readUInt16LE)(this.buffer, (64 * 2) - 104) & v68) & 0xFFFFF);
        let v84 = (v82 | (0, common_js_1.readUInt16LE)(this.buffer, (60 * 2) - 104)) ^ v80;
        let v85 = (0, common_js_1.readUInt16LE)(this.buffer, (56 * 2) - 104);
        let v86 = (v84 ^ v85) & 127;
        v2 = v86 ^ this.Misty1Const[((v84 ^ v85) & 0xFFFF) >> 7];
        let v87 = v2 ^ this.Misty1_setup[v86];
        let v88 = v82 ^ this.Misty1Const[(v2 & 0xFFFF) ^ v137] ^ (v136 ^ v87) & 127 ^ ((v136 ^ v87) << 9);
        v2 = (v82 ^ v67) & 127;
        let v89 = v2 ^ this.Misty1Const[((v82 ^ v67) & 0xFFFF) >> 7];
        v2 = v89 ^ this.Misty1_setup[v2];
        v2 = (v15 ^ v2) & 127 ^ this.Misty1Const[(v89 ^ this.a) & 0xFFFF] ^ ((v15 ^ v2) << 9) ^ v88;
        v88 = (v88 ^ v36) & 0xFFFF;
        let v90 = (v88 & 0xFFFF) >> 7;
        let v91 = v88 & 127;
        let v92 = v91 ^ this.Misty1Const[v90];
        let v93 = v68 ^ v8 ^ (v83 | v67) ^ v2;
        let v94 = this.Misty1Const[(v92 ^ this.d) & 0xFFFF] ^ v83 ^ v2;
        let v95 = v55 ^ v92 ^ this.Misty1_setup[v91];
        let v96 = v94 ^ v95 & 127 ^ (v95 << 9);
        let v97 = (v93 ^ v47) & 127;
        let v98 = v97 ^ this.Misty1Const[((v93 ^ v47) & 0xFFFF) >> 7];
        let v99 = v98 ^ this.Misty1_setup[v97];
        let v100 = v96 ^ this.Misty1Const[(v98 ^ v135) & 0xFFFF] ^ (v134 ^ v99) & 127 ^ ((v134 ^ v99) << 9);
        let v101 = (v96 ^ v22) & 127;
        v2 = v101 ^ this.Misty1Const[((v96 ^ v22) & 0xFFFF) >> 7];
        let v102 = v2 ^ this.Misty1_setup[v101];
        let v103 = v100 ^ this.Misty1Const[(v2 ^ v33) & 0xFFFF] ^ (v34 ^ v102) & 127 ^ ((v34 ^ v102) << 9);
        v100 = (v100 ^ v85) & 0xFFFF;
        v2 = this.Misty1Const[(v100 & 0xFFFF) >> 7];
        let v104 = v100 & 127;
        v2 = (v104 ^ v2) & 0xFFFF;
        let v105 = v84 ^ v29 ^ v103;
        let v106 = v73 ^ v2 ^ this.Misty1_setup[v104];
        let v107 = this.Misty1Const[(v2 ^ v12) & 0xFFFF] ^ v82 ^ v103 ^ v106 & 127 ^ (v106 << 9) ^ v105 & v36; // correct
        let v108 = v96 ^ v93 & (0, common_js_1.readUInt16LE)(this.buffer, (65 * 2) - 104);
        let v109 = (v107 | (0, common_js_1.readUInt16LE)(this.buffer, (61 * 2) - 104)) ^ v105;
        let v110 = (v109 ^ v67) & 127;
        let v111 = v110 ^ this.Misty1Const[((v109 ^ v67) & 0xFFFF) >> 7];
        let v112 = v111 ^ this.Misty1_setup[v110];
        let v113 = v107 ^ this.Misty1Const[(v111 ^ v133) & 0xFFFF] ^ (v132 ^ v112) & 127 ^ ((v132 ^ v112) << 9);
        let v114 = (v107 ^ v8) & 127;
        v2 = (v114 ^ this.Misty1Const[((v107 ^ v8) & 0xFFFF) >> 7]) & 0xFFFF;
        let v115 = v55 ^ v2 ^ this.Misty1_setup[v114];
        let v116 = v115 & 127 ^ this.Misty1Const[(v2 ^ this.d) & 0xFFFF] ^ (v115 << 9) ^ v113;
        v113 = (v113 ^ v47) & 0xFFFF;
        let v117 = v113 >> 7;
        let v118 = v113 & 127;
        let v119 = v118 ^ this.Misty1Const[v117];
        let v120 = v119 ^ this.Misty1_setup[v118];
        let v121 = v93 ^ v17;
        let v122 = v108 | v22;
        let v123 = v108 ^ this.Misty1Const[(v119 ^ v137) & 0xFFFF];
        let v124 = v121 ^ v122 ^ v116;
        let v125 = v123 ^ v116 ^ (v136 ^ v120) & 127 ^ ((v136 ^ v120) << 9);
        let v126 = (v124 ^ v22) & 127;
        v116 = (v126 ^ this.Misty1Const[((v121 ^ v122 ^ v116 ^ v22) & 0xFFFF) >> 7]) & 0xFFFF;
        v126 = (v116 ^ this.Misty1_setup[v126]) & 0xFFFF;
        v126 = (v125 ^ this.Misty1Const[(v116 ^ v44) & 0xFFFF] ^ ((0, common_js_1.readUInt16LE)(this.buffer, (80 * 2) - 104) ^ v126) & 127 ^ (((0, common_js_1.readUInt16LE)(this.buffer, (80 * 2) - 104) ^ (v126 & 0xFFFF)) << 9)) & 0xFFFF;
        let v127 = (v125 ^ v29) & 127;
        let v128 = v127 ^ this.Misty1Const[((v125 ^ v29) & 0xFFFF) >> 7];
        v127 = (v73 ^ v128 ^ this.Misty1_setup[v127]) & 0xFFFF;
        v127 = (v126 ^ this.Misty1Const[(v128 ^ v12) & 0xFFFF] ^ v127 & 127 ^ (v127 << 9)) & 0xFFFF;
        v126 = (v126 ^ v67) & 0xFFFF;
        let v129 = (v126 & 0xFFFF) >> 7;
        let v130 = v126 & 127;
        v129 = (v130 ^ this.Misty1Const[v129]) & 0xFFFF;
        v130 = (v134 ^ v129 ^ this.Misty1_setup[v130]) & 0xFFFF;
        v109 = (v109 ^ v36 ^ v127) & 0xFFFF;
        v2 = (v107 ^ this.Misty1Const[(v129 ^ v135) & 0xFFFF] ^ v127 ^ v130 & 127 ^ (v130 << 9) ^ v109 & v85) & 0xFFFF; // correct
        v92 = (v125 ^ v124 & (0, common_js_1.readUInt16LE)(this.buffer, (66 * 2) - 104)) & 0xFFFF;
        v69 = (((v2 & 0xFFFF) | v139) ^ v109) & 0xFFFF;
        let final = ((v92 | (0, common_js_1.readUInt16LE)(this.buffer, (52 * 2) - 104)) ^ v124) & 0xFFFF;
        //swtch a , b , c , d bytes
        var out_blk;
        if ((0, common_js_1.isBuffer)(block)) {
            out_blk = Buffer.alloc(8);
        }
        else {
            out_blk = new Uint8Array(8);
        }
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(final), 0);
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(v92), 2);
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(v69), 4);
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(v2 & 0xFFFF), 6);
        if (this.iv_set == true) {
            this.iv = out_blk;
        }
        return out_blk;
    }
    ;
    decrypt_block(block) {
        let start_chunk = block;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = start_chunk;
        let letter = "a";
        let i;
        for (i = 0; i < 4; i++) {
            const element1 = start_chunk[i * 2];
            const element2 = start_chunk[(i * 2) + 1];
            var value = (element1 * 256) + element2;
            this[letter] = value;
            letter = String.fromCharCode(letter.charCodeAt(0) + 1);
        }
        let v139 = (0, common_js_1.readUInt16LE)(this.buffer, (52 * 2) - 104);
        let v8 = (v139 | this.b) ^ this.a;
        let v146 = (0, common_js_1.readUInt16LE)(this.buffer, (62 * 2) - 104);
        let v9 = (v146 | this.d) ^ this.c;
        let v145 = (0, common_js_1.readUInt16LE)(this.buffer, (66 * 2) - 104);
        let v10 = v145 & v8 ^ this.b;
        let v11 = (0, common_js_1.readUInt16LE)(this.buffer, (56 * 2) - 104);
        let v12 = (0, common_js_1.readUInt16LE)(this.buffer, (59 * 2) - 104);
        let v13 = (v12 ^ v8) & 127;
        let v14 = this.Misty1_setup[v13];
        let v15 = v13 ^ this.Misty1Const[((v12 ^ v8) & 0xFFFF) >> 7];
        let v144 = (0, common_js_1.readUInt16LE)(this.buffer, (72 * 2) - 104);
        let v143 = (0, common_js_1.readUInt16LE)(this.buffer, (80 * 2) - 104);
        let v16 = this.Misty1Const[(v15 ^ v144) & 0xFFFF] ^ v10 ^ (v143 ^ v15 ^ v14) & 127 ^ ((v143 ^ v15 ^ v14) << 9);
        let v2 = (0, common_js_1.readUInt16LE)(this.buffer, (53 * 2) - 104);
        let v17 = (v2 ^ v10) & 127;
        let v18 = v17 ^ this.Misty1Const[(((v2 & 0XFFFF) ^ v10) & 0XFFFF) >> 7];
        let v19 = v18 ^ this.Misty1_setup[v17];
        this.c = (0, common_js_1.readUInt16LE)(this.buffer, (68 * 2) - 104);
        let v20 = (0, common_js_1.readUInt16LE)(this.buffer, (76 * 2) - 104);
        let v21 = this.Misty1Const[(v18 ^ this.c) & 0xFFFF] ^ v16 ^ (v20 ^ v19) & 127 ^ ((v20 ^ v19) << 9);
        let v22 = (0, common_js_1.readUInt16LE)(this.buffer, (58 * 2) - 104);
        v16 = (v22 ^ v16) & 0xFFFF;
        let v23 = (v16 & 0xFFFF) >> 7;
        let v24 = v16 & 127;
        let v25 = this.Misty1_setup[v24];
        let v26 = v24 ^ this.Misty1Const[v23];
        let v27 = v26 ^ v25;
        let v28 = (0, common_js_1.readUInt16LE)(this.buffer, (78 * 2) - 104);
        let v140 = (0, common_js_1.readUInt16LE)(this.buffer, (70 * 2) - 104);
        let v29 = this.Misty1Const[(v26 ^ v140) & 0xFFFF];
        let v30 = (0, common_js_1.readUInt16LE)(this.buffer, (55 * 2) - 104);
        let v31 = v21 ^ v9 ^ v30;
        let v32 = v11 & v9 ^ this.d ^ v21 ^ v29 ^ (v28 ^ v27) & 127 ^ ((v28 ^ v27) << 9);
        let v33 = (v31 ^ v22) & 127;
        let v34 = v33 ^ this.Misty1Const[((v31 ^ v22) & 0XFFFF) >> 7];
        let v35 = v34 ^ this.Misty1_setup[v33];
        let v142 = (0, common_js_1.readUInt16LE)(this.buffer, (71 * 2) - 104);
        let v141 = (0, common_js_1.readUInt16LE)(this.buffer, (79 * 2) - 104);
        let v36 = this.Misty1Const[(v34 ^ v142) & 0XFFFF] ^ v32 ^ (v141 ^ v35) & 127 ^ ((v141 ^ v35) << 9);
        let v37 = (v32 ^ v139) & 127;
        let v38 = this.Misty1Const[((v32 ^ v139) & 0XFFFF) >> 7] ^ v37;
        let v39 = v38 ^ this.Misty1_setup[v37];
        let v40 = (0, common_js_1.readUInt16LE)(this.buffer, (75 * 2) - 104);
        let v41 = (0, common_js_1.readUInt16LE)(this.buffer, (83 * 2) - 104);
        let v42 = v36 ^ this.Misty1Const[(v40 ^ v38) & 0XFFFF] ^ (v41 ^ v39) & 127 ^ ((v41 ^ v39) << 9);
        let v43 = (0, common_js_1.readUInt16LE)(this.buffer, (57 * 2) - 104);
        v36 = (v36 ^ v43) & 0XFFFF;
        let v44 = (v36 & 0XFFFF) >> 7;
        let v45 = v36 & 127;
        let v46 = this.Misty1_setup[v45];
        let v47 = v45 ^ this.Misty1Const[v44];
        v25 = (0, common_js_1.readUInt16LE)(this.buffer, (69 * 2) - 104);
        let v48 = this.Misty1Const[(v47 ^ v25) & 0xFFFF];
        let v49 = v47 ^ v46;
        let v50 = (0, common_js_1.readUInt16LE)(this.buffer, (77 * 2) - 104);
        let v51 = v42 ^ v10 ^ v48 ^ (v50 ^ v49) & 127 ^ ((v50 ^ v49) << 9);
        let v52 = (0, common_js_1.readUInt16LE)(this.buffer, (54 * 2) - 104);
        let v53 = v42 ^ v8 ^ v52 ^ (v51 | v12);
        let v54 = ((0, common_js_1.readUInt16LE)(this.buffer, (61 * 2) - 104) | v32) ^ v31;
        let v55 = ((v53 & (0, common_js_1.readUInt16LE)(this.buffer, (65 * 2) - 104)) & 0xFFFF) ^ v51;
        let v56 = (v53 ^ v43) & 127;
        let v57 = v56 ^ this.Misty1Const[((v53 ^ v43) & 0xFFFF) >> 7];
        let v58 = v57 ^ this.Misty1_setup[v56];
        let v59 = v55 ^ this.Misty1Const[(v57 ^ v140) & 0xFFFF] ^ (v28 ^ v58) & 127 ^ ((v28 ^ v58) << 9);
        let v60 = (v55 ^ v12) & 127;
        let v61 = v60 ^ this.Misty1Const[((v55 ^ v12) & 0xFFFF) >> 7];
        let v62 = v61 ^ this.Misty1_setup[v60];
        v48 = (0, common_js_1.readUInt16LE)(this.buffer, (74 * 2) - 104);
        let v63 = (0, common_js_1.readUInt16LE)(this.buffer, (82 * 2) - 104);
        let v64 = v59 ^ this.Misty1Const[(v61 ^ v48) & 0xFFFF] ^ (v63 ^ v62) & 127 ^ ((v63 ^ v62) << 9);
        let v65 = ((v59 & 0xFFFF) ^ (v11 & 0xFFFF)) & 127;
        let v66 = v65 ^ this.Misty1Const[((v59 ^ v11) & 0xFFFF) >> 7];
        let v67 = v66 ^ this.Misty1_setup[v65];
        let v68 = v54 & v30 ^ v32 ^ this.Misty1Const[(v66 ^ this.c) & 0xFFFF];
        let v69 = v54 ^ v2 ^ v64;
        let v70 = v68 ^ v64 ^ (v20 ^ v67) & 127 ^ ((v20 ^ v67) << 9);
        let v71 = (v69 ^ v11) & 127;
        let v72 = v71 ^ this.Misty1Const[((v69 ^ v11) & 0xFFFF) >> 7];
        let v73 = v72 ^ this.Misty1_setup[v71];
        let v74 = v70 ^ this.Misty1Const[(v72 ^ v25) & 0xFFFF] ^ (v50 ^ v73) & 127 ^ ((v50 ^ v73) << 9);
        let v75 = (v70 ^ v22) & 127;
        let v76 = v75 ^ this.Misty1Const[((v70 ^ v22) & 0xFFFF) >> 7];
        let v77 = v76 ^ this.Misty1_setup[v75];
        v68 = (0, common_js_1.readUInt16LE)(this.buffer, (73 * 2) - 104);
        v64 = (v76 ^ v68) & 0xFFFF;
        let v78 = (0, common_js_1.readUInt16LE)(this.buffer, (81 * 2) - 104);
        let v79 = v74 ^ this.Misty1Const[(v64 & 0xFFFF)] ^ (v78 ^ v77) & 127 ^ ((v78 ^ v77) << 9);
        v74 = (v74 ^ v30) & 0xFFFF;
        let v80 = (v74 & 0xFFFF) >> 7;
        let v81 = v74 & 127;
        let v82 = v81 ^ this.Misty1Const[v80];
        let v83 = v82 ^ this.Misty1_setup[v81];
        let v84 = this.Misty1Const[(v82 ^ v40) & 0xFFFF] ^ v55 ^ v79 ^ (v41 ^ v83) & 127 ^ ((v41 ^ v83) << 9);
        let v85 = v53 ^ v139 ^ v79 ^ (v84 | v22);
        let v86 = (v70 | (0, common_js_1.readUInt16LE)(this.buffer, (60 * 2) - 104)) ^ v69;
        let v87 = ((v85 & (0, common_js_1.readUInt16LE)(this.buffer, (64 * 2) - 104)) & 0xFFFF) ^ v84;
        let v88 = (v85 ^ v30) & 127;
        let v89 = v88 ^ this.Misty1Const[((v85 ^ v30) & 0xFFFF) >> 7];
        let v90 = v89 ^ this.Misty1_setup[v88];
        let v91 = v87 ^ this.Misty1Const[(v89 ^ this.c) & 0xFFFF] ^ (v20 ^ v90) & 127 ^ ((v20 ^ v90) << 9);
        let v92 = (v87 ^ v43) & 127;
        let v93 = v92 ^ this.Misty1Const[((v87 ^ v43) & 0xFFFF) >> 7];
        let v94 = v93 ^ this.Misty1_setup[v92];
        let v95 = v91 ^ this.Misty1Const[(v93 ^ v144) & 0xFFFF] ^ (v143 ^ v94) & 127 ^ ((v143 ^ v94) << 9);
        v91 = (v91 ^ v52) & 0xFFFF;
        let v96 = (v91 & 0xFFFF) >> 7;
        let v97 = v91 & 127;
        let v98 = v97 ^ this.Misty1Const[v96];
        let v99 = v98 ^ this.Misty1_setup[v97];
        let v100 = v86 & v52 ^ v70 ^ this.Misty1Const[(v98 ^ v48) & 0xFFFF];
        let v101 = v86 ^ v12 ^ v95;
        let v102 = v100 ^ v95 ^ (v63 ^ v99) & 127 ^ ((v63 ^ v99) << 9);
        let v103 = (v101 ^ v52) & 127;
        let v104 = v103 ^ this.Misty1Const[((v101 ^ v52) & 0xFFFF) >> 7];
        let v105 = v104 ^ this.Misty1_setup[v103];
        let v106 = v102 ^ this.Misty1Const[(v104 ^ v40) & 0xFFFF] ^ (v41 ^ v105) & 127 ^ ((v41 ^ v105) << 9);
        let v107 = (v102 ^ v11) & 127;
        let v108 = v107 ^ this.Misty1Const[((v102 ^ v11) & 0xFFFF) >> 7];
        let v109 = v141 ^ v108 ^ this.Misty1_setup[v107];
        let v110 = v106 ^ this.Misty1Const[(v108 ^ v142) & 0xFFFF] ^ v109 & 127 ^ (v109 << 9);
        v106 = (v106 ^ (v2 & 0xFFFF)) & 0xFFFF;
        let v111 = this.Misty1Const[(v106 & 0xFFFF) >> 7];
        let v112 = v106 & 127;
        let v113 = v112 ^ v111;
        let v114 = v78 ^ v113 ^ this.Misty1_setup[v112];
        let v115 = v87 ^ this.Misty1Const[(v113 ^ v68) & 0xFFFF] ^ v110 ^ v114 & 127 ^ (v114 << 9);
        let v116 = v85 ^ v22 ^ v110 ^ (v115 | v43);
        let v117 = (v102 | (0, common_js_1.readUInt16LE)(this.buffer, (67 * 2) - 104)) ^ v101;
        let v118 = ((v116 & (0, common_js_1.readUInt16LE)(this.buffer, (63 * 2) - 104)) & 0xFFFF) ^ v115;
        let v119 = (v116 ^ v2) & 127;
        let v120 = v119 ^ this.Misty1Const[((v116 ^ (v2 & 0xFFFF)) & 0xFFFF) >> 7];
        let v121 = v63 ^ v120 ^ this.Misty1_setup[v119];
        let v122 = v118 ^ this.Misty1Const[(v120 ^ v48) & 0xFFFF] ^ v121 & 127 ^ (v121 << 9);
        let v123 = (v118 ^ v30) & 127;
        let v124 = v123 ^ this.Misty1Const[((v118 ^ v30) & 0xFFFF) >> 7];
        let v125 = v124 ^ this.Misty1_setup[v123];
        let v126 = v122 ^ this.Misty1Const[(v124 ^ v140) & 0xFFFF] ^ (v28 ^ v125) & 127 ^ ((v28 ^ v125) << 9);
        v122 = (v122 ^ v139) & 0xFFFF;
        let v127 = (v122 & 0xFFFF) >> 7;
        let v128 = v122 & 127;
        let v129 = v128 ^ this.Misty1Const[v127];
        let v130 = v129 ^ this.Misty1_setup[v128];
        let v131 = v117 & v2;
        let v132 = v117 ^ v43 ^ v126;
        let v133 = v102 ^ this.Misty1Const[(v129 ^ v144) & 0xFFFF] ^ v131 ^ v126 ^ (v143 ^ v130) & 127 ^ ((v143 ^ v130) << 9);
        let v134 = (v132 ^ v139) & 127;
        v126 = (v134 ^ this.Misty1Const[((v132 ^ v139) & 0xFFFF) >> 7]) & 0xFFFF;
        v134 = (v78 ^ v126 ^ this.Misty1_setup[v134]) & 0xFFFF;
        v68 = (v133 ^ this.Misty1Const[(v126 ^ v68) & 0xFFFF] ^ v134 & 127 ^ (v134 << 9)) & 0xFFFF;
        let v135 = (v133 ^ v52) & 127;
        v126 = (v135 ^ this.Misty1Const[((v133 ^ v52) & 0xFFFF) >> 7]) & 0xFFFF;
        v135 = (v50 ^ v126 ^ this.Misty1_setup[v135]) & 0xFFFF;
        v135 = (v68 ^ this.Misty1Const[(v126 ^ v25) & 0xFFFF] ^ v135 & 127 ^ (v135 << 9)) & 0xFFFF;
        v68 = (v68 ^ v12) & 0xFFFF;
        let v136 = (v68 & 0xFFFF) >> 7;
        let v137 = v68 & 127;
        v136 = (v137 ^ this.Misty1Const[v136]) & 0xFFFF;
        v137 = (v141 ^ v136 ^ this.Misty1_setup[v137]) & 0xFFFF;
        v118 = (v118 ^ this.Misty1Const[(v136 ^ v142) & 0xFFFF] ^ v135 ^ v137 & 127 ^ (v137 << 9)) & 0xFFFF;
        v2 = (v116 ^ v11 ^ v135 ^ (v118 | v11)) & 0XFFFF;
        v12 = ((v2 & 0xFFFF) & v146 ^ v118) & 0xFFFF;
        v11 = (((v133 | v145) ^ v132) & v139 ^ v133) & 0xFFFF;
        let final = ((v133 | v145) ^ v132) & 0xFFFF;
        var out_blk;
        if ((0, common_js_1.isBuffer)(block)) {
            out_blk = Buffer.alloc(8);
        }
        else {
            out_blk = new Uint8Array(8);
        }
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(final), 0);
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(v11), 2);
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(v2), 4);
        (0, common_js_1.writeUInt16LE)(out_blk, ShortSwitch(v12 & 0xFFFF), 6);
        var return_buffer = out_blk;
        if (this.iv_set == true) {
            return_buffer = (0, common_js_1.xor)(out_blk, this.iv);
        }
        return return_buffer;
    }
    ;
    /**
     * IV for CBC encryption.
     *
     * Must be 8 bytes!
     *
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv) {
        if (iv) {
            if (!(0, common_js_1.isBufferOrUint8Array)(iv)) {
                throw Error("IV must be a buffer or UInt8Array");
            }
            else {
                if (iv.length != 8) {
                    throw Error("Enter a vaild 8 byte IV for CBC mode");
                }
                else {
                    this.iv = iv;
                    this.iv_set = true;
                }
            }
        }
        else {
            throw Error("Enter a vaild 8 byte IV for CBC mode");
        }
    }
    ;
    /**
     *
     * If IV is not set, runs in ECB mode.
     * If IV was set, runs in CBC mode.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @param {number} padd - ```number```
     * @returns ```Buffer``` or ```Uint8Array```
     */
    encrypt(data_in, padd) {
        if (!(0, common_js_1.isBufferOrUint8Array)(data_in)) {
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 8;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padd;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padd_value == undefined) {
                padd_value = 0xff;
            }
            if ((0, common_js_1.isBuffer)(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xff);
                data = Buffer.concat([data_in, paddbuffer]);
            }
            else {
                data = (0, common_js_1.extendUint8Array)(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer;
        if ((0, common_js_1.isBuffer)(data_in)) {
            final_buffer = Buffer.concat(return_buff);
        }
        else {
            final_buffer = (0, common_js_1.concatenateUint8Arrays)(return_buff);
        }
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     *
     * If IV is not set, runs in ECB mode.
     * If IV was set, runs in CBC mode.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @returns ```Buffer``` or ```Uint8Array```
     */
    decrypt(data_in) {
        if (!(0, common_js_1.isBufferOrUint8Array)(data_in)) {
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 8;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var padd_value = 0xff;
            if ((0, common_js_1.isBuffer)(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                data = Buffer.concat([data_in, paddbuffer]);
            }
            else {
                data = (0, common_js_1.extendUint8Array)(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.decrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer;
        if ((0, common_js_1.isBuffer)(data_in)) {
            final_buffer = Buffer.concat(return_buff);
        }
        else {
            final_buffer = (0, common_js_1.concatenateUint8Arrays)(return_buff);
        }
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
exports.MISTY1 = MISTY1;
//# sourceMappingURL=MISTY1.js.map