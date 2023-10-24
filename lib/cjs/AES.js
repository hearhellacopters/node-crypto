"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AES = void 0;
const common_1 = require("./common");
/**
 * AES 128 / 192 / 256 encryption.
 *
 * 16, 24 or 32 bytes key, 16 byte IV
 *
 * Example:
 * ```
 * const cipher = new AES();
 * // Key for browser
 * const encoder_key = new TextEncoder();
 * const key = encoder_key.encode("0123456789ABCDEF");
 * cipher.set_key(key)
 * // Key for node
 * const key = Buffer.from("0123456789ABCDEF");
 * cipher.set_key(key)
 * // set IV for browser
 * const encoder_IV = new TextEncoder();
 * const IV = encoder_IV.encode("0123456789ABCDEF");
 * cipher.set_iv(IV)
 * // set IV for node
 * const IV = Buffer.from("0123456789ABCDEF");
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
class AES {
    AES_SubBytes(state, sbox) {
        for (var i = 0; i < 16; i++) {
            state[i] = sbox[state[i]];
        }
    }
    AES_AddRoundKey(state, rkey) {
        for (var i = 0; i < 16; i++) {
            state[i] ^= rkey[i];
        }
    }
    AES_ShiftRows(state, shifttab) {
        var h = new Array().concat(state);
        for (var i = 0; i < 16; i++) {
            state[i] = h[shifttab[i]];
        }
    }
    AES_MixColumns(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0], s1 = state[i + 1];
            var s2 = state[i + 2], s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            state[i + 0] ^= h ^ this.AES_xtime[s0 ^ s1];
            state[i + 1] ^= h ^ this.AES_xtime[s1 ^ s2];
            state[i + 2] ^= h ^ this.AES_xtime[s2 ^ s3];
            state[i + 3] ^= h ^ this.AES_xtime[s3 ^ s0];
        }
    }
    AES_MixColumns_Inv(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0], s1 = state[i + 1];
            var s2 = state[i + 2], s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            var xh = this.AES_xtime[h];
            var h1 = this.AES_xtime[this.AES_xtime[xh ^ s0 ^ s2]] ^ h;
            var h2 = this.AES_xtime[this.AES_xtime[xh ^ s1 ^ s3]] ^ h;
            state[i + 0] ^= h1 ^ this.AES_xtime[s0 ^ s1];
            state[i + 1] ^= h2 ^ this.AES_xtime[s1 ^ s2];
            state[i + 2] ^= h1 ^ this.AES_xtime[s2 ^ s3];
            state[i + 3] ^= h2 ^ this.AES_xtime[s3 ^ s0];
        }
    }
    constructor() {
        this.key_set = false;
        this.iv_set = false;
        this.AES_Sbox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);
        this.AES_ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
        this.AES_Sbox_Inv = new Array(256);
        this.AES_xtime = new Array(256);
        this.AES_ShiftRowTab_Inv = new Array(16);
    }
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer|Uint8Array} key_data - ```Buffer``` or ```Uint8Array```
     */
    set_key(key_data) {
        if (!(0, common_1.isBufferOrUint8Array)(key_data)) {
            throw Error("key must be Buffer or Uint8Array");
        }
        var kl = key_data.length, ks, Rcon = 1;
        switch (kl) {
            case 16:
                ks = 16 * (10 + 1);
                break;
            case 24:
                ks = 16 * (12 + 1);
                break;
            case 32:
                ks = 16 * (14 + 1);
                break;
            default:
                throw Error("Only key lengths of 16, 24 or 32 bytes allowed!");
        }
        const key = new Array(key_data.length);
        for (let i = 0; i < key_data.length; i++) {
            key[i] = key_data[i];
        }
        this.key = key;
        for (var i = kl; i < ks; i += 4) {
            var temp = key.slice(i - 4, i);
            if (i % kl == 0) {
                temp = new Array(this.AES_Sbox[temp[1]] ^ Rcon, this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]], this.AES_Sbox[temp[0]]);
                if ((Rcon <<= 1) >= 256)
                    Rcon ^= 0x11b;
            }
            else if ((kl > 24) && (i % kl == 16))
                temp = new Array(this.AES_Sbox[temp[0]], this.AES_Sbox[temp[1]], this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]]);
            for (var j = 0; j < 4; j++)
                key[i + j] = key[i + j - kl] ^ temp[j];
        }
        this.key_set = true;
        //setup
        for (var z = 0; z < 256; z++) {
            this.AES_Sbox_Inv[this.AES_Sbox[z]] = z;
        }
        for (var z = 0; z < 16; z++) {
            this.AES_ShiftRowTab_Inv[this.AES_ShiftRowTab[z]] = z;
        }
        for (var z = 0; z < 128; z++) {
            this.AES_xtime[z] = z << 1;
            this.AES_xtime[128 + z] = (z << 1) ^ 0x1b;
        }
    }
    ;
    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     *
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv) {
        if (iv) {
            if (!(0, common_1.isBufferOrUint8Array)(iv)) {
                throw Error("IV must be a buffer or UInt8Array");
            }
            else {
                if (iv.length != 16) {
                    throw Error("Enter a vaild 16 byte IV for CBC mode");
                }
                else {
                    this.iv = iv;
                    this.iv_set = true;
                }
            }
        }
        else {
            throw Error("Enter a vaild 16 byte IV for CBC mode");
        }
    }
    ;
    encrypt_block(start_chunk) {
        //check if IV is set, if so runs CBC
        let block = start_chunk;
        if (this.iv_set == true) {
            block = (0, common_1.xor)(start_chunk, this.iv);
        }
        const block_data = new Array(16);
        for (let i = 0; i < 16; i++) {
            block_data[i] = block[i];
        }
        var key = this.key;
        var l = key.length;
        this.AES_AddRoundKey(block_data, key.slice(0, 16));
        for (var i = 16; i < l - 16; i += 16) {
            this.AES_SubBytes(block_data, this.AES_Sbox);
            this.AES_ShiftRows(block_data, this.AES_ShiftRowTab);
            this.AES_MixColumns(block_data);
            this.AES_AddRoundKey(block_data, key.slice(i, i + 16));
        }
        this.AES_SubBytes(block_data, this.AES_Sbox);
        this.AES_ShiftRows(block_data, this.AES_ShiftRowTab);
        this.AES_AddRoundKey(block_data, key.slice(i, l));
        var block_out = block_data;
        if ((0, common_1.isBuffer)(start_chunk)) {
            block_out = Buffer.alloc(16);
            for (let i = 0; i < 16; i++) {
                block_out[i] = block_data[i];
            }
        }
        else {
            block_out = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                block_out[i] = block_data[i];
            }
        }
        if (this.iv_set == true) {
            this.iv = block_out;
        }
        return block_out;
    }
    ;
    decrypt_block(start_chunk) {
        let block = start_chunk;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = block;
        const block_data = new Array(16);
        for (let i = 0; i < 16; i++) {
            block_data[i] = block[i];
        }
        var key = this.key;
        var l = key.length;
        this.AES_AddRoundKey(block_data, key.slice(l - 16, l));
        this.AES_ShiftRows(block_data, this.AES_ShiftRowTab_Inv);
        this.AES_SubBytes(block_data, this.AES_Sbox_Inv);
        for (var i = l - 32; i >= 16; i -= 16) {
            this.AES_AddRoundKey(block_data, key.slice(i, i + 16));
            this.AES_MixColumns_Inv(block_data);
            this.AES_ShiftRows(block_data, this.AES_ShiftRowTab_Inv);
            this.AES_SubBytes(block_data, this.AES_Sbox_Inv);
        }
        this.AES_AddRoundKey(block_data, key.slice(0, 16));
        var block_out = block_data;
        if ((0, common_1.isBuffer)(start_chunk)) {
            block_out = Buffer.alloc(16);
            for (let i = 0; i < 16; i++) {
                block_out[i] = block_data[i];
            }
        }
        else {
            block_out = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                block_out[i] = block_data[i];
            }
        }
        var return_buffer = block_out;
        if (this.iv_set == true) {
            return_buffer = (0, common_1.xor)(block_out, this.iv);
        }
        return return_buffer;
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
        if (!(0, common_1.isBufferOrUint8Array)(data_in)) {
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 16;
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
            if ((0, common_1.isBuffer)(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                data = Buffer.concat([data_in, paddbuffer]);
            }
            else {
                data = (0, common_1.extendUint8Array)(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer;
        if ((0, common_1.isBuffer)(data_in)) {
            final_buffer = Buffer.concat(return_buff);
        }
        else {
            final_buffer = (0, common_1.concatenateUint8Arrays)(return_buff);
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
        if (!(0, common_1.isBufferOrUint8Array)(data_in)) {
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var padd_value = 0xff;
            if ((0, common_1.isBuffer)(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                data = Buffer.concat([data_in, paddbuffer]);
            }
            else {
                data = (0, common_1.extendUint8Array)(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.decrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer;
        if ((0, common_1.isBuffer)(data_in)) {
            final_buffer = Buffer.concat(return_buff);
        }
        else {
            final_buffer = (0, common_1.concatenateUint8Arrays)(return_buff);
        }
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
exports.AES = AES;
//# sourceMappingURL=AES.js.map