import { isBuffer, isBufferOrUint8Array, extendUint8Array, concatenateUint8Arrays, xor, align, removePKCSPadding } from './common.js';
/**
 * CHACHA20 encryption.
 *
 * Key must be 32 bytes, 12 byte Nonce, 16 byte IV
 *
 * Example:
 * ```
 * const cipher = new CHACHA20();
 * // Key for browser
 * const encoder_key = new TextEncoder();
 * const key = encoder_key.encode("0123456789ABCDEF0123456789ABCDEF");
 * const encoder_nonce = new TextEncoder();
 * const nonce = encoder_nonce.encode("0123456789AB");
 * cipher.set_key(key,nonce)
 * // Key for node
 * const key = Buffer.from("0123456789ABCDEF0123456789ABCDEF");
 * const nonce = Buffer.from("0123456789AB");
 * cipher.set_key(key, nonce)
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
export class CHACHA20 {
    constructor() {
        this.key_set = false;
        this.iv_set = false;
        this.matrix = new Uint32Array(16);
        this.intToLittleEndian = function (n, bs, off) {
            bs[off] = ((n) | 0);
            bs[++off] = ((n >>> 8) | 0);
            bs[++off] = ((n >>> 16) | 0);
            bs[++off] = ((n >>> 24) | 0);
        };
    }
    littleEndianToInt(bs, i) {
        return (bs[i] & 255) | ((bs[i + 1] & 255) << 8) | ((bs[i + 2] & 255) << 16) | ((bs[i + 3] & 255) << 24);
    }
    ;
    ROTATE(v, c) {
        return (v << c) | (v >>> (32 - c));
    }
    ;
    quarterRound(x, a, b, c, d) {
        x[a] += x[b];
        x[d] = this.ROTATE(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = this.ROTATE(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = this.ROTATE(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = this.ROTATE(x[b] ^ x[c], 7);
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
            if (!isBufferOrUint8Array(iv)) {
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
    /**
     * Key for encryption.
     *
     * Key must be 32 bytes!
     * Nonce must be 12 bytes!
     *
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     * @param {Buffer|Uint8Array} nonce - ```Buffer``` or ```Uint8Array```
     */
    set_key(key, nonce) {
        if (!isBufferOrUint8Array(key)) {
            throw Error("key must be Buffer or Uint8Array");
        }
        this.matrix = new Uint32Array(16);
        if (key.length !== 32) {
            throw new Error("Key must be 32 bytes");
        }
        this.matrix[0] = 1634760805;
        this.matrix[1] = 857760878;
        this.matrix[2] = 2036477234;
        this.matrix[3] = 1797285236;
        this.matrix[4] = this.littleEndianToInt(key, 0);
        this.matrix[5] = this.littleEndianToInt(key, 4);
        this.matrix[6] = this.littleEndianToInt(key, 8);
        this.matrix[7] = this.littleEndianToInt(key, 12);
        this.matrix[8] = this.littleEndianToInt(key, 16);
        this.matrix[9] = this.littleEndianToInt(key, 20);
        this.matrix[10] = this.littleEndianToInt(key, 24);
        this.matrix[11] = this.littleEndianToInt(key, 28);
        if (nonce.length === 12) {
            this.matrix[12] = 0;
            this.matrix[13] = this.littleEndianToInt(nonce, 0);
            this.matrix[14] = this.littleEndianToInt(nonce, 4);
            this.matrix[15] = this.littleEndianToInt(nonce, 8);
        }
        else {
            throw new Error("Nonce must be 12 bytes");
        }
        this.key_set = true;
    }
    ;
    decrypt_block(block) {
        let src = block;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = src;
        var x = new Uint32Array(16);
        var output = new Uint8Array(16);
        var dst = new Uint8Array(16);
        var i;
        for (i = 16; i-- > 0;) {
            x[i] = this.matrix[i];
        }
        for (i = 20; i > 0; i -= 2) {
            {
                this.quarterRound(x, 0, 4, 8, 12);
                this.quarterRound(x, 1, 5, 9, 13);
                this.quarterRound(x, 2, 6, 10, 14);
                this.quarterRound(x, 3, 7, 11, 15);
                this.quarterRound(x, 0, 5, 10, 15);
                this.quarterRound(x, 1, 6, 11, 12);
                this.quarterRound(x, 2, 7, 8, 13);
                this.quarterRound(x, 3, 4, 9, 14);
            }
            ;
        }
        for (i = 16; i-- > 0;) {
            x[i] += this.matrix[i];
        }
        for (i = 16; i-- > 0;) {
            this.intToLittleEndian(x[i], output, 4 * i);
        }
        this.matrix[12] += 1;
        if (this.matrix[12] === 0) {
            this.matrix[13] += 1;
        }
        for (i = 16; i-- > 0;) {
            dst[i] = ((src[i] ^ output[i]) | 0);
        }
        var out_blk;
        if (isBuffer(block)) {
            out_blk = Buffer.from(dst);
        }
        else {
            out_blk = dst;
        }
        var return_buffer = out_blk;
        if (this.iv_set == true) {
            return_buffer = xor(out_blk, this.iv);
        }
        return return_buffer;
    }
    ;
    encrypt_block(block) {
        let src = block;
        if (this.iv_set == true) {
            src = xor(block, this.iv);
        }
        var x = new Uint32Array(16);
        var output = new Uint8Array(16);
        var dst = new Uint8Array(16);
        var i;
        for (i = 16; i-- > 0;) {
            x[i] = this.matrix[i];
        }
        for (i = 20; i > 0; i -= 2) {
            {
                this.quarterRound(x, 0, 4, 8, 12);
                this.quarterRound(x, 1, 5, 9, 13);
                this.quarterRound(x, 2, 6, 10, 14);
                this.quarterRound(x, 3, 7, 11, 15);
                this.quarterRound(x, 0, 5, 10, 15);
                this.quarterRound(x, 1, 6, 11, 12);
                this.quarterRound(x, 2, 7, 8, 13);
                this.quarterRound(x, 3, 4, 9, 14);
            }
            ;
        }
        for (i = 16; i-- > 0;) {
            x[i] += this.matrix[i];
        }
        for (i = 16; i-- > 0;) {
            this.intToLittleEndian(x[i], output, 4 * i);
        }
        this.matrix[12] += 1;
        if (this.matrix[12] === 0) {
            this.matrix[13] += 1;
        }
        for (i = 16; i-- > 0;) {
            dst[i] = ((src[i] ^ output[i]) | 0);
        }
        var out_blk;
        if (isBuffer(block)) {
            out_blk = Buffer.from(dst);
        }
        else {
            out_blk = dst;
        }
        if (this.iv_set == true) {
            this.iv = out_blk;
        }
        return dst;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @param {number} padding - ```number```
     * @returns ```Buffer``` or ```Uint8Array```
     */
    encrypt(data_in, padding) {
        if (!isBufferOrUint8Array(data_in)) {
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padding;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padd_value == undefined) {
                padd_value = align(data.length, block_size);
            }
            if (isBuffer(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                data = Buffer.concat([data_in, paddbuffer]);
            }
            else {
                data = extendUint8Array(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer;
        if (isBuffer(data_in)) {
            final_buffer = Buffer.concat(return_buff);
        }
        else {
            final_buffer = concatenateUint8Arrays(return_buff);
        }
        this.key_set = false;
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If remove_padding is ``number``, will check the last block and remove padded number.
     *
     * If remove_padding is ``true``, will remove PKCS padding on last block.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @param {boolean|number} remove_padding - Will check the last block and remove padded ``number``. Will remove PKCS if ``true``
     * @returns ```Buffer``` or ```Uint8Array```
     */
    decrypt(data_in, remove_padding) {
        if (!isBufferOrUint8Array(data_in)) {
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value;
        if (remove_padding == undefined) {
            padd_value = 0xff;
        }
        else if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
        }
        else {
            padd_value = align(data.length, block_size);
        }
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (isBuffer(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                data = Buffer.concat([data_in, paddbuffer]);
            }
            else {
                data = extendUint8Array(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            var return_block = this.decrypt_block(block);
            if (index == (amount - 1)) {
                if (remove_padding != undefined) {
                    if (typeof remove_padding == 'number') {
                        return_block = removePKCSPadding(return_block, block_size, padd_value);
                    }
                    else {
                        return_block = removePKCSPadding(return_block, block_size);
                    }
                }
                return_buff.push(return_block);
            }
            else {
                return_buff.push(return_block);
            }
        }
        var final_buffer;
        if (isBuffer(data_in)) {
            final_buffer = Buffer.concat(return_buff);
        }
        else {
            final_buffer = concatenateUint8Arrays(return_buff);
        }
        this.key_set = false;
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
//# sourceMappingURL=CHACHA20.js.map