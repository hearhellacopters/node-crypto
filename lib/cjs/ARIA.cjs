"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ARIA = void 0;
function isBufferOrUint8Array(obj) {
    return obj instanceof Uint8Array || (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}
function isBuffer(obj) {
    return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}
function extendUint8Array(array, newLength, padValue) {
    const newArray = new Uint8Array(newLength);
    newArray.set(array);
    for (let i = array.length; i < newLength; i++) {
        newArray[i] = padValue;
    }
    return newArray;
}
function concatenateUint8Arrays(arrays) {
    const totalLength = arrays.reduce((length, array) => length + array.length, 0);
    const concatenatedArray = new Uint8Array(totalLength);
    let offset = 0;
    for (let i = 0; i < arrays.length; i++) {
        concatenatedArray.set(arrays[i], offset);
        offset += arrays[i].length;
    }
    return concatenatedArray;
}
function xor(buf1, buf2) {
    let number = -1;
    const bufResult = buf1.map((b) => {
        if (number != buf2.length - 1) {
            number = number + 1;
        }
        else {
            number = 0;
        }
        return b ^ buf2[number];
    });
    return bufResult;
}
function align(a, n) {
    var a = a % n;
    if (a) {
        return (n - a);
    }
    else {
        return 0;
    }
}
function removePKCSPadding(buffer, blockSize, number) {
    if (buffer.length % blockSize !== 0) {
        return buffer;
    }
    const lastByte = buffer[buffer.length - 1];
    const paddingSize = lastByte;
    // if number supplied padding number
    if (number != undefined) {
        if (lastByte != number) {
            return buffer;
        }
        else {
            var len = buffer.length;
            for (let i = buffer.length - 1; i >= buffer.length; i--) {
                if (buffer[i] == number) {
                    len--;
                }
            }
            return buffer.subarray(0, len);
        }
    }
    if (paddingSize > blockSize) {
        return buffer;
    }
    else {
        for (let i = buffer.length - 1; i >= buffer.length - paddingSize; i--) {
            if (buffer[i] !== paddingSize) {
                return buffer;
            }
        }
        return buffer.subarray(0, buffer.length - paddingSize);
    }
}
/**
 * ARIA 128 / 192 / 256 encryption.
 *
 * 16, 24 or 32 bytes key, matching byte IV
 *
 * Example:
 * ```
 * const cipher = new ARIA();
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
class ARIA {
    constructor() {
        this.key_set = false;
        this.iv_set = false;
    }
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     */
    set_key(key) {
        if (!isBufferOrUint8Array(key)) {
            throw Error("key must be Buffer or Uint8Array");
        }
        if (this.mEK === undefined) {
            this.mEK = null;
        }
        if (this.mDK === undefined) {
            this.mDK = null;
        }
        if (this.mNumberRounds === undefined) {
            this.mNumberRounds = 0;
        }
        if (this.mKeyLength === undefined) {
            this.mKeyLength = 0;
        }
        this.scheduleKey(key);
        this.key_set = true;
    }
    /**
     * IV for CBC encryption.
     *
     * Must be same length as key!
     *
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv) {
        if (this.key_set != true) {
            throw Error("Must set key before IV");
        }
        if (iv) {
            if (!isBufferOrUint8Array(iv)) {
                throw Error("IV must be a buffer or UInt8Array");
            }
            else {
                if (iv.length != this.mKeyLength) {
                    throw Error(`Enter a vaild ${this.mKeyLength} byte IV for CBC mode`);
                }
                else {
                    this.iv = iv;
                    this.iv_set = true;
                }
            }
        }
        else {
            throw Error(`Enter a vaild ${this.mKeyLength} byte IV for CBC mode`);
        }
    }
    ;
    C1_$LI$() {
        if (this.C1 == null) {
            this.C1 = new Uint8Array([81, 124, 193, 183, 39, 34, 10, 148, 254, 19, 171, 232, 250, 154, 110, 224]);
        }
        return this.C1;
    }
    ;
    C2_$LI$() {
        if (this.C2 == null) {
            this.C2 = new Uint8Array([109, 177, 74, 204, 158, 33, 200, 32, 255, 40, 177, 213, 239, 93, 226, 176]);
        }
        return this.C2;
    }
    ;
    C3_$LI$() {
        if (this.C3 == null) {
            this.C3 = new Uint8Array([219, 146, 55, 29, 33, 38, 233, 112, 3, 36, 151, 117, 4, 232, 201, 14]);
        }
        return this.C3;
    }
    ;
    SB1_$LI$() {
        if (this.SB1 == null) {
            this.SB1 = new Uint8Array([99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
                202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
                183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
                4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
                9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
                83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
                208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
                81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
                205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
                96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
                224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
                231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
                186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
                112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
                225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
                140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]);
        }
        return this.SB1;
    }
    ;
    SB2_$LI$() {
        if (this.SB2 == null) {
            this.SB2 = new Uint8Array([226, 78, 84, 252, 148, 194, 74, 204, 98, 13, 106, 70, 60, 77, 139, 209,
                94, 250, 100, 203, 180, 151, 190, 43, 188, 119, 46, 3, 211, 25, 89, 193,
                29, 6, 65, 107, 85, 240, 153, 105, 234, 156, 24, 174, 99, 223, 231, 187,
                0, 115, 102, 251, 150, 76, 133, 228, 58, 9, 69, 170, 15, 238, 16, 235,
                45, 127, 244, 41, 172, 207, 173, 145, 141, 120, 200, 149, 249, 47, 206, 205,
                8, 122, 136, 56, 92, 131, 42, 40, 71, 219, 184, 199, 147, 164, 18, 83,
                255, 135, 14, 49, 54, 33, 88, 72, 1, 142, 55, 116, 50, 202, 233, 177,
                183, 171, 12, 215, 196, 86, 66, 38, 7, 152, 96, 217, 182, 185, 17, 64,
                236, 32, 140, 189, 160, 201, 132, 4, 73, 35, 241, 79, 80, 31, 19, 220,
                216, 192, 158, 87, 227, 195, 123, 101, 59, 2, 143, 62, 232, 37, 146, 229,
                21, 221, 253, 23, 169, 191, 212, 154, 126, 197, 57, 103, 254, 118, 157, 67,
                167, 225, 208, 245, 104, 242, 27, 52, 112, 5, 163, 138, 213, 121, 134, 168,
                48, 198, 81, 75, 30, 166, 39, 246, 53, 210, 110, 36, 22, 130, 95, 218,
                230, 117, 162, 239, 44, 178, 28, 159, 93, 111, 128, 10, 114, 68, 155, 108,
                144, 11, 91, 51, 125, 90, 82, 243, 97, 161, 247, 176, 214, 63, 124, 109,
                237, 20, 224, 165, 61, 34, 179, 248, 137, 222, 113, 26, 175, 186, 181, 129]);
        }
        return this.SB2;
    }
    ;
    SB3_$LI$() {
        if (this.SB3 == null) {
            this.SB3 = new Uint8Array([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
                124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
                84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
                8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
                114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
                108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
                144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
                208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
                58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
                150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
                71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
                252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
                31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
                96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
                160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
                23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]);
        }
        return this.SB3;
    }
    ;
    SB4_$LI$() {
        if (this.SB4 == null) {
            this.SB4 = new Uint8Array([48, 104, 153, 27, 135, 185, 33, 120, 80, 57, 219, 225, 114, 9, 98, 60,
                62, 126, 94, 142, 241, 160, 204, 163, 42, 29, 251, 182, 214, 32, 196, 141,
                129, 101, 245, 137, 203, 157, 119, 198, 87, 67, 86, 23, 212, 64, 26, 77,
                192, 99, 108, 227, 183, 200, 100, 106, 83, 170, 56, 152, 12, 244, 155, 237,
                127, 34, 118, 175, 221, 58, 11, 88, 103, 136, 6, 195, 53, 13, 1, 139,
                140, 194, 230, 95, 2, 36, 117, 147, 102, 30, 229, 226, 84, 216, 16, 206,
                122, 232, 8, 44, 18, 151, 50, 171, 180, 39, 10, 35, 223, 239, 202, 217,
                184, 250, 220, 49, 107, 209, 173, 25, 73, 189, 81, 150, 238, 228, 168, 65,
                218, 255, 205, 85, 134, 54, 190, 97, 82, 248, 187, 14, 130, 72, 105, 154,
                224, 71, 158, 92, 4, 75, 52, 21, 121, 38, 167, 222, 41, 174, 146, 215,
                132, 233, 210, 186, 93, 243, 197, 176, 191, 164, 59, 113, 68, 70, 43, 252,
                235, 111, 213, 246, 20, 254, 124, 112, 90, 125, 253, 47, 24, 131, 22, 165,
                145, 31, 5, 149, 116, 169, 193, 91, 74, 133, 109, 19, 7, 79, 78, 69,
                178, 15, 201, 28, 166, 188, 236, 115, 144, 123, 207, 89, 143, 161, 249, 45,
                242, 177, 0, 148, 55, 159, 208, 46, 156, 110, 40, 63, 128, 240, 61, 211,
                37, 138, 181, 231, 66, 179, 199, 234, 247, 76, 17, 51, 3, 162, 172, 96]);
        }
        return this.SB4;
    }
    ;
    XOR(x, y) {
        var length = x.length;
        var result = new Uint8Array(length);
        result.set(x);
        var i = 0;
        while ((i < length && i < y.length)) {
            {
                result[i] ^= y[i];
                i++;
            }
        }
        ;
        return result;
    }
    ;
    ROL(array, nShift) {
        var nBytes = array.length;
        var result = new Uint8Array(nBytes);
        nShift = nShift % (nBytes * 8);
        if (nShift === 0) {
            result.set(array);
        }
        else {
            var byteOffset = (nShift / 8 | 0);
            var leftShift = nShift % 8;
            var rightShift = 8 - leftShift;
            for (var i = 0; i < nBytes; i++) {
                {
                    var leftPart = ((array[(i + byteOffset) % nBytes] << leftShift) | 0);
                    var rightPart = ((this.unsigned(array[(i + byteOffset + 1) % nBytes]) >> rightShift) | 0);
                    result[i] = ((leftPart | rightPart) | 0);
                }
                ;
            }
        }
        return result;
    }
    ;
    ROR(array, nShift) {
        return this.ROL(array, (array.length * 8) - nShift);
    }
    ;
    unsigned(b) {
        return b & 255;
    }
    ;
    SL1(array) {
        var result = new Uint8Array(16);
        result[0] = this.SB1_$LI$()[this.unsigned(array[0])];
        result[1] = this.SB2_$LI$()[this.unsigned(array[1])];
        result[2] = this.SB3_$LI$()[this.unsigned(array[2])];
        result[3] = this.SB4_$LI$()[this.unsigned(array[3])];
        result[4] = this.SB1_$LI$()[this.unsigned(array[4])];
        result[5] = this.SB2_$LI$()[this.unsigned(array[5])];
        result[6] = this.SB3_$LI$()[this.unsigned(array[6])];
        result[7] = this.SB4_$LI$()[this.unsigned(array[7])];
        result[8] = this.SB1_$LI$()[this.unsigned(array[8])];
        result[9] = this.SB2_$LI$()[this.unsigned(array[9])];
        result[10] = this.SB3_$LI$()[this.unsigned(array[10])];
        result[11] = this.SB4_$LI$()[this.unsigned(array[11])];
        result[12] = this.SB1_$LI$()[this.unsigned(array[12])];
        result[13] = this.SB2_$LI$()[this.unsigned(array[13])];
        result[14] = this.SB3_$LI$()[this.unsigned(array[14])];
        result[15] = this.SB4_$LI$()[this.unsigned(array[15])];
        return result;
    }
    ;
    SL2(array) {
        var result = new Uint8Array(16);
        result[0] = this.SB3_$LI$()[this.unsigned(array[0])];
        result[1] = this.SB4_$LI$()[this.unsigned(array[1])];
        result[2] = this.SB1_$LI$()[this.unsigned(array[2])];
        result[3] = this.SB2_$LI$()[this.unsigned(array[3])];
        result[4] = this.SB3_$LI$()[this.unsigned(array[4])];
        result[5] = this.SB4_$LI$()[this.unsigned(array[5])];
        result[6] = this.SB1_$LI$()[this.unsigned(array[6])];
        result[7] = this.SB2_$LI$()[this.unsigned(array[7])];
        result[8] = this.SB3_$LI$()[this.unsigned(array[8])];
        result[9] = this.SB4_$LI$()[this.unsigned(array[9])];
        result[10] = this.SB1_$LI$()[this.unsigned(array[10])];
        result[11] = this.SB2_$LI$()[this.unsigned(array[11])];
        result[12] = this.SB3_$LI$()[this.unsigned(array[12])];
        result[13] = this.SB4_$LI$()[this.unsigned(array[13])];
        result[14] = this.SB1_$LI$()[this.unsigned(array[14])];
        result[15] = this.SB2_$LI$()[this.unsigned(array[15])];
        return result;
    }
    ;
    FO(D, RK) {
        return this.A(this.SL1(this.XOR(D, RK)));
    }
    ;
    FE(D, RK) {
        return this.A(this.SL2(this.XOR(D, RK)));
    }
    ;
    A(b) {
        var length = b.length;
        if (length !== 16) {
            throw new Error("Illegal input size. Diffusion layer should take 16-byte string as parameter.");
        }
        else {
            var result = new Uint8Array(16);
            result[0] = ((b[3] ^ b[4] ^ b[6] ^ b[8] ^ b[9] ^ b[13] ^ b[14]) | 0);
            result[1] = ((b[2] ^ b[5] ^ b[7] ^ b[8] ^ b[9] ^ b[12] ^ b[15]) | 0);
            result[2] = ((b[1] ^ b[4] ^ b[6] ^ b[10] ^ b[11] ^ b[12] ^ b[15]) | 0);
            result[3] = ((b[0] ^ b[5] ^ b[7] ^ b[10] ^ b[11] ^ b[13] ^ b[14]) | 0);
            result[4] = ((b[0] ^ b[2] ^ b[5] ^ b[8] ^ b[11] ^ b[14] ^ b[15]) | 0);
            result[5] = ((b[1] ^ b[3] ^ b[4] ^ b[9] ^ b[10] ^ b[14] ^ b[15]) | 0);
            result[6] = ((b[0] ^ b[2] ^ b[7] ^ b[9] ^ b[10] ^ b[12] ^ b[13]) | 0);
            result[7] = ((b[1] ^ b[3] ^ b[6] ^ b[8] ^ b[11] ^ b[12] ^ b[13]) | 0);
            result[8] = ((b[0] ^ b[1] ^ b[4] ^ b[7] ^ b[10] ^ b[13] ^ b[15]) | 0);
            result[9] = ((b[0] ^ b[1] ^ b[5] ^ b[6] ^ b[11] ^ b[12] ^ b[14]) | 0);
            result[10] = ((b[2] ^ b[3] ^ b[5] ^ b[6] ^ b[8] ^ b[13] ^ b[15]) | 0);
            result[11] = ((b[2] ^ b[3] ^ b[4] ^ b[7] ^ b[9] ^ b[12] ^ b[14]) | 0);
            result[12] = ((b[1] ^ b[2] ^ b[6] ^ b[7] ^ b[9] ^ b[11] ^ b[12]) | 0);
            result[13] = ((b[0] ^ b[3] ^ b[6] ^ b[7] ^ b[8] ^ b[10] ^ b[13]) | 0);
            result[14] = ((b[0] ^ b[3] ^ b[4] ^ b[5] ^ b[9] ^ b[11] ^ b[14]) | 0);
            result[15] = ((b[1] ^ b[2] ^ b[4] ^ b[5] ^ b[8] ^ b[10] ^ b[15]) | 0);
            return result;
        }
    }
    ;
    scheduleKey(key) {
        this.mKeyLength = key.length;
        var CK1;
        var CK2;
        var CK3;
        if (this.mKeyLength === 16) {
            CK1 = this.C1_$LI$();
            CK2 = this.C2_$LI$();
            CK3 = this.C3_$LI$();
            this.mNumberRounds = 12;
        }
        else if (this.mKeyLength === 24) {
            CK1 = this.C2_$LI$();
            CK2 = this.C3_$LI$();
            CK3 = this.C1_$LI$();
            this.mNumberRounds = 14;
        }
        else if (this.mKeyLength === 32) {
            CK1 = this.C3_$LI$();
            CK2 = this.C1_$LI$();
            CK3 = this.C2_$LI$();
            this.mNumberRounds = 16;
        }
        else {
            throw new Error("Illegal key length. Only 128, 192 and 256 bit keys are valid.");
        }
        var W0 = key.slice(0, 16);
        var KR = (this.mKeyLength > 16) ? extendUint8Array(key.slice(16, key.length), 16, 0) : new Uint8Array(16);
        var W1 = this.XOR(this.FO(W0, CK1), KR);
        var W2 = this.XOR(this.FE(W1, CK2), W0);
        var W3 = this.XOR(this.FO(W2, CK3), W1);
        this.mEK = new Array(17);
        this.mEK[0] = this.XOR(W0, this.ROR(W1, 19));
        this.mEK[1] = this.XOR(W1, this.ROR(W2, 19));
        this.mEK[2] = this.XOR(W2, this.ROR(W3, 19));
        this.mEK[3] = this.XOR(this.ROR(W0, 19), W3);
        this.mEK[4] = this.XOR(W0, this.ROR(W1, 31));
        this.mEK[5] = this.XOR(W1, this.ROR(W2, 31));
        this.mEK[6] = this.XOR(W2, this.ROR(W3, 31));
        this.mEK[7] = this.XOR(this.ROR(W0, 31), W3);
        this.mEK[8] = this.XOR(W0, this.ROL(W1, 61));
        this.mEK[9] = this.XOR(W1, this.ROL(W2, 61));
        this.mEK[10] = this.XOR(W2, this.ROL(W3, 61));
        this.mEK[11] = this.XOR(this.ROL(W0, 61), W3);
        this.mEK[12] = this.XOR(W0, this.ROL(W1, 31));
        this.mEK[13] = this.XOR(W1, this.ROL(W2, 31));
        this.mEK[14] = this.XOR(W2, this.ROL(W3, 31));
        this.mEK[15] = this.XOR(this.ROL(W0, 31), W3);
        this.mEK[16] = this.XOR(W0, this.ROL(W1, 19));
        this.mDK = new Array(this.mNumberRounds + 1);
        this.mDK[0] = this.mEK[this.mNumberRounds];
        for (var i = 1; i < this.mNumberRounds; i++) {
            this.mDK[i] = this.A(this.mEK[this.mNumberRounds - i]);
        }
        this.mDK[this.mNumberRounds] = this.mEK[0];
    }
    ;
    encrypt_block(start_chunk) {
        let text = start_chunk;
        if (this.iv_set == true) {
            text = xor(start_chunk, this.iv);
        }
        var keys = this.mEK;
        var length = text.length;
        var result = new Uint8Array(length);
        var block = new Uint8Array(this.mKeyLength);
        var nBlocks = (length / this.mKeyLength | 0);
        for (var i = 0; i < nBlocks; i++) {
            {
                var currentPos = i * this.mKeyLength;
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.slice(srcOff, srcOff + size);
                        for (var i_1 = 0; i_1 < size; i_1++)
                            dstPts[dstOff++] = tmp[i_1];
                    }
                })(text, currentPos, block, 0, this.mKeyLength);
                block = this.FO(block, keys[0]);
                for (var j = 1; j < this.mNumberRounds - 1; j++) {
                    block = (j % 2) === 0 ? this.FO(block, keys[j]) : this.FE(block, keys[j]);
                }
                block = this.XOR(this.SL2(this.XOR(block, keys[this.mNumberRounds - 1])), keys[this.mNumberRounds]);
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.slice(srcOff, srcOff + size);
                        for (var i_2 = 0; i_2 < size; i_2++)
                            dstPts[dstOff++] = tmp[i_2];
                    }
                })(block, 0, result, currentPos, this.mKeyLength);
            }
            ;
        }
        if (this.iv_set == true) {
            this.iv = result;
        }
        return result;
    }
    ;
    decrypt_block(start_chunk) {
        var text = start_chunk;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = text;
        var keys = this.mDK;
        var length = text.length;
        var result = new Uint8Array(length);
        var block = new Uint8Array(this.mKeyLength);
        var nBlocks = (length / this.mKeyLength | 0);
        for (var i = 0; i < nBlocks; i++) {
            {
                var currentPos = i * this.mKeyLength;
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.slice(srcOff, srcOff + size);
                        for (var i_1 = 0; i_1 < size; i_1++)
                            dstPts[dstOff++] = tmp[i_1];
                    }
                })(text, currentPos, block, 0, this.mKeyLength);
                block = this.FO(block, keys[0]);
                for (var j = 1; j < this.mNumberRounds - 1; j++) {
                    block = (j % 2) === 0 ? this.FO(block, keys[j]) : this.FE(block, keys[j]);
                }
                block = this.XOR(this.SL2(this.XOR(block, keys[this.mNumberRounds - 1])), keys[this.mNumberRounds]);
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.slice(srcOff, srcOff + size);
                        for (var i_2 = 0; i_2 < size; i_2++)
                            dstPts[dstOff++] = tmp[i_2];
                    }
                })(block, 0, result, currentPos, this.mKeyLength);
            }
            ;
        }
        var return_buffer = result;
        if (this.iv_set == true) {
            return_buffer = this.XOR(result, this.iv);
        }
        return return_buffer;
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
        const block_size = this.mKeyLength;
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
        const block_size = this.mKeyLength;
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
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
exports.ARIA = ARIA;
//# sourceMappingURL=ARIA.js.map