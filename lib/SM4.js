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
    let number = -1
    const bufResult = buf1.map((b, i) => {
        if (number != buf2.length - 1) {
        number = number + 1
        } else {
        number = 0
        }
        return b ^ buf2[number]
    });
    return bufResult;
}

class SM4 {
    constructor() {
        this.ROUND = 32;
        this.BLOCK = 16;
        this.SBOX = new Uint8Array(
            [214, 144, 233, 254, 204, 225, 61,  183, 22,  182, 20,  194, 40,  251, 44,  5, 
                43,  103, 154, 118, 42,  190, 4,   195, 170, 68,  19,  38,  73,  134, 6,   153,
                156, 66,  80,  244, 145, 239, 152, 122, 51,  84,  11,  67,  237, 207, 172, 98, 
                228, 179, 28,  169, 201, 8,   232, 149, 128, 223, 148, 250, 117, 143, 63,  166, 
                71,  7,   167, 252, 243, 115, 23,  186, 131, 89,  60,  25,  230, 133, 79,  168, 
                104, 107, 129, 178, 113, 100, 218, 139, 248, 235, 15,  75,  112, 86,  157, 53, 
                30,  36,  14,  94,  99,  88,  209, 162, 37,  34,  124, 59,  1,   33,  120, 135,
                212, 0,   70,  87,  159, 211, 39,  82,  76,  54,  2,   231, 160, 196, 200, 158, 
                234, 191, 138, 210, 64,  199, 56,  181, 163, 247, 242, 206, 249, 97,  21,  161, 
                224, 174, 93,  164, 155, 52,  26,  85,  173, 147, 50,  48,  245, 140, 177, 227, 
                29,  246, 226, 46,  130, 102, 202, 96,  192, 41,  35,  171, 13,  83,  78,  111, 
                213, 219, 55,  69,  222, 253, 142, 47,  3,   255, 106, 114, 109, 108, 91,  81, 
                141, 27,  175, 146, 187, 221, 188, 127, 17,  217, 92,  65,  31,  16,  90,  216, 
                10,  193, 49,  136, 165, 205, 123, 189, 45,  116, 208, 18,  184, 229, 180, 176, 
                137, 105, 151, 74,  12,  150, 119, 126, 101, 185, 241, 9,   197, 110, 198, 132, 
                24,  240, 125, 236, 58,  220, 77,  32,  121, 238, 95,  62,  215, 203, 57,  72]
        );
        this.CK = new Uint32Array(
                [462357,      472066609,   943670861,   1415275113, 
                 1886879365,  -1936483679, -1464879427, -993275175, 
                 -521670923,  -66909679,   404694573,   876298825, 
                 1347903077,  1819507329,  -2003855715, -1532251463, 
                 -1060647211, -589042959,  -117504499,  337322537, 
                 808926789,   1280531041,  1752135293,  -2071227751, 
                 -1599623499, -1128019247, -656414995,  -184876535, 
                 269950501,   741554753,   1213159005,  1684763257]
        );
        /*private*/ this.Rotl = function (x, y) {
            return x << y | x >>> (32 - y);
        };
        /*private*/ this.ByteSub = function (A) {
            return (this.SBOX[A >>> 24 & 255] & 255) << 24 | (this.SBOX[A >>> 16 & 255] & 255) << 16 | (this.SBOX[A >>> 8 & 255] & 255) << 8 | (this.SBOX[A & 255] & 255);
        };
        /*private*/ this.L1 = function (B) {
            return B ^ this.Rotl(B, 2) ^ this.Rotl(B, 10) ^ this.Rotl(B, 18) ^ this.Rotl(B, 24);
        };
        /*private*/ this.L2 = function (B) {
            return B ^ this.Rotl(B, 13) ^ this.Rotl(B, 23);
        };

        /**
         * IV for CBC encryption.
         *
         * Must be 16 bytes!
         * 
         * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
         */
        this.set_iv = function (iv) {
            if (iv) {
                if (!isBufferOrUint8Array(iv)) {
                    throw Error("IV must be a buffer or UInt8Array");
                } else {
                    if (iv.length != 16) {
                        throw Error("Enter a vaild 16 byte IV for CBC mode");
                    } else {
                        this.iv = iv;
                        this.iv_set = true;
                    }
                }
            } else {
                throw Error("Enter a vaild 16 byte IV for CBC mode");
            }
        };

        /**
         * Key for encryption.
         *
         * Key must be 16 bytes!
         * 
         * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
         */
        this.set_key = function (key) {
            if (!isBufferOrUint8Array(key)) {
                throw Error("key must be Buffer or Uint8Array");
            }
            let key_len = key.length;
            if (key_len != 16) {
                throw Error("key must be 16 bytes");
            }
            this.key = key
            this.key_set = true
        }
        this.SM4Crypt = function (Input) {
            var rk = this.round_key
            var Output = new Uint8Array(16)
            var r;
            var mid;
            var x = [0, 0, 0, 0];
            var tmp = [0, 0, 0, 0];
            for (var i = 0; i < 4; i++) {
                {
                    tmp[0] = Input[0 + 4 * i] & 255;
                    tmp[1] = Input[1 + 4 * i] & 255;
                    tmp[2] = Input[2 + 4 * i] & 255;
                    tmp[3] = Input[3 + 4 * i] & 255;
                    x[i] = tmp[0] << 24 | tmp[1] << 16 | tmp[2] << 8 | tmp[3];
                }
                ;
            }
            for (r = 0; r < 32; r += 4) {
                {
                    mid = x[1] ^ x[2] ^ x[3] ^ rk[r + 0];
                    mid = this.ByteSub(mid);
                    x[0] = x[0] ^ this.L1(mid);
                    mid = x[2] ^ x[3] ^ x[0] ^ rk[r + 1];
                    mid = this.ByteSub(mid);
                    x[1] = x[1] ^ this.L1(mid);
                    mid = x[3] ^ x[0] ^ x[1] ^ rk[r + 2];
                    mid = this.ByteSub(mid);
                    x[2] = x[2] ^ this.L1(mid);
                    mid = x[0] ^ x[1] ^ x[2] ^ rk[r + 3];
                    mid = this.ByteSub(mid);
                    x[3] = x[3] ^ this.L1(mid);
                }
                ;
            }
            for (var j = 0; j < 16; j += 4) {
                {
                    Output[j] = ((x[3 - (j / 4 | 0)] >>> 24 & 255) | 0);
                    Output[j + 1] = ((x[3 - (j / 4 | 0)] >>> 16 & 255) | 0);
                    Output[j + 2] = ((x[3 - (j / 4 | 0)] >>> 8 & 255) | 0);
                    Output[j + 3] = ((x[3 - (j / 4 | 0)] & 255) | 0);
                }
                ;
            }
            return Output
        };
        /*private*/ this.SM4KeyExt = function (CryptFlag) {
            var Key = this.key
            var rk = this.round_key
            var r;
            var mid;
            var x = [0, 0, 0, 0];
            var tmp = [0, 0, 0, 0];
            for (var i = 0; i < 4; i++) {
                {
                    tmp[0] = Key[0 + 4 * i] & 255;
                    tmp[1] = Key[1 + 4 * i] & 255;
                    tmp[2] = Key[2 + 4 * i] & 255;
                    tmp[3] = Key[3 + 4 * i] & 255;
                    x[i] = tmp[0] << 24 | tmp[1] << 16 | tmp[2] << 8 | tmp[3];
                }
                ;
            }
            x[0] ^= -1548633402;
            x[1] ^= 1453994832;
            x[2] ^= 1736282519;
            x[3] ^= -1301273892;
            for (r = 0; r < 32; r += 4) {
                {
                    mid = x[1] ^ x[2] ^ x[3] ^ this.CK[r + 0];
                    mid = this.ByteSub(mid);
                    rk[r + 0] = x[0] ^= this.L2(mid);
                    mid = x[2] ^ x[3] ^ x[0] ^ this.CK[r + 1];
                    mid = this.ByteSub(mid);
                    rk[r + 1] = x[1] ^= this.L2(mid);
                    mid = x[3] ^ x[0] ^ x[1] ^ this.CK[r + 2];
                    mid = this.ByteSub(mid);
                    rk[r + 2] = x[2] ^= this.L2(mid);
                    mid = x[0] ^ x[1] ^ x[2] ^ this.CK[r + 3];
                    mid = this.ByteSub(mid);
                    rk[r + 3] = x[3] ^= this.L2(mid);
                }
                ;
            }
            if (CryptFlag === false) {
                for (r = 0; r < 16; r++) {
                    {
                        mid = rk[r];
                        rk[r] = rk[31 - r];
                        rk[31 - r] = mid;
                    }
                    ;
                }
            }
        };

        /**
         *
         * If IV is not set, runs in ECB mode.
         * If IV was set, runs in CBC mode.
         *
         * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
         * @param {Number} padd - ```Number```
         * @returns ```Buffer``` or ```Uint8Array```
         */
        this.encrypt = function (data_in, padd) {
            if(!isBufferOrUint8Array(data_in)){
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
                if (isBuffer(data_in)) {
                    var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xff);
                    data = Buffer.concat([data_in, paddbuffer]);
                } else {
                    data = extendUint8Array(data_in, data.length + to_padd, padd_value);
                }
            }

            this.round_key = new Uint32Array(this.ROUND);
            this.SM4KeyExt(false);

            for (let index = 0; index < data.length / block_size; index++) {
                var block = data.subarray((index * block_size), (index + 1) * block_size);
                if (this.iv_set == true) {
                    block = xor(block, this.iv);
                }
                const return_block = this.SM4Crypt(block);
                if (this.iv_set == true) {
                    this.iv = return_block;
                }
                return_buff.push(return_block);
            }
            var final_buffer = return_buff;
            if (isBuffer(data_in)) {
                final_buffer = Buffer.concat(return_buff);
            } else {
                final_buffer = concatenateUint8Arrays(return_buff);
            }
            this.iv_set = false
            return final_buffer;
        };
        /**
         *
         * If IV is not set, runs in ECB mode.
         * If IV was set, runs in CBC mode.
         *
         * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
         * @returns ```Buffer``` or ```Uint8Array```
         */
        this.decrypt = function (data_in) {
            if(!isBufferOrUint8Array(data_in)){
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
                if (isBuffer(data_in)) {
                    var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                    data = Buffer.concat([data_in, paddbuffer]);
                } else {
                    data = extendUint8Array(data_in, data.length + to_padd, padd_value);
                }
            }

            this.round_key = new Uint32Array(this.ROUND);
            this.SM4KeyExt(true);

            for (let index = 0; index < data.length / block_size; index++) {
                var block = data.subarray((index * block_size), (index + 1) * block_size);
                if (this.iv_set == true) {
                    if (this.previous_block != undefined) {
                        this.iv = this.previous_block;
                    }
                }
                this.previous_block = block;

                var return_block = this.SM4Crypt(block);

                if (this.iv_set == true) {
                    return_block = xor(return_block, this.iv);
                }
                return_buff.push(return_block);
            }
            var final_buffer = return_buff;
            if (isBuffer(data_in)) {
                final_buffer = Buffer.concat(return_buff);
            } else {
                final_buffer = concatenateUint8Arrays(return_buff);
            }
            this.iv_set = false
            return final_buffer;
        };
    }
}

module.exports = SM4

