import {
    isBuffer,
    isBufferOrUint8Array,
    extendUint8Array,
    concatenateUint8Arrays,
    xor,
} from './common'

/**
 * SM4 encryption.
 * 
 * 16 byte key, 16 byte IV
 * 
 * Example:
 * ```
 * const cipher = new SM4();
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
export class SM4 {
    public key:any;
    public key_set:boolean = false;
    public iv:any;
    public iv_set:boolean = false;

    private previous_block:any;

    private ROUND = 32;
    private round_key:any;

    constructor() {
    }
    
    private SBOX = new Uint8Array(
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

    private CK = new Uint32Array(
            [462357,      472066609,   943670861,   1415275113, 
                1886879365,  -1936483679, -1464879427, -993275175, 
                -521670923,  -66909679,   404694573,   876298825, 
                1347903077,  1819507329,  -2003855715, -1532251463, 
                -1060647211, -589042959,  -117504499,  337322537, 
                808926789,   1280531041,  1752135293,  -2071227751, 
                -1599623499, -1128019247, -656414995,  -184876535, 
                269950501,   741554753,   1213159005,  1684763257]
    );

    private Rotl(x:number, y:number):number {
        return x << y | x >>> (32 - y);
    };

    private ByteSub(A:number):number {
        return (this.SBOX[A >>> 24 & 255] & 255) << 24 | (this.SBOX[A >>> 16 & 255] & 255) << 16 | (this.SBOX[A >>> 8 & 255] & 255) << 8 | (this.SBOX[A & 255] & 255);
    };

    private L1(B:number):number {
        return B ^ this.Rotl(B, 2) ^ this.Rotl(B, 10) ^ this.Rotl(B, 18) ^ this.Rotl(B, 24);
    };

    private L2(B:number):number {
        return B ^ this.Rotl(B, 13) ^ this.Rotl(B, 23);
    };

    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     * 
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv (iv:Buffer|Uint8Array):void {
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
    set_key(key:Buffer|Uint8Array):void {
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

    private SM4Crypt(Input:Buffer|Uint8Array) {
        var rk = this.round_key
        var Output = new Uint8Array(16)
        var r:number;
        var mid:number;
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

    private SM4KeyExt (CryptFlag:boolean):void {
        var Key = this.key
        var rk = this.round_key
        var r:number;
        var mid:number;
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
    encrypt(data_in:Buffer|Uint8Array, padd:number):Buffer|Uint8Array {
        if(!isBufferOrUint8Array(data_in)){
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padd;
        const return_buff:any[] = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padd_value == undefined) {
                padd_value = 0xff;
            }
            if (isBuffer(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xff);
                data = Buffer.concat([data_in as Buffer, paddbuffer]);
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
        var final_buffer:Buffer|Uint8Array;
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
    decrypt(data_in:Buffer|Uint8Array):Buffer|Uint8Array {
        if(!isBufferOrUint8Array(data_in)){
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        const return_buff:any[] = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var padd_value = 0xff;
            if (isBuffer(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                data = Buffer.concat([data_in as Buffer, paddbuffer]);
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
        var final_buffer:Buffer|Uint8Array;
        if (isBuffer(data_in)) {
            final_buffer = Buffer.concat(return_buff);
        } else {
            final_buffer = concatenateUint8Arrays(return_buff);
        }
        this.iv_set = false
        return final_buffer;
    };
}