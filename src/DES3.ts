function isBufferOrUint8Array(obj: any): boolean {
    return obj instanceof Uint8Array || (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}

function isBuffer(obj: any): boolean {
    return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}

function extendUint8Array(array: Uint8Array, newLength: number, padValue: number): Uint8Array {
    const newArray = new Uint8Array(newLength);
    newArray.set(array);

    for (let i = array.length; i < newLength; i++) {
        newArray[i] = padValue;
    }

    return newArray;
}

function concatenateUint8Arrays(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((length, array) => length + array.length, 0);
    const concatenatedArray = new Uint8Array(totalLength);
    let offset = 0;

    for (let i = 0; i < arrays.length; i++) {
        concatenatedArray.set(arrays[i], offset);
        offset += arrays[i].length;
    }

    return concatenatedArray;
}

function xor(buf1: Uint8Array | Buffer, buf2: Uint8Array | Buffer): Uint8Array | Buffer {
    let number = -1
    const bufResult = buf1.map((b) => {
        if (number != buf2.length - 1) {
            number = number + 1
        } else {
            number = 0
        }
        return b ^ buf2[number]
    });
    return bufResult;
}

function align(a: number, n: number): number {
    var a = a % n;
    if (a) {
        return (n - a);
    } else {
        return 0;
    }
}

function removePKCSPadding(buffer: Uint8Array | Buffer, blockSize: number, number?: number): Uint8Array | Buffer {
    if (buffer.length % blockSize !== 0) {
        return buffer;
    }

    const lastByte = buffer[buffer.length - 1];
    const paddingSize = lastByte;

    // if number supplied padding number
    if (number != undefined) {
        if (lastByte != number) {
            return buffer;
        } else {
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

    } else {

        for (let i = buffer.length - 1; i >= buffer.length - paddingSize; i--) {
            if (buffer[i] !== paddingSize) {
                return buffer;
            }
        }

        return buffer.subarray(0, buffer.length - paddingSize);
    }
}

/**
 * DES3 encryption.
 * 
 * Key must be 8 bytes, 8 byte IV
 * 
 * Example:
 * ```
 * const cipher = new DES3();
 * // Key for browser
 * const encoder_key = new TextEncoder();
 * const key = encoder_key.encode("01234567");
 * cipher.set_key(key)
 * // Key for node
 * const key = Buffer.from("01234567");
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
export class DES3{
    public key:any;
    public key_set:boolean = false;
    public iv:any;
    public iv_set:boolean = false;
    
    private previous_block:any;

    constructor() {
    }

    private ROUNDS = 16;
    private KEY_LENGTH = 8;
    private sKey = new Uint32Array(32);
    private INTERNAL_KEY_LENGTH = this.ROUNDS * 2;
    private SKB = new Uint32Array(8 * 64);
    private SP_TRANS = new Uint32Array(8 * 64);

    private s(c:any):number{
        return (c.charCodeAt == null ? c : c.charCodeAt(0))
    }

    private __static_initializer_0():void {
        var cd = "D]PKESYM`UBJ\\@RXA`I[T`HC`LZQ\\PB]TL`[C`JQ@Y`HSXDUIZRAM`EK";
        var j:number;
        var s:number;
        var bit:number;
        var count = 0;
        var offset = 0;
        for (var i = 0; i < cd.length; i++) {
            {
                s = this.s(cd.charAt(i)) - '@'.charCodeAt(0);
                if (s !== 32) {
                    bit = 1 << count++;
                    for (j = 0; j < 64; j++) {
                        if ((bit & j) !== 0)
                            this.SKB[offset + j] |= 1 << s;
                        ;
                    }
                    if (count === 6) {
                        offset += 64;
                        count = 0;
                    }
                }
            }
            ;
        }
        var spt = "g3H821:80:H03BA0@N1290BAA88::3112aIH8:8282@0@AH0:1W3A8P810@22;22A18^@9H9@129:<8@822`?:@0@8PH2H81A19:G1@03403A0B1;:0@1g192:@919AA0A109:W21492H@0051919811:215011139883942N8::3112A2:31981jM118::A101@I88:1aN0<@030128:X;811`920:;H0310D1033@W980:8A4@804A3803o1A2021B2:@1AH023GA:8:@81@@12092B:098042P@:0:A0HA9>1;289:@1804:40Ph=1:H0I0HP0408024bC9P8@I808A;@0@0PnH0::8:19J@818:@iF0398:8A9H0<13@001@11<8;@82B01P0a2989B:0AY0912889bD0A1@B1A0A0AB033O91182440A9P8@I80n@1I03@1J828212A`A8:12B1@19A9@9@8^B:0@H00<82AB030bB840821Q:8310A302102::A1::20A1;8";
        offset = 0;
        var k:number;
        var c:number;
        var param:number;
        for (var i = 0; i < 32; i++) {
            {
                k = -1;
                bit = 1 << i;
                for (j = 0; j < 32; j++) {
                    {
                        c = this.s(spt.charAt(offset >> 1)) - '0'.charCodeAt(0) >> (offset & 1) * 3 & 7
                        offset++;
                        if (c < 5) {
                            k += c + 1;
                            this.SP_TRANS[k] |= bit;
                            continue;
                        }
                        param = this.s(spt.charAt(offset >> 1)) - '0'.charCodeAt(0) >> (offset & 1) * 3 & 7;
                        offset++;
                        if (c === 5) {
                            k += param + 6;
                            this.SP_TRANS[k] |= bit;
                        }
                        else if (c === 6) {
                            k += (param << 6) + 1;
                            this.SP_TRANS[k] |= bit;
                        }
                        else {
                            k += param << 6;
                            j--;
                        }
                    }
                    ;
                }
            }
            ;
        }
    };

    /**
     * Key for encryption.
     *
     * Key must be 8 bytes!
     * 
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     */
    set_key(key:Buffer|Uint8Array):void {
        if (!isBufferOrUint8Array(key)) {
            throw Error("key must be Buffer or Uint8Array");
        }
        var userkey = key;
        if (userkey == null){
            throw new Error("Null user key");
        }
        if (userkey.length !== this.KEY_LENGTH){
            throw new Error("key must be 8 bytes");
        }

        this.__static_initializer_0();

        var i = 0;
        var c = (userkey[i++] & 255) | (userkey[i++] & 255) << 8 | (userkey[i++] & 255) << 16 | (userkey[i++] & 255) << 24;
        var d = (userkey[i++] & 255) | (userkey[i++] & 255) << 8 | (userkey[i++] & 255) << 16 | (userkey[i++] & 255) << 24;
        var t = ((d >>> 4) ^ c) & 252645135;
        c ^= t;
        d ^= t << 4;
        t = ((c << 18) ^ c) & -859045888;
        c ^= t ^ t >>> 18;
        t = ((d << 18) ^ d) & -859045888;
        d ^= t ^ t >>> 18;
        t = ((d >>> 1) ^ c) & 1431655765;
        c ^= t;
        d ^= t << 1;
        t = ((c >>> 8) ^ d) & 16711935;
        d ^= t;
        c ^= t << 8;
        t = ((d >>> 1) ^ c) & 1431655765;
        c ^= t;
        d ^= t << 1;
        d = (d & 255) << 16 | (d & 65280) | (d & 16711680) >>> 16 | (c & -268435456) >>> 4;
        c &= 268435455;
        var s;
        var j = 0;
        for (i = 0; i < this.ROUNDS; i++) {
            {
                if ((32508 >> i & 1) === 1) {
                    c = (c >>> 2 | c << 26) & 268435455;
                    d = (d >>> 2 | d << 26) & 268435455;
                }
                else {
                    c = (c >>> 1 | c << 27) & 268435455;
                    d = (d >>> 1 | d << 27) & 268435455;
                }
                s = this.SKB[c & 63] | this.SKB[64 | (((c >>> 6) & 3) | ((c >>> 7) & 60))] | this.SKB[128 | (((c >>> 13) & 15) | ((c >>> 14) & 48))] | this.SKB[192 | (((c >>> 20) & 1) | ((c >>> 21) & 6) | ((c >>> 22) & 56))];
                t = this.SKB[256 | (d & 63)] | this.SKB[320 | (((d >>> 7) & 3) | ((d >>> 8) & 60))] | this.SKB[384 | ((d >>> 15) & 63)] | this.SKB[448 | (((d >>> 21) & 15) | ((d >>> 22) & 48))];
                this.sKey[j++] = t << 16 | (s & 65535);
                s = s >>> 16 | (t & -65536);
                this.sKey[j++] = s << 4 | s >>> 28;
            }
            ;
        }
        this.key_set = true
    };

    /**
     * IV for CBC encryption.
     *
     * Must be 8 bytes!
     * 
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv (iv:Buffer|Uint8Array):void {
        if (iv) {
            if (!isBufferOrUint8Array(iv)) {
                throw Error("IV must be a buffer or UInt8Array");
            } else {
                if (iv.length != 8) {
                    throw Error("Enter a vaild 8 byte IV for CBC mode");
                } else {
                    this.iv = iv;
                    this.iv_set = true;
                }
            }
        } else {
            throw Error("Enter a vaild 8 byte IV for CBC mode");
        }
    };

    private initialPermutation (io:number[]):void {
        var L = io[0];
        var R = io[1];
        var t = ((R >>> 4) ^ L) & 252645135;
        L ^= t;
        R ^= t << 4;
        t = ((L >>> 16) ^ R) & 65535;
        R ^= t;
        L ^= t << 16;
        t = ((R >>> 2) ^ L) & 858993459;
        L ^= t;
        R ^= t << 2;
        t = ((L >>> 8) ^ R) & 16711935;
        R ^= t;
        L ^= t << 8;
        t = ((R >>> 1) ^ L) & 1431655765;
        io[0] = L ^ t;
        io[1] = R ^ (t << 1);
    };

    private run_block (block:Buffer|Uint8Array, encrypt:boolean):Buffer|Uint8Array {
        var __in = block
        var out = new Uint8Array(8);
        var outOffset = 0;
        var inOffset = 0;
        var lr = [(__in[inOffset++] & 255) | (__in[inOffset++] & 255) << 8 | (__in[inOffset++] & 255) << 16 | (__in[inOffset++] & 255) << 24, (__in[inOffset++] & 255) | (__in[inOffset++] & 255) << 8 | (__in[inOffset++] & 255) << 16 | (__in[inOffset] & 255) << 24];
        this.initialPermutation(lr);
        if (encrypt){
            this.encrypt_base(lr);
        } else {
            this.decrypt_base(lr);
        }
        this.finalPermutation(lr);
        var R = lr[0];
        var L = lr[1];
        out[outOffset++] = (L | 0);
        out[outOffset++] = ((L >> 8) | 0);
        out[outOffset++] = ((L >> 16) | 0);
        out[outOffset++] = ((L >> 24) | 0);
        out[outOffset++] = (R | 0);
        out[outOffset++] = ((R >> 8) | 0);
        out[outOffset++] = ((R >> 16) | 0);
        out[outOffset] = ((R >> 24) | 0);
        if(isBuffer(block)){
            out = Buffer.from(out)
        }
        return out;
    };

    private encrypt_base (io:number[]):void {
        var L = io[0];
        var R = io[1];
        var u = R << 1 | R >>> 31;
        R = L << 1 | L >>> 31;
        L = u;
        var t:number;
        for (var i = 0; i < this.INTERNAL_KEY_LENGTH;) {
            {
                u = R ^ this.sKey[i++];
                t = R ^ this.sKey[i++];
                t = t >>> 4 | t << 28;
                L ^= (this.SP_TRANS[64 | (t & 63)] | this.SP_TRANS[192 | ((t >>> 8) & 63)] | this.SP_TRANS[320 | ((t >>> 16) & 63)] | this.SP_TRANS[448 | ((t >>> 24) & 63)] | this.SP_TRANS[u & 63] | this.SP_TRANS[128 | ((u >>> 8) & 63)] | this.SP_TRANS[256 | ((u >>> 16) & 63)] | this.SP_TRANS[384 | ((u >>> 24) & 63)]);
                u = L ^ this.sKey[i++];
                t = L ^ this.sKey[i++];
                t = t >>> 4 | t << 28;
                R ^= (this.SP_TRANS[64 | (t & 63)] | this.SP_TRANS[192 | ((t >>> 8) & 63)] | this.SP_TRANS[320 | ((t >>> 16) & 63)] | this.SP_TRANS[448 | ((t >>> 24) & 63)] | this.SP_TRANS[u & 63] | this.SP_TRANS[128 | ((u >>> 8) & 63)] | this.SP_TRANS[256 | ((u >>> 16) & 63)] | this.SP_TRANS[384 | ((u >>> 24) & 63)]);
            }
            ;
        }
        io[0] = R >>> 1 | R << 31;
        io[1] = L >>> 1 | L << 31;
    };

    private decrypt_base(io:number[]):void {
        var L = io[0];
        var R = io[1];
        var u = R << 1 | R >>> 31;
        R = L << 1 | L >>> 31;
        L = u;
        var t:number;
        for (var i = this.INTERNAL_KEY_LENGTH - 1; i > 0;) {
            {
                t = R ^ this.sKey[i--];
                u = R ^ this.sKey[i--];
                t = t >>> 4 | t << 28;
                L ^= (this.SP_TRANS[64 | (t & 63)] | this.SP_TRANS[192 | ((t >>> 8) & 63)] | this.SP_TRANS[320 | ((t >>> 16) & 63)] | this.SP_TRANS[448 | ((t >>> 24) & 63)] | this.SP_TRANS[u & 63] | this.SP_TRANS[128 | ((u >>> 8) & 63)] | this.SP_TRANS[256 | ((u >>> 16) & 63)] | this.SP_TRANS[384 | ((u >>> 24) & 63)]);
                t = L ^ this.sKey[i--];
                u = L ^ this.sKey[i--];
                t = t >>> 4 | t << 28;
                R ^= (this.SP_TRANS[64 | (t & 63)] | this.SP_TRANS[192 | ((t >>> 8) & 63)] | this.SP_TRANS[320 | ((t >>> 16) & 63)] | this.SP_TRANS[448 | ((t >>> 24) & 63)] | this.SP_TRANS[u & 63] | this.SP_TRANS[128 | ((u >>> 8) & 63)] | this.SP_TRANS[256 | ((u >>> 16) & 63)] | this.SP_TRANS[384 | ((u >>> 24) & 63)]);
            }
            ;
        }
        io[0] = R >>> 1 | R << 31;
        io[1] = L >>> 1 | L << 31;
    };

    private finalPermutation(io:number[]):void {
        var L = io[1];
        var R = io[0];
        var t = (R >>> 1 ^ L) & 1431655765;
        L ^= t;
        R ^= t << 1;
        t = (L >>> 8 ^ R) & 16711935;
        R ^= t;
        L ^= t << 8;
        t = (R >>> 2 ^ L) & 858993459;
        L ^= t;
        R ^= t << 2;
        t = (L >>> 16 ^ R) & 65535;
        R ^= t;
        L ^= t << 16;
        t = (R >>> 4 ^ L) & 252645135;
        io[1] = L ^ t;
        io[0] = R ^ (t << 4);
    };

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
    encrypt(data_in:Buffer|Uint8Array, padding?:number):Buffer|Uint8Array {
        if(!isBufferOrUint8Array(data_in)){
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 8;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padding;
        const return_buff:any[]  = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padd_value == undefined) {
                padd_value = align(data.length, block_size);
            }
            if (isBuffer(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xff);
                data = Buffer.concat([data_in as Buffer, paddbuffer]);
            } else {
                data = extendUint8Array(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0; index < data.length / block_size; index++) {
            var block = data.subarray((index * block_size), (index + 1) * block_size);
            if (this.iv_set == true) {
                block = xor(block, this.iv);
            }
            const return_block = this.run_block(block, true);

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
    decrypt(data_in:Buffer|Uint8Array,remove_padding?:boolean|number):Buffer|Uint8Array {
        if(!isBufferOrUint8Array(data_in)){
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 8;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value:number;
        if(remove_padding == undefined){
            padd_value = 0xff;
        } else if(typeof remove_padding == 'number'){
            padd_value = remove_padding & 0xFF;
        } else {
            padd_value = align(data.length, block_size);
        }
        const return_buff:any[] = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (isBuffer(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
                data = Buffer.concat([data_in as Buffer, paddbuffer]);
            } else {
                data = extendUint8Array(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            var block = data.subarray((index * block_size), (index + 1) * block_size);
            if (this.iv_set == true) {
                if (this.previous_block != undefined) {
                    this.iv = this.previous_block;
                }
            }
            this.previous_block = block;

            var return_block = this.run_block(block, false);

            if (this.iv_set == true) {
                return_block = xor(return_block, this.iv);
            }
            if(index == (amount-1)){
                if(remove_padding != undefined){
                    if(typeof remove_padding == 'number'){
                        return_block = removePKCSPadding(return_block,block_size,padd_value);
                    } else {
                        return_block = removePKCSPadding(return_block,block_size);
                    }
                }
                return_buff.push(return_block);
            } else {
                return_buff.push(return_block);
            }
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