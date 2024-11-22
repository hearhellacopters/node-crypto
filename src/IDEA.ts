function writeUInt16BE(array: Uint8Array | Buffer, value: number, offset: number): void {
    array[offset] = (value >> 8) & 0xff;
    array[offset + 1] = value & 0xff;
}

const readUInt16BE = (array: Uint8Array | Buffer, index: number): number => {
    return (array[index] << 8) | array[index + 1];
}

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

function removePKCSPadding(buffer: Uint8Array | Buffer, number: number, PKCS: boolean | number = false): Uint8Array | Buffer {
    const lastByte = buffer[buffer.length - 1];
    if (PKCS == true) {
        return buffer.subarray(0, buffer.length - lastByte);
    } else 
    if (lastByte != number) {
        return buffer;
    } else {
        var len = buffer.length;
        for (let i = buffer.length - 1; i > 0; i--) {
            if (buffer[i] == number) {
                len--;
            }
        }
        return buffer.subarray(0, len);
    }
}

function rotl(a:number, b:number):number {
    return ((a >>> (32 - (b & 31))) | (a << (b & 31))) >>> 0
}

const ideaMul = function (a:number, b:number):number {
    let c:number;

    //Perform multiplication modulo 2^16 - 1
    c = (a * b) >>> 0;

    if (c != 0) {
        c = ((rotl(c, 16) - c) >> 16) + 1;
    } else {
        c = 1 - a - b;
    }

    //Return the result
    return c & 0xFFFF;
};

const ideaInv = function (a:number):number {
    let b:number, q:number, r:number;
    let t:number, u:number, v:number;

    b = 0x10001;
    u = 0;
    v = 1;

    while (a > 0) {
        q = (b / a) >>> 0;
        r = (b % a) >>> 0;

        b = a >>> 0;
        a = r;

        t = (v | 0) << 0;
        v = ((u - q * v) | 0) << 0;
        u = (t | 0) << 0;
    }

    if (u < 0) {
        u = ((u + 0x10001) | 0) << 0;
    }

    return u;
};

/**
 * IDEA encryption.
 * 
 * Key must be 16 bytes, 8 byte IV
 * 
 * Example:
 * ```
 * const cipher = new IDEA();
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
export class IDEA {
    public key:any;
    public key_set:boolean = false;
    public iv:any;
    public iv_set:boolean = false;
    
    private previous_block:any;
    private ek:any;
    private dk:any;
    private buffer:any;
    
    constructor() {
    }

    /**
     * Key for encryption.
     *
     * Key must be 16 bytes!
     * 
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     */
    set_key(key:Buffer|Uint8Array) {
        if (!isBufferOrUint8Array(key)) {
            throw Error("key must be Buffer or Uint8Array");
        }
        let key_len = key.length;
        if (key_len != 16) {
            throw Error("key must be 16 bytes");
        }

        const ek = new Uint16Array(52);
        for (let i = 0; i < 8; i++) {
            const element = readUInt16BE(key, i * 2);
            ek[i] = element;
        }
        for (let i = 8; i < 52; i++) {
            if ((i % 8) == 6) {
                ek[i] = (ek[i - 7] << 9) | (ek[i - 14] >> 7);
            }
            else if ((i % 8) == 7) {
                ek[i] = (ek[i - 15] << 9) | (ek[i - 14] >> 7);
            }
            else {
                ek[i] = (ek[i - 7] << 9) | (ek[i - 6] >> 7);
            }
        }
        const dk = new Uint16Array(52);

        let i:number;
        for (i = 0; i < 52; i += 6) {
            dk[i] = ideaInv(ek[48 - i]);

            if (i == 0 || i == 48) {
                dk[i + 1] = -ek[49 - i];
                dk[i + 2] = -ek[50 - i];
            }
            else {
                dk[i + 1] = -ek[50 - i];
                dk[i + 2] = -ek[49 - i];
            }

            dk[i + 3] = ideaInv(ek[51 - i]);

            if (i < 48) {
                dk[i + 4] = ek[46 - i];
                dk[i + 5] = ek[47 - i];
            }
        }

        this.ek = ek;
        this.dk = dk;
        this.buffer = new Uint8Array(208);
        for (let i = 0; i < 52; i++) {
            this.buffer.writeUint16LE(ek[i], i * 2);
            this.buffer.writeUint16LE(dk[i], 104 + (i * 2));
        }
        this.key_set = true
    };

    private encrypt_block (block:Buffer|Uint8Array):Buffer|Uint8Array {
        //check if IV is set, if so runs CBC
        let start_chunk = block;
        if (this.iv_set == true) {
            start_chunk = xor(block, this.iv);
        }

        let a = readUInt16BE(start_chunk, 0);
        let b = readUInt16BE(start_chunk, 2);
        let c = readUInt16BE(start_chunk, 4);
        let d = readUInt16BE(start_chunk, 6);

        //The process consists of eight identical encryption steps
        let loc = 0;
        let i:number, e:number, f:number;
        for (i = 0; i < 8; i++) {
            //Apply a round
            a = ideaMul(a, this.ek[loc + 0]);
            b = (b + this.ek[loc + 1]) & 0xFFFF;
            c = (c + this.ek[loc + 2]) & 0xFFFF;
            d = ideaMul(d, this.ek[loc + 3]);

            e = (a ^ c) & 0xFFFF;
            f = (b ^ d) & 0xFFFF;

            e = ideaMul(e, this.ek[loc + 4]);
            f = (f + e) & 0xFFFF;
            f = ideaMul(f, this.ek[loc + 5]);
            e = (e + f) & 0xFFFF;

            a = (a ^ f) & 0xFFFF;
            d = (d ^ e) & 0xFFFF;
            e = (e ^ b) & 0xFFFF;
            f = (f ^ c) & 0xFFFF;

            b = f;
            c = e;

            //Advance current location in key schedule
            loc += 6;
        }

        //The four 16-bit values produced at the end of the 8th encryption
        //round are combined with the last four of the 52 key sub-blocks
        a = ideaMul(a, this.ek[loc + 0]);
        c = (c + this.ek[loc + 1]) & 0xFFFF;
        b = (b + this.ek[loc + 2]) & 0xFFFF;
        d = ideaMul(d, this.ek[loc + 3]);


        let out_blk:Uint8Array|Buffer;
        if (isBuffer(block)) {
            out_blk = Buffer.alloc(8);
        } else {
            out_blk = new Uint8Array(8);
        } 
        writeUInt16BE(out_blk, a, 0);
        writeUInt16BE(out_blk, c, 2);
        writeUInt16BE(out_blk, b, 4);
        writeUInt16BE(out_blk, d, 6);

        if (this.iv_set == true) {
            this.iv = out_blk;
        }
        return out_blk;
    };

    private decrypt_block (block:Uint8Array|Buffer):Uint8Array|Buffer {
        let start_chunk = block;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = start_chunk;

        let a = readUInt16BE(start_chunk,0);
        let b = readUInt16BE(start_chunk,2);
        let c = readUInt16BE(start_chunk,4);
        let d = readUInt16BE(start_chunk,6);

        //The computational process used for decryption of the ciphertext is
        //essentially the same as that used for encryption of the plaintext
        let loc = 0;
        let i:number, e:number, f:number;
        for (i = 0; i < 8; i++) {
            //Apply a round
            a = ideaMul(a, this.dk[loc + 0]);
            b = (b + this.dk[loc + 1]) & 0xFFFF;
            c = (c + this.dk[loc + 2]) & 0xFFFF;
            d = ideaMul(d, this.dk[loc + 3]);

            e = (a ^ c) & 0xFFFF;
            f = (b ^ d) & 0xFFFF;

            e = ideaMul(e, this.dk[loc + 4]);
            f = (f + e) & 0xFFFF;
            f = ideaMul(f, this.dk[loc + 5]);
            e = (e + f) & 0xFFFF;

            a = (a ^ f) & 0xFFFF;
            d = (d ^ e) & 0xFFFF;
            e = (e ^ b) & 0xFFFF;
            f = (f ^ c) & 0xFFFF;

            b = f;
            c = e;

            //Advance current location in key schedule
            loc += 6;
        }

        //The four 16-bit values produced at the end of the 8th encryption
        //round are combined with the last four of the 52 key sub-blocks
        a = ideaMul(a, this.dk[loc + 0]);
        c = (c + this.dk[loc + 1]) & 0xFFFF;
        b = (b + this.dk[loc + 2]) & 0xFFFF;
        d = ideaMul(d, this.dk[loc + 3]);

        let out_blk:Uint8Array|Buffer;
        if (isBuffer(block)) {
            out_blk = Buffer.alloc(8);
        } else {
            out_blk = new Uint8Array(8);
        } 
        writeUInt16BE(out_blk, a, 0);
        writeUInt16BE(out_blk, c, 2);
        writeUInt16BE(out_blk, b, 4);
        writeUInt16BE(out_blk, d, 6);
        var return_buffer = out_blk;
        if (this.iv_set == true) {
            return_buffer = xor(out_blk, this.iv);
        }
        return return_buffer;
    };

    /**
     * IV for CBC encryption.
     *
     * Must be 8 bytes!
     * 
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv:Buffer|Uint8Array):void {
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

    /**
     * If IV is not set, runs in ECB mode.
     * 
     * If IV was set, runs in CBC mode.
     * 
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @param {number} padding - ```number``` defaults to 0 for PKCS or can use a value
     * @returns ```Buffer``` or ```Uint8Array```
     */
    encrypt(data_in:Buffer|Uint8Array, padding:number = 0):Buffer|Uint8Array {
        if(!isBufferOrUint8Array(data_in)){
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 8;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padding;
        const return_buff:any[] = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padding == 0) {
                padd_value = to_padd;
            }
            if (isBuffer(data_in)) {
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xff);
                data = Buffer.concat([data_in as Buffer, paddbuffer]);
            } else {
                data = extendUint8Array(data_in, data.length + to_padd, padd_value);
            }
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
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
    decrypt (data_in:Buffer|Uint8Array,remove_padding:boolean|number = false):Buffer|Uint8Array {
        if(!isBufferOrUint8Array(data_in)){
            throw Error("Data must be Buffer or Uint8Array");
        }
        const block_size = 8;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = align(data.length, block_size);
        if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
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
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            var return_block = this.decrypt_block(block);
            if ((remove_padding != false ) && (index == (amount - 1))) {
                return_block = removePKCSPadding(return_block, padd_value, remove_padding);
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