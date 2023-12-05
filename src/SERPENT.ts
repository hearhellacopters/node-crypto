import {
    isBuffer,
    isBufferOrUint8Array,
    extendUint8Array,
    concatenateUint8Arrays,
    xor,
    writeUInt32LE,
    readUInt32LE,
    rotl,
    rotr
} from './common'

/**
 * Serpent encryption.
 * 
 * 16, 24 or 32 bytes key, 16 byte IV
 * 
 * Example:
 * ```
 * const cipher = new SERPENT();
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
export class SERPENT {

    public key:any;
    public key_set:boolean = false;
    public iv:any;
    public iv_set:boolean = false;

    private previous_block:any;

    private r0:any;
    private r1:any;
    private r2:any;
    private r3:any;
    private r4:any;
    private buffer:any;
    constructor() {
    }

    private SBOX0 (a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }
        this.r4 = 0;

        this.r3 ^= this.r0 >>> 0;
        this.r4 = this.r1 >>> 0;
        this.r1 &= this.r3 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r4 = this.r4 >>> 0;
        this.r1 ^= this.r0 >>> 0;
        this.r0 |= this.r3 >>> 0;
        this.r0 ^= this.r4 >>> 0;
        this.r4 ^= this.r3 >>> 0;
        this.r3 ^= this.r2 >>> 0;
        this.r2 |= this.r1 >>> 0;
        this.r2 ^= this.r4 >>> 0;
        this.r4 = ~this.r4 >>> 0;
        this.r4 |= this.r1 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r1 ^= this.r4 >>> 0;
        this.r3 |= this.r0 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r4 ^= this.r3 >>> 0;
        this.r3 = this.r0 >>> 0;
        this.r0 = this.r1 >>> 0;
        this.r1 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    private SBOX1(a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }

        this.r4 = 0;
        this.r0 = ~this.r0 >>> 0;
        this.r2 = ~this.r2 >>> 0;
        this.r4 = this.r0 >>> 0;
        this.r0 &= this.r1 >>> 0;
        this.r2 ^= this.r0 >>> 0;
        this.r0 |= this.r3 >>> 0;
        this.r3 ^= this.r2 >>> 0;
        this.r1 ^= this.r0 >>> 0;
        this.r0 ^= this.r4 >>> 0;
        this.r4 |= this.r1 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r2 |= this.r0 >>> 0;
        this.r2 &= this.r4 >>> 0;
        this.r0 ^= this.r1 >>> 0;
        this.r1 &= this.r2 >>> 0;
        this.r1 ^= this.r0 >>> 0;
        this.r0 &= this.r2 >>> 0;
        this.r0 ^= this.r4 >>> 0;
        this.r4 = this.r0 >>> 0;
        this.r0 = this.r2 >>> 0;
        this.r2 = this.r3 >>> 0;
        this.r3 = this.r1 >>> 0;
        this.r1 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    private SBOX2 (a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }

        this.r4 = 0;
        this.r4 = this.r0 >>> 0;
        this.r0 &= this.r2 >>> 0;
        this.r0 ^= this.r3 >>> 0;
        this.r2 ^= this.r1 >>> 0;
        this.r2 ^= this.r0 >>> 0;
        this.r3 |= this.r4 >>> 0;
        this.r3 ^= this.r1 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r1 = this.r3 >>> 0;
        this.r3 |= this.r4 >>> 0;
        this.r3 ^= this.r0 >>> 0;
        this.r0 &= this.r1 >>> 0;
        this.r4 ^= this.r0 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r1 ^= this.r4 >>> 0;
        this.r4 = ~this.r4 >>> 0;
        this.r0 = this.r2 >>> 0;
        this.r2 = this.r1 >>> 0;
        this.r1 = this.r3 >>> 0;
        this.r3 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    private SBOX3 (a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }
        this.r4 = 0;

        this.r4 = this.r0 >>> 0;
        this.r0 |= this.r3 >>> 0;
        this.r3 ^= this.r1 >>> 0;
        this.r1 &= this.r4 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r2 ^= this.r3 >>> 0;
        this.r3 &= this.r0 >>> 0;
        this.r4 |= this.r1 >>> 0;
        this.r3 ^= this.r4 >>> 0;
        this.r0 ^= this.r1 >>> 0;
        this.r4 &= this.r0 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r1 |= this.r0 >>> 0;
        this.r1 ^= this.r2 >>> 0;
        this.r0 ^= this.r3 >>> 0;
        this.r2 = this.r1 >>> 0;
        this.r1 |= this.r3 >>> 0;
        this.r1 ^= this.r0 >>> 0;
        this.r0 = this.r1 >>> 0;
        this.r1 = this.r2 >>> 0;
        this.r2 = this.r3 >>> 0;
        this.r3 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    private SBOX4 (a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }
        this.r4 = 0;

        this.r1 ^= this.r3 >>> 0;
        this.r3 = ~this.r3 >>> 0;
        this.r2 ^= this.r3 >>> 0;
        this.r3 ^= this.r0 >>> 0;
        this.r4 = this.r1 >>> 0;
        this.r1 &= this.r3 >>> 0;
        this.r1 ^= this.r2 >>> 0;
        this.r4 ^= this.r3 >>> 0;
        this.r0 ^= this.r4 >>> 0;
        this.r2 &= this.r4 >>> 0;
        this.r2 ^= this.r0 >>> 0;
        this.r0 &= this.r1 >>> 0;
        this.r3 ^= this.r0 >>> 0;
        this.r4 |= this.r1 >>> 0;
        this.r4 ^= this.r0 >>> 0;
        this.r0 |= this.r3 >>> 0;
        this.r0 ^= this.r2 >>> 0;
        this.r2 &= this.r3 >>> 0;
        this.r0 = ~this.r0 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r2 = this.r0 >>> 0;
        this.r0 = this.r1 >>> 0;
        this.r1 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    private SBOX5 (a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }
        this.r4 = 0;

        this.r0 ^= this.r1 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r3 = ~this.r3 >>> 0;
        this.r4 = this.r1 >>> 0;
        this.r1 &= this.r0 >>> 0;
        this.r2 ^= this.r3 >>> 0;
        this.r1 ^= this.r2 >>> 0;
        this.r2 |= this.r4 >>> 0;
        this.r4 ^= this.r3 >>> 0;
        this.r3 &= this.r1 >>> 0;
        this.r3 ^= this.r0 >>> 0;
        this.r4 ^= this.r1 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r2 ^= this.r0 >>> 0;
        this.r0 &= this.r3 >>> 0;
        this.r2 = ~this.r2 >>> 0;
        this.r0 ^= this.r4 >>> 0;
        this.r4 |= this.r3 >>> 0;
        this.r2 ^= this.r4 >>> 0;
        this.r4 = this.r0 >>> 0;
        this.r0 = this.r1 >>> 0;
        this.r1 = this.r3 >>> 0;
        this.r3 = this.r2 >>> 0;
        this.r2 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    private SBOX6 (a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }
        this.r4 = 0;

        this.r2 = ~this.r2 >>> 0;
        this.r4 = this.r3 >>> 0;
        this.r3 &= this.r0 >>> 0;
        this.r0 ^= this.r4 >>> 0;
        this.r3 ^= this.r2 >>> 0;
        this.r2 |= this.r4 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r2 ^= this.r0 >>> 0;
        this.r0 |= this.r1 >>> 0;
        this.r2 ^= this.r1 >>> 0;
        this.r4 ^= this.r0 >>> 0;
        this.r0 |= this.r3 >>> 0;
        this.r0 ^= this.r2 >>> 0;
        this.r4 ^= this.r3 >>> 0;
        this.r4 ^= this.r0 >>> 0;
        this.r3 = ~this.r3 >>> 0;
        this.r2 &= this.r4 >>> 0;
        this.r2 ^= this.r3 >>> 0;
        this.r3 = this.r2 >>> 0;
        this.r2 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    private SBOX7 (a:number, b:number, c:number, d:number, usevalue?:boolean):void {
        if (!usevalue) {
            this.r0 = readUInt32LE(this.buffer, a);
            this.r1 = readUInt32LE(this.buffer, b);
            this.r2 = readUInt32LE(this.buffer, c);
            this.r3 = readUInt32LE(this.buffer, d);
        }
        this.r4 = 0;

        this.r4 = this.r1 >>> 0;
        this.r1 |= this.r2 >>> 0;
        this.r1 ^= this.r3 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r2 ^= this.r1 >>> 0;
        this.r3 |= this.r4 >>> 0;
        this.r3 &= this.r0 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r3 ^= this.r1 >>> 0;
        this.r1 |= this.r4 >>> 0;
        this.r1 ^= this.r0 >>> 0;
        this.r0 |= this.r4 >>> 0;
        this.r0 ^= this.r2 >>> 0;
        this.r1 ^= this.r4 >>> 0;
        this.r2 ^= this.r1 >>> 0;
        this.r1 &= this.r0 >>> 0;
        this.r1 ^= this.r4 >>> 0;
        this.r2 = ~this.r2 >>> 0;
        this.r2 |= this.r0 >>> 0;
        this.r4 ^= this.r2 >>> 0;
        this.r2 = this.r1 >>> 0;
        this.r1 = this.r3 >>> 0;
        this.r3 = this.r0 >>> 0;
        this.r0 = this.r4 >>> 0;

        if (!usevalue) {
            writeUInt32LE(this.buffer, this.r0 >>> 0, a);
            writeUInt32LE(this.buffer, this.r1 >>> 0, b);
            writeUInt32LE(this.buffer, this.r2 >>> 0, c);
            writeUInt32LE(this.buffer, this.r3 >>> 0, d);
        }
    };

    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     * 
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     */
    set_key (key:Buffer|Uint8Array):void {
        if (!isBufferOrUint8Array(key)) {
            throw Error("key must be Buffer or Uint8Array");
            }
        var keyLen = key.length;
        switch (keyLen) {
            case 16: 
                break;
            case 24:
                break;
            case 32:
                break;
            default:
                throw Error("Only key lengths of 16, 24 or 32 bytes allowed!");
        }
        keyLen = keyLen / 4;
        this.buffer = new Uint8Array(560);
        let i = 0;
        for (i; i < keyLen; i++) {
            const element = readUInt32LE(key, i * 4);
            writeUInt32LE(this.buffer, element, i * 4);
        }
        if (i < 8) {
            writeUInt32LE(this.buffer, 0x00000001, i * 4);
            i++;
        }
        while (i < 8) {
            writeUInt32LE(this.buffer, 0x0, i * 4);
            i++;
        }
        var key_loc = 0;
        var writer_pointer = 32;
        let k:number;
        for (k = 0; k != 132; ++k) {
            var int_1 = readUInt32LE(this.buffer, key_loc + (k * 4));
            var int_2 = readUInt32LE(this.buffer, key_loc + 12 + (k * 4));
            var int_3 = readUInt32LE(this.buffer, key_loc + 20 + (k * 4));
            var int_4 = readUInt32LE(this.buffer, key_loc + 28 + (k * 4));
            var value = rotl(k ^ int_1 ^ int_2 ^ int_3 ^ int_4 ^ 0x9E3779B9, 11);
            writeUInt32LE(this.buffer, value, writer_pointer + (k * 4));
        }

        for (i = 0; i < 128; i += 32) {
            this.SBOX3((i * 4) + (0 * 4) + 32, (i * 4) + (1 * 4) + 32, (i * 4) + (2 * 4) + 32, (i * 4) + (3 * 4) + 32);
            this.SBOX2((i * 4) + (4 * 4) + 32, (i * 4) + (5 * 4) + 32, (i * 4) + (6 * 4) + 32, (i * 4) + (7 * 4) + 32);
            this.SBOX1((i * 4) + (8 * 4) + 32, (i * 4) + (9 * 4) + 32, (i * 4) + (10 * 4) + 32, (i * 4) + (11 * 4) + 32);
            this.SBOX0((i * 4) + (12 * 4) + 32, (i * 4) + (13 * 4) + 32, (i * 4) + (14 * 4) + 32, (i * 4) + (15 * 4) + 32);
            this.SBOX7((i * 4) + (16 * 4) + 32, (i * 4) + (17 * 4) + 32, (i * 4) + (18 * 4) + 32, (i * 4) + (19 * 4) + 32);
            this.SBOX6((i * 4) + (20 * 4) + 32, (i * 4) + (21 * 4) + 32, (i * 4) + (22 * 4) + 32, (i * 4) + (23 * 4) + 32);
            this.SBOX5((i * 4) + (24 * 4) + 32, (i * 4) + (25 * 4) + 32, (i * 4) + (26 * 4) + 32, (i * 4) + (27 * 4) + 32);
            this.SBOX4((i * 4) + (28 * 4) + 32, (i * 4) + (29 * 4) + 32, (i * 4) + (30 * 4) + 32, (i * 4) + (31 * 4) + 32);
        }
        this.SBOX3(544, 548, 552, 556);
        this.key_set = true
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

    private encrypt_block (block:Buffer|Uint8Array):Buffer|Uint8Array {
        let start_chunk = block;
        if (this.iv_set == true) {
            start_chunk = xor(block, this.iv);
        }

        let t3 = 0; let t6 = 0; let t4 = 0; let v11 = 0; let v12 = 0; let x22 = 0; let v14 = 0; let x0 = 0;
        let x2 = 0; let x3 = 0; let x1 = 0; let x01 = 0; let x21 = 0; let v21 = 0; let v22 = 0; let v23 = 0;
        let v24 = 0; let v25 = 0; let v26 = 0; let v27 = 0; let v28 = 0; let v29 = 0; let v30 = 0; let v31 = 0;
        let v32 = 0; let v33 = 0; let v34 = 0; let v35 = 0; let v36 = 0; let v37 = 0; let v38 = 0; let v39 = 0;
        let v40 = 0; let v41 = 0; let v42 = 0; let v43 = 0; let v44 = 0; let v45 = 0; let v46 = 0; let v47 = 0;
        let v48 = 0; let v49 = 0; let v50 = 0; let v51 = 0; let v52 = 0; let v53 = 0; let v54 = 0; let v55 = 0;
        let v56 = 0; let v57 = 0; let v58 = 0; let v59 = 0; let v60 = 0; let v61 = 0; let v62 = 0; let v63 = 0;
        let v64 = 0; let v65 = 0; let v66 = 0; let v67 = 0; let v68 = 0; let v69 = 0; let v70 = 0; let v71 = 0;
        let v72 = 0; let v73 = 0; let v74 = 0; let v75 = 0; let v76 = 0; let v77 = 0; let v78 = 0; let v79 = 0;
        let v80 = 0; let v81 = 0; let v82 = 0; let v83 = 0; let v84 = 0; let v85 = 0; let v86 = 0; let v87 = 0;
        let v88 = 0; let v89 = 0; let v90 = 0; let v91 = 0; let v92 = 0; let v93 = 0; let v94 = 0; let v95 = 0;
        let v96 = 0; let v97 = 0; let v98 = 0; let v99 = 0; let v100 = 0; let v101 = 0; let v102 = 0; let v103 = 0;
        let v104 = 0; let v105 = 0; let v106 = 0; let v107 = 0; let v108 = 0; let v109 = 0; let v110 = 0; let v111 = 0;
        let v112 = 0; let v113 = 0; let v114 = 0; let v115 = 0; let v116 = 0; let v117 = 0; let v118 = 0; let v119 = 0;
        let v120 = 0; let v121 = 0; let v122 = 0; let v123 = 0; let v124 = 0; let v125 = 0; let v126 = 0; let v127 = 0;
        let v128 = 0; let v129 = 0; let v130 = 0; let v131 = 0; let v132 = 0; let v133 = 0; let v134 = 0; let v135 = 0;
        let v136 = 0; let v137 = 0; let v138 = 0; let v139 = 0; let v140 = 0; let v141 = 0; let v142 = 0; let v143 = 0;
        let v144 = 0; let v145 = 0; let v146 = 0; let v147 = 0; let v148 = 0; let v149 = 0; let v150 = 0; let v151 = 0;
        let v152 = 0; let v153 = 0; let v154 = 0; let v155 = 0; let v156 = 0; let v157 = 0; let v158 = 0; let v159 = 0;
        let v160 = 0; let v161 = 0; let v162 = 0; let v163 = 0; let v164 = 0; let v165 = 0; let v166 = 0; let v167 = 0;
        let v168 = 0; let v169 = 0; let v170 = 0; let v171 = 0; let v172 = 0; let v173 = 0; let v174 = 0; let v175 = 0;
        let v176 = 0; let v177 = 0; let v178 = 0; let v179 = 0; let v180 = 0; let v181 = 0; let v182 = 0; let v183 = 0;
        let v184 = 0; let v185 = 0; let v186 = 0; let v187 = 0; let v188 = 0; let v189 = 0; let v190 = 0; let v191 = 0;
        let v192 = 0; let v193 = 0; let v194 = 0; let v195 = 0; let v196 = 0; let v197 = 0; let v198 = 0; let v199 = 0;
        let v200 = 0; let v201 = 0; let v202 = 0; let v203 = 0; let v204 = 0; let v205 = 0; let v206 = 0; let v207 = 0;
        let v208 = 0; let v209 = 0; let v210 = 0; let v211 = 0; let v212 = 0; let v213 = 0; let v214 = 0; let v215 = 0;
        let v216 = 0; let v217 = 0; let v218 = 0; let v219 = 0; let v220 = 0; let v221 = 0; let v222 = 0; let v223 = 0;
        let v224 = 0; let v225 = 0; let v226 = 0; let v227 = 0; let v228 = 0; let v229 = 0; let v230 = 0; let v231 = 0;
        let v232 = 0; let v233 = 0; let v234 = 0; let v235 = 0; let v236 = 0; let v237 = 0; let v238 = 0; let v239 = 0;
        let v240 = 0; let v241 = 0; let v242 = 0; let v243 = 0; let v244 = 0; let v245 = 0; let v246 = 0; let v247 = 0;
        let v248 = 0; let v249 = 0; let v250 = 0; let v251 = 0; let v252 = 0; let v253 = 0; let v254 = 0; let v255 = 0;
        let v256 = 0; let v257 = 0; let v258 = 0; let v259 = 0; let v260 = 0; let v261 = 0; let v262 = 0; let v263 = 0;
        let v264 = 0; let v265 = 0; let v266 = 0; let v267 = 0; let v268 = 0; let v269 = 0; let v270 = 0; let v271 = 0;
        let v272 = 0; let v273 = 0; let v274 = 0; let v275 = 0; let v276 = 0; let v277 = 0; let v278 = 0; let v279 = 0;
        let v280 = 0; let v281 = 0; let v282 = 0; let v283 = 0; let v284 = 0; let v285 = 0; let v286 = 0; let v287 = 0;
        let v288 = 0; let v289 = 0; let v290 = 0; let v291 = 0; let v292 = 0; let v293 = 0; let v294 = 0; let v295 = 0;
        let v296 = 0; let v297 = 0; let v298 = 0; let v299 = 0; let v300 = 0; let v301 = 0; let v302 = 0; let v303 = 0;
        let v304 = 0; let v305 = 0; let v306 = 0; let v307 = 0; let v308 = 0; let v309 = 0; let v310 = 0; let v311 = 0;
        let v312 = 0; let v313 = 0; let v314 = 0; let v315 = 0; let v316 = 0; let v317 = 0; let v318 = 0; let v319 = 0;
        let v320 = 0; let v321 = 0; let v322 = 0; let v323 = 0; let v324 = 0; let v325 = 0; let v326 = 0; let v327 = 0;
        let v328 = 0; let v329 = 0; let v330 = 0; let v331 = 0; let v332 = 0; let v333 = 0; let v334 = 0; let v335 = 0;
        let v336 = 0; let v337 = 0; let v338 = 0; let v339 = 0; let v340 = 0; let v341 = 0; let v342 = 0; let v343 = 0;
        let v344 = 0; let v345 = 0; let v346 = 0; let v347 = 0; let v348 = 0; let v349 = 0; let v350 = 0; let v351 = 0;
        let v352 = 0; let v353 = 0; let v354 = 0; let v355 = 0; let v356 = 0; let v357 = 0; let v358 = 0; let v359 = 0;
        let v360 = 0; let v361 = 0; let v362 = 0; let v363 = 0; let v364 = 0; let v365 = 0; let v366 = 0; let v367 = 0;
        let v368 = 0; let v369 = 0; let v370 = 0; let v371 = 0; let v372 = 0; let v373 = 0; let v374 = 0; let v375 = 0;
        let v376 = 0; let v377 = 0; let v378 = 0; let v379 = 0; let v380 = 0; let v381 = 0; let v382 = 0; let v383 = 0;
        let v384 = 0; let v385 = 0; let v386 = 0; let v387 = 0; let v388 = 0; let v389 = 0; let v390 = 0; let v391 = 0;
        let v392 = 0; let v393 = 0; let v394 = 0; let v395 = 0; let v396 = 0; let v397 = 0; let v398 = 0; let v399 = 0;
        let v400 = 0; let v401 = 0; let v402 = 0; let v403 = 0; let v404 = 0; let v405 = 0; let v406 = 0; let v407 = 0;
        let v408 = 0; let v409 = 0; let v410 = 0; let v411 = 0; let v412 = 0; let v413 = 0; let v414 = 0; let v415 = 0;
        let v416 = 0; let v417 = 0; let v418 = 0; let v419 = 0; let v420 = 0; let v421 = 0; let v422 = 0; let v423 = 0;
        let v424 = 0; let v425 = 0; let v426 = 0; let v427 = 0; let v428 = 0; let v429 = 0; let v430 = 0; let v431 = 0;
        let v432 = 0; let v433 = 0; let v434 = 0; let v435 = 0; let v436 = 0; let v437 = 0; let v438 = 0; let v439 = 0;
        let v440 = 0; let v441 = 0; let v442 = 0; let v443 = 0; let v444 = 0; let v445 = 0; let v446 = 0; let v447 = 0;
        let v448 = 0; let v449 = 0; let v450 = 0; let v451 = 0; let v452 = 0; let v453 = 0; let v454 = 0; let v455 = 0;
        let v456 = 0; let v457 = 0; let v458 = 0; let v459 = 0; let v460 = 0; let v461 = 0; let v462 = 0; let v463 = 0;
        let v464 = 0; let v465 = 0; let v466 = 0; let v467 = 0; let v468 = 0; let v469 = 0; let v470 = 0; let v471 = 0;
        let v472 = 0; let v473 = 0; let v474 = 0; let v475 = 0; let v476 = 0; let v477 = 0; let v478 = 0; let v479 = 0;
        let v480 = 0; let v481 = 0; let v482 = 0; let v483 = 0; let v484 = 0; let v485 = 0; let v486 = 0; let v487 = 0;
        let v488 = 0; let v489 = 0; let v490 = 0; let v491 = 0; let v492 = 0; let v493 = 0; let v494 = 0; let v495 = 0;
        let v496 = 0; let v497 = 0; let v498 = 0; let v499 = 0; let v500 = 0; let v501 = 0; let v502 = 0; let v503 = 0;
        let v504 = 0; let v505 = 0; let v506 = 0; let v507 = 0; let v508 = 0; let v509 = 0; let v510 = 0; let v511 = 0;
        let v512 = 0; let v513 = 0; let v514 = 0; let v515 = 0; let v516 = 0; let v517 = 0; let v518 = 0; let v519 = 0;
        let v520 = 0; let v521 = 0; let v522 = 0; let v523 = 0; let v524 = 0; let v525 = 0; let v526 = 0; let v527 = 0;
        let v528 = 0; let v529 = 0; let v530 = 0; let v531 = 0; let v532 = 0; let v533 = 0; let v534 = 0; let v535 = 0;
        let v536 = 0; let v537 = 0; let v538 = 0; let v539 = 0; let v540 = 0; let v541 = 0; let v542 = 0; let v543 = 0;
        let v544 = 0; let v545 = 0; let v546 = 0; let v547 = 0; let v548 = 0; let v549 = 0; let v550 = 0; let v551 = 0;
        let v552 = 0; let v553 = 0; let resu = 0; let v555 = 0; let v556 = 0; let v557 = 0; let v558 = 0; let v559 = 0;
        let v560 = 0; let v561 = 0; let v562 = 0; let v563 = 0; let v564 = 0; let v565 = 0; let v566 = 0; let v567 = 0;
        let v568 = 0;

        let a = readUInt32LE(start_chunk, 0) ^  readUInt32LE(this.buffer, 32);
        let b = readUInt32LE(start_chunk, 4) ^  readUInt32LE(this.buffer, 36);
        let c = readUInt32LE(start_chunk, 8) ^  readUInt32LE(this.buffer, 40);
        let d = readUInt32LE(start_chunk, 12) ^ readUInt32LE(this.buffer, 44);

        t3 = d ^ a ^ c;
        t6 = (d ^ a) & b;
        t4 = t3 ^ b;
        v11 = t4 ^ d & a;
        v12 = t6 ^ a;
        x22 = (v12 | c) ^ t4;
        v14 = v11 & (v12 ^ t3);
        x0 = rotl(v14 ^ ~v12, 13);
        x2 = rotl(x22, 3);
        x3 = rotl(x2 ^ (8 * x0) ^ v11, 7);
        x1 = rotl(v14 ^ ~(x2 ^ x0 ^ t3), 1);
        x01 = rotl(x3 ^ x0 ^ x1, 5);
        x21 = rotl(x3 ^ x2 ^ (x1 << 7), 22);
        v21 = readUInt32LE(this.buffer, (38 * 4) - 104) ^ x01;
        v22 = readUInt32LE(this.buffer, (39 * 4) - 104) ^ x1;
        v23 = v22 ^ v21;
        v24 = readUInt32LE(this.buffer, (41 * 4) - 104) ^ x3;
        v25 = v24 | ~(v22 ^ v21);
        v26 = readUInt32LE(this.buffer, (40 * 4) - 104) ^ x21 ^ (v21 | ~(v22 ^ v21));
        v27 = v26 ^ v24;
        v28 = v25 ^ v22;
        v29 = v23 ^ ~(v26 ^ v24);
        v30 = v29 ^ v28 & v26;
        v31 = v28 ^ v26;
        v32 = rotl(v29 & (v28 ^ v26) ^ v26, 13);
        v33 = rotl(v27, 3);
        v34 = v30 ^ v33 ^ (8 * v32);
        v35 = v30 ^ v33 ^ v32 ^ v31;
        v36 = rotl(v34, 7);
        v37 = rotl(v35, 1);
        v38 = rotl(v36 ^ v32 ^ v37, 5);
        v39 = rotl(v36 ^ v33 ^ (v37 << 7), 22);
        v40 = readUInt32LE(this.buffer, (42 * 4) - 104) ^ v38;
        v41 = readUInt32LE(this.buffer, (43 * 4) - 104) ^ v37;
        v42 = readUInt32LE(this.buffer, (45 * 4) - 104);
        v43 = readUInt32LE(this.buffer, (44 * 4) - 104) ^ v39;
        v44 = v42 ^ v36 ^ v41 ^ v43 & ~v40;
        v45 = v40 ^ ~v43;
        v46 = (v44 ^ v43) & v41;
        v47 = v46 ^ v45;
        v48 = (v46 | v42 ^ v36) & (v44 | v45) ^ v40;
        v49 = (v42 ^ ~v36) & ~v40;
        v50 = rotl(v44, 13);
        v51 = rotl(v48, 3);
        v52 = v47 ^ v51 ^ v41 ^ v50 ^ v49 ^ v48;
        v53 = rotl(v47 ^ v51 ^ (8 * v50), 7);
        v54 = rotl(v52, 1);
        v55 = v53 ^ v50 ^ v54;
        v56 = v53 ^ v51 ^ (v54 << 7);
        v57 = rotl(v55, 5);
        v58 = rotl(v56, 22);
        v59 = readUInt32LE(this.buffer, (46 * 4) - 104) ^ v57;
        v60 = readUInt32LE(this.buffer, (47 * 4) - 104) ^ v54;
        v61 = readUInt32LE(this.buffer, (48 * 4) - 104) ^ v58;
        v62 = readUInt32LE(this.buffer, (49 * 4) - 104) ^ v53;
        v63 = v61 ^ v59 ^ v62;
        v64 = v63 & v59 ^ v62;
        v65 = v64 & v60 ^ v63;
        v66 = v62 | v60;
        v67 = (v65 | v59) & v64;
        v68 = (v62 | v59) ^ v60;
        v69 = rotl((v63 & v59 ^ (v62 | v60)) & v61 ^ v68, 13);
        v70 = rotl(v65, 3);
        v71 = v67 ^ v70 ^ (8 * v69) ^ v68 ^ v65;
        v72 = v67 ^ v70 ^ v69 ^ v66;
        v73 = rotl(v71, 7);
        v74 = rotl(v72, 1);
        v75 = v73 ^ v69 ^ v74;
        v76 = v73 ^ v70 ^ (v74 << 7);
        v77 = rotl(v75, 5);
        v78 = rotl(v76, 22);
        v79 = readUInt32LE(this.buffer, (50 * 4) - 104) ^ v77;
        v80 = readUInt32LE(this.buffer, (51 * 4) - 104) ^ v74;
        v81 = readUInt32LE(this.buffer, (53 * 4) - 104) ^ v73;
        v82 = v81 ^ v79;
        v83 = readUInt32LE(this.buffer, (52 * 4) - 104) ^ v78 ^ (v81 ^ v79) & v81;
        v84 = v83 | v80;
        v85 = v83 ^ (v81 ^ v79 | ~v80);
        v86 = v80 ^ ~(v81 ^ v79);
        v87 = v85 & v79 ^ v84 & v86;
        v88 = v87 & v86;
        v89 = rotl(v85, 13);
        v90 = rotl(v87, 3);
        v91 = rotl(v90 ^ (8 * v89) ^ v82 ^ v84, 7);
        v92 = rotl(v89 ^ v79 ^ v90 ^ v83 ^ v88, 1);
        v93 = rotl(v91 ^ v89 ^ v92, 5);
        v94 = rotl(v91 ^ v90 ^ (v92 << 7), 22);
        v95 = readUInt32LE(this.buffer, (54 * 4) - 104) ^ v93;
        v96 = readUInt32LE(this.buffer, (55 * 4) - 104) ^ v92;
        v97 = readUInt32LE(this.buffer, (57 * 4) - 104) ^ v91;
        v98 = v95 ^ ~v94 ^ readUInt32LE(this.buffer, (56 * 4) - 104) ^ (v97 ^ v95 | v96 ^ v95);
        v99 = v98 & v97;
        v100 = v98 ^ v96 ^ v95 ^ v98 & v97;
        v101 = v98 & v97 | v96 ^ v95;
        v102 = (v98 | ~v95) ^ v97 ^ v95;
        v103 = v101 ^ v102;
        v104 = v100 & v102;
        v105 = rotl(v98, 13);
        v106 = rotl(v103, 3);
        v107 = rotl(v106 ^ v96 ^ (8 * v105) ^ v99 ^ v104, 7);
        v108 = rotl(v106 ^ v105 ^ v100, 1);
        v109 = rotl(v107 ^ v105 ^ v108, 5);
        v110 = rotl(v107 ^ v106 ^ (v108 << 7), 22);
        v111 = readUInt32LE(this.buffer, (58 * 4) - 104) ^ v109;
        v112 = readUInt32LE(this.buffer, (59 * 4) - 104) ^ v108;
        v113 = readUInt32LE(this.buffer, (61 * 4) - 104) ^ v107;
        v114 = v113 ^ v111 ^ v112;
        v115 = readUInt32LE(this.buffer, (60 * 4) - 104) ^ v110 ^ (v113 ^ v111 | ~v111);
        v116 = v115 ^ v112;
        v117 = (v115 ^ v112 | v113 ^ v111) ^ v113;
        v118 = v117 & v115 ^ v114;
        v119 = v117 ^ v115;
        v120 = v119 & v114;
        v121 = rotl(v118 ^ v119, 13);
        v122 = rotl(v118, 3);
        v123 = v122 ^ (8 * v121) ^ v115 ^ ~v120;
        v124 = v122 ^ v121 ^ v116;
        v125 = rotl(v123, 7);
        v126 = rotl(v124, 1);
        v127 = rotl(v125 ^ v121 ^ v126, 5);
        v128 = rotl(v125 ^ v122 ^ (v126 << 7), 22);
        v129 = readUInt32LE(this.buffer, (62 * 4) - 104) ^ v127;
        v130 = readUInt32LE(this.buffer, (63 * 4) - 104) ^ v126;
        v131 = readUInt32LE(this.buffer, (64 * 4) - 104) ^ v128;
        v132 = readUInt32LE(this.buffer, (65 * 4) - 104) ^ v125;
        v133 = v130 | ~v131;
        v134 = (v133 ^ v132) & v129;
        v135 = v134 ^ v131 ^ v130;
        v136 = v132 ^ v129 ^ (v134 ^ v130 | v131 ^ v130);
        v137 = (v136 ^ v134) & v135 ^ v133 & v132;
        v138 = rotl(v136 ^ v134 ^ (v133 ^ v132 | ~v131) ^ v137, 13);
        v139 = rotl(v137, 3);
        v140 = v139 ^ (8 * v138) ^ v135;
        v141 = v139 ^ v138 ^ v136;
        v142 = rotl(v140, 7);
        v143 = rotl(v141, 1);
        v144 = rotl(v142 ^ v138 ^ v143, 5);
        v145 = rotl(v142 ^ v139 ^ (v143 << 7), 22);
        v146 = readUInt32LE(this.buffer, (66 * 4) - 104) ^ v144;
        v147 = readUInt32LE(this.buffer, (67 * 4) - 104) ^ v143;
        v148 = readUInt32LE(this.buffer, (68 * 4) - 104) ^ v145;
        v149 = readUInt32LE(this.buffer, (69 * 4) - 104) ^ v142;
        v150 = v149 ^ v146 ^ v148;
        v151 = (v149 ^ v146) & v147;
        v152 = v150 ^ v147;
        v153 = v152 ^ v149 & v146;
        v154 = v151 ^ v146;
        v155 = (v154 | v148) ^ v152;
        v156 = v153 & (v154 ^ v150);
        v157 = rotl(v156 ^ ~v154, 13);
        v158 = rotl(v155, 3);
        v159 = rotl(v158 ^ (8 * v157) ^ v153, 7);
        v160 = rotl(v156 ^ ~(v158 ^ v157 ^ v150), 1);
        v161 = rotl(v159 ^ v157 ^ v160, 5);
        v162 = rotl(v159 ^ v158 ^ (v160 << 7), 22);
        v163 = readUInt32LE(this.buffer, (70 * 4) - 104) ^ v161;
        v164 = readUInt32LE(this.buffer, (71 * 4) - 104) ^ v160;
        v165 = v164 ^ v163;
        v166 = readUInt32LE(this.buffer, (73 * 4) - 104) ^ v159;
        v167 = v166 | ~(v164 ^ v163);
        v168 = readUInt32LE(this.buffer, (72 * 4) - 104) ^ v162 ^ (v163 | ~(v164 ^ v163));
        v169 = v168 ^ v166;
        v170 = v167 ^ v164;
        v171 = v165 ^ ~(v168 ^ v166);
        v172 = v171 ^ v170 & v168;
        v173 = v170 ^ v168;
        v174 = rotl(v171 & (v170 ^ v168) ^ v168, 13);
        v175 = rotl(v169, 3);
        v176 = v172 ^ v175 ^ (8 * v174);
        v177 = v172 ^ v175 ^ v174 ^ v173;
        v178 = rotl(v176, 7);
        v179 = rotl(v177, 1);
        v180 = rotl(v178 ^ v174 ^ v179, 5);
        v181 = rotl(v178 ^ v175 ^ (v179 << 7), 22);
        v182 = readUInt32LE(this.buffer, (74 * 4) - 104) ^ v180;
        v183 = readUInt32LE(this.buffer, (75 * 4) - 104) ^ v179;
        v184 = readUInt32LE(this.buffer, (76 * 4) - 104) ^ v181;
        v185 = readUInt32LE(this.buffer, (77 * 4) - 104);
        v186 = v185 ^ v178 ^ v183 ^ v184 & ~v182;
        v187 = v182 ^ ~v184;
        v188 = (v186 ^ v184) & v183;
        v189 = v188 ^ v187;
        v190 = (v188 | v185 ^ v178) & (v186 | v187) ^ v182;
        v191 = (v185 ^ ~v178) & ~v182;
        v192 = rotl(v186, 13);
        v193 = rotl(v190, 3);
        v194 = v189 ^ v193 ^ v183 ^ v192 ^ v191 ^ v190;
        v195 = rotl(v189 ^ v193 ^ (8 * v192), 7);
        v196 = rotl(v194, 1);
        v197 = v195 ^ v192 ^ v196;
        v198 = v195 ^ v193 ^ (v196 << 7);
        v199 = rotl(v197, 5);
        v200 = rotl(v198, 22);
        v201 = readUInt32LE(this.buffer, (78 * 4) - 104) ^ v199;
        v202 = readUInt32LE(this.buffer, (79 * 4) - 104) ^ v196;
        v203 = readUInt32LE(this.buffer, (80 * 4) - 104) ^ v200;
        v204 = readUInt32LE(this.buffer, (81 * 4) - 104) ^ v195;
        v205 = v203 ^ v201 ^ v204;
        v206 = v205 & v201 ^ v204;
        v207 = v206 & v202 ^ v205;
        v208 = v204 | v202;
        v209 = (v207 | v201) & v206;
        v210 = (v204 | v201) ^ v202;
        v211 = rotl((v205 & v201 ^ (v204 | v202)) & v203 ^ v210, 13);
        v212 = rotl(v207, 3);
        v213 = v209 ^ v212 ^ (8 * v211) ^ v210 ^ v207;
        v214 = v209 ^ v212 ^ v211 ^ v208;
        v215 = rotl(v213, 7);
        v216 = rotl(v214, 1);
        v217 = v215 ^ v211 ^ v216;
        v218 = v215 ^ v212 ^ (v216 << 7);
        v219 = rotl(v217, 5);
        v220 = rotl(v218, 22);
        v221 = readUInt32LE(this.buffer, (82 * 4) - 104) ^ v219;
        v222 = readUInt32LE(this.buffer, (83 * 4) - 104) ^ v216;
        v223 = readUInt32LE(this.buffer, (85 * 4) - 104) ^ v215;
        v224 = v223 ^ v221;
        v225 = readUInt32LE(this.buffer, (84 * 4) - 104) ^ v220 ^ (v223 ^ v221) & v223;
        v226 = v225 | v222;
        v227 = v225 ^ (v223 ^ v221 | ~v222);
        v228 = v222 ^ ~(v223 ^ v221);
        v229 = v227 & v221 ^ v226 & v228;
        v230 = v229 & v228;
        v231 = rotl(v227, 13);
        v232 = rotl(v229, 3);
        v233 = rotl(v232 ^ (8 * v231) ^ v224 ^ v226, 7);
        v234 = rotl(v231 ^ v221 ^ v232 ^ v225 ^ v230, 1);
        v235 = rotl(v233 ^ v231 ^ v234, 5);
        v236 = rotl(v233 ^ v232 ^ (v234 << 7), 22);
        v237 = readUInt32LE(this.buffer, (86 * 4) - 104) ^ v235;
        v238 = readUInt32LE(this.buffer, (87 * 4) - 104) ^ v234;
        v239 = readUInt32LE(this.buffer, (89 * 4) - 104) ^ v233;
        v240 = v237 ^ ~v236 ^ readUInt32LE(this.buffer, (88 * 4) - 104) ^ (v239 ^ v237 | v238 ^ v237);
        v241 = v240 & v239;
        v242 = v240 ^ v238 ^ v237 ^ v240 & v239;
        v243 = v240 & v239 | v238 ^ v237;
        v244 = (v240 | ~v237) ^ v239 ^ v237;
        v245 = v243 ^ v244;
        v246 = v242 & v244;
        v247 = rotl(v240, 13);
        v248 = rotl(v245, 3);
        v249 = rotl(v248 ^ v238 ^ (8 * v247) ^ v241 ^ v246, 7);
        v250 = rotl(v248 ^ v247 ^ v242, 1);
        v251 = rotl(v249 ^ v247 ^ v250, 5);
        v252 = rotl(v249 ^ v248 ^ (v250 << 7), 22);
        v253 = readUInt32LE(this.buffer, (90 * 4) - 104) ^ v251;
        v254 = readUInt32LE(this.buffer, (91 * 4) - 104) ^ v250;
        v255 = readUInt32LE(this.buffer, (93 * 4) - 104) ^ v249;
        v256 = v255 ^ v253 ^ v254;
        v257 = readUInt32LE(this.buffer, (92 * 4) - 104) ^ v252 ^ (v255 ^ v253 | ~v253);
        v258 = v257 ^ v254;
        v259 = (v257 ^ v254 | v255 ^ v253) ^ v255;
        v260 = v259 & v257 ^ v256;
        v261 = v259 ^ v257;
        v262 = v261 & v256;
        v263 = rotl(v260 ^ v261, 13);
        v264 = rotl(v260, 3);
        v265 = v264 ^ (8 * v263) ^ v257 ^ ~v262;
        v266 = v264 ^ v263 ^ v258;
        v267 = rotl(v265, 7);
        v268 = rotl(v266, 1);
        v269 = rotl(v267 ^ v263 ^ v268, 5);
        v270 = rotl(v267 ^ v264 ^ (v268 << 7), 22);
        v271 = readUInt32LE(this.buffer, (94 * 4) - 104) ^ v269;
        v272 = readUInt32LE(this.buffer, (95 * 4) - 104) ^ v268;
        v273 = readUInt32LE(this.buffer, (96 * 4) - 104) ^ v270;
        v274 = readUInt32LE(this.buffer, (97 * 4) - 104) ^ v267;
        v275 = v272 | ~v273;
        v276 = (v275 ^ v274) & v271;
        v277 = v276 ^ v273 ^ v272;
        v278 = v274 ^ v271 ^ (v276 ^ v272 | v273 ^ v272);
        v279 = (v278 ^ v276) & v277 ^ v275 & v274;
        v280 = rotl(v278 ^ v276 ^ (v275 ^ v274 | ~v273) ^ v279, 13);
        v281 = rotl(v279, 3);
        v282 = v281 ^ (8 * v280) ^ v277;
        v283 = v281 ^ v280 ^ v278;
        v284 = rotl(v282, 7);
        v285 = rotl(v283, 1);
        v286 = rotl(v284 ^ v280 ^ v285, 5);
        v287 = rotl(v284 ^ v281 ^ (v285 << 7), 22);
        v288 = readUInt32LE(this.buffer, (98 * 4) - 104) ^ v286;
        v289 = readUInt32LE(this.buffer, (99 * 4) - 104) ^ v285;
        v290 = readUInt32LE(this.buffer, (100 * 4) - 104) ^ v287;
        v291 = readUInt32LE(this.buffer, (101 * 4) - 104) ^ v284;
        v292 = v291 ^ v288 ^ v290;
        v293 = (v291 ^ v288) & v289;
        v294 = v292 ^ v289;
        v295 = v294 ^ v291 & v288;
        v296 = v293 ^ v288;
        v297 = (v296 | v290) ^ v294;
        v298 = v295 & (v296 ^ v292);
        v299 = rotl(v298 ^ ~v296, 13);
        v300 = rotl(v297, 3);
        v301 = rotl(v300 ^ (8 * v299) ^ v295, 7);
        v302 = rotl(v298 ^ ~(v300 ^ v299 ^ v292), 1);
        v303 = rotl(v301 ^ v299 ^ v302, 5);
        v304 = rotl(v301 ^ v300 ^ (v302 << 7), 22);
        v305 = readUInt32LE(this.buffer, (102 * 4) - 104) ^ v303;
        v306 = readUInt32LE(this.buffer, (103 * 4) - 104) ^ v302;
        v307 = v306 ^ v305;
        v308 = readUInt32LE(this.buffer, (105 * 4) - 104) ^ v301;
        v309 = v308 | ~(v306 ^ v305);
        v310 = readUInt32LE(this.buffer, (104 * 4) - 104) ^ v304 ^ (v305 | ~(v306 ^ v305));
        v311 = v310 ^ v308;
        v312 = v309 ^ v306;
        v313 = v307 ^ ~(v310 ^ v308);
        v314 = v313 ^ v312 & v310;
        v315 = v312 ^ v310;
        v316 = rotl(v313 & (v312 ^ v310) ^ v310, 13);
        v317 = rotl(v311, 3);
        v318 = v314 ^ v317 ^ (8 * v316);
        v319 = v314 ^ v317 ^ v316 ^ v315;
        v320 = rotl(v318, 7);
        v321 = rotl(v319, 1);
        v322 = rotl(v320 ^ v316 ^ v321, 5);
        v323 = rotl(v320 ^ v317 ^ (v321 << 7), 22);
        v324 = readUInt32LE(this.buffer, (106 * 4) - 104) ^ v322;
        v325 = readUInt32LE(this.buffer, (107 * 4) - 104) ^ v321;
        v326 = readUInt32LE(this.buffer, (108 * 4) - 104) ^ v323;
        v327 = readUInt32LE(this.buffer, (109 * 4) - 104);
        v328 = v327 ^ v320 ^ v325 ^ v326 & ~v324;
        v329 = v324 ^ ~v326;
        v330 = (v328 ^ v326) & v325;
        v331 = v330 ^ v329;
        v332 = (v330 | v327 ^ v320) & (v328 | v329) ^ v324;
        v333 = (v327 ^ ~v320) & ~v324;
        v334 = rotl(v328, 13);
        v335 = rotl(v332, 3);
        v336 = v331 ^ v335 ^ v325 ^ v334 ^ v333 ^ v332;
        v337 = rotl(v331 ^ v335 ^ (8 * v334), 7);
        v338 = rotl(v336, 1);
        v339 = v337 ^ v334 ^ v338;
        v340 = v337 ^ v335 ^ (v338 << 7);
        v341 = rotl(v339, 5);
        v342 = rotl(v340, 22);
        v343 = readUInt32LE(this.buffer, (110 * 4) - 104) ^ v341;
        v344 = readUInt32LE(this.buffer, (111 * 4) - 104) ^ v338;
        v345 = readUInt32LE(this.buffer, (112 * 4) - 104) ^ v342;
        v346 = readUInt32LE(this.buffer, (113 * 4) - 104) ^ v337;
        v347 = v345 ^ v343 ^ v346;
        v348 = v347 & v343 ^ v346;
        v349 = v348 & v344 ^ v347;
        v350 = v346 | v344;
        v351 = (v349 | v343) & v348;
        v352 = (v346 | v343) ^ v344;
        v353 = rotl((v347 & v343 ^ (v346 | v344)) & v345 ^ v352, 13);
        v354 = rotl(v349, 3);
        v355 = v351 ^ v354 ^ (8 * v353) ^ v352 ^ v349;
        v356 = v351 ^ v354 ^ v353 ^ v350;
        v357 = rotl(v355, 7);
        v358 = rotl(v356, 1);
        v359 = v357 ^ v353 ^ v358;
        v360 = v357 ^ v354 ^ (v358 << 7);
        v361 = rotl(v359, 5);
        v362 = rotl(v360, 22);
        v363 = readUInt32LE(this.buffer, (114 * 4) - 104) ^ v361;
        v364 = readUInt32LE(this.buffer, (115 * 4) - 104) ^ v358;
        v365 = readUInt32LE(this.buffer, (117 * 4) - 104) ^ v357;
        v366 = v365 ^ v363;
        v367 = readUInt32LE(this.buffer, (116 * 4) - 104) ^ v362 ^ (v365 ^ v363) & v365;
        v368 = v367 | v364;
        v369 = v367 ^ (v365 ^ v363 | ~v364);
        v370 = v364 ^ ~(v365 ^ v363);
        v371 = v369 & v363 ^ v368 & v370;
        v372 = v371 & v370;
        v373 = rotl(v369, 13);
        v374 = rotl(v371, 3);
        v375 = rotl(v374 ^ (8 * v373) ^ v366 ^ v368, 7);
        v376 = rotl(v373 ^ v363 ^ v374 ^ v367 ^ v372, 1);
        v377 = rotl(v375 ^ v373 ^ v376, 5);
        v378 = rotl(v375 ^ v374 ^ (v376 << 7), 22);
        v379 = readUInt32LE(this.buffer, (118 * 4) - 104) ^ v377;
        v380 = readUInt32LE(this.buffer, (119 * 4) - 104) ^ v376;
        v381 = readUInt32LE(this.buffer, (121 * 4) - 104) ^ v375;
        v382 = v379 ^ ~v378 ^ readUInt32LE(this.buffer, (120 * 4) - 104) ^ (v381 ^ v379 | v380 ^ v379);
        v383 = v382 & v381;
        v384 = v382 ^ v380 ^ v379 ^ v382 & v381;
        v385 = v382 & v381 | v380 ^ v379;
        v386 = (v382 | ~v379) ^ v381 ^ v379;
        v387 = v385 ^ v386;
        v388 = v384 & v386;
        v389 = rotl(v382, 13);
        v390 = rotl(v387, 3);
        v391 = rotl(v390 ^ v380 ^ (8 * v389) ^ v383 ^ v388, 7);
        v392 = rotl(v390 ^ v389 ^ v384, 1);
        v393 = rotl(v391 ^ v389 ^ v392, 5);
        v394 = rotl(v391 ^ v390 ^ (v392 << 7), 22);
        v395 = readUInt32LE(this.buffer, (122 * 4) - 104) ^ v393;
        v396 = readUInt32LE(this.buffer, (123 * 4) - 104) ^ v392;
        v397 = readUInt32LE(this.buffer, (125 * 4) - 104) ^ v391;
        v398 = v397 ^ v395 ^ v396;
        v399 = readUInt32LE(this.buffer, (124 * 4) - 104) ^ v394 ^ (v397 ^ v395 | ~v395);
        v400 = v399 ^ v396;
        v401 = (v399 ^ v396 | v397 ^ v395) ^ v397;
        v402 = v401 & v399 ^ v398;
        v403 = v401 ^ v399;
        v404 = v403 & v398;
        v405 = rotl(v402 ^ v403, 13);
        v406 = rotl(v402, 3);
        v407 = v406 ^ (8 * v405) ^ v399 ^ ~v404;
        v408 = v406 ^ v405 ^ v400;
        v409 = rotl(v407, 7);
        v410 = rotl(v408, 1);
        v411 = rotl(v409 ^ v405 ^ v410, 5);
        v412 = rotl(v409 ^ v406 ^ (v410 << 7), 22);
        v413 = readUInt32LE(this.buffer, (126 * 4) - 104) ^ v411;
        v414 = readUInt32LE(this.buffer, (127 * 4) - 104) ^ v410;
        v415 = readUInt32LE(this.buffer, (128 * 4) - 104) ^ v412;
        v416 = readUInt32LE(this.buffer, (129 * 4) - 104) ^ v409;
        v417 = v414 | ~v415;
        v418 = (v417 ^ v416) & v413;
        v419 = v418 ^ v415 ^ v414;
        v420 = v416 ^ v413 ^ (v418 ^ v414 | v415 ^ v414);
        v421 = (v420 ^ v418) & v419 ^ v417 & v416;
        v422 = rotl(v420 ^ v418 ^ (v417 ^ v416 | ~v415) ^ v421, 13);
        v423 = rotl(v421, 3);
        v424 = v423 ^ (8 * v422) ^ v419;
        v425 = v423 ^ v422 ^ v420;
        v426 = rotl(v424, 7);
        v427 = rotl(v425, 1);
        v428 = rotl(v426 ^ v422 ^ v427, 5);
        v429 = rotl(v426 ^ v423 ^ (v427 << 7), 22);
        v430 = readUInt32LE(this.buffer, (130 * 4) - 104) ^ v428;
        v431 = readUInt32LE(this.buffer, (131 * 4) - 104) ^ v427;
        v432 = readUInt32LE(this.buffer, (132 * 4) - 104) ^ v429;
        v433 = readUInt32LE(this.buffer, (133 * 4) - 104) ^ v426;
        v434 = v433 ^ v430 ^ v432;
        v435 = (v433 ^ v430) & v431;
        v436 = v434 ^ v431;
        v437 = v436 ^ v433 & v430;
        v438 = v435 ^ v430;
        v439 = (v438 | v432) ^ v436;
        v440 = v437 & (v438 ^ v434);
        v441 = rotl(v440 ^ ~v438, 13);
        v442 = rotl(v439, 3);
        v443 = rotl(v442 ^ (8 * v441) ^ v437, 7);
        v444 = rotl(v440 ^ ~(v442 ^ v441 ^ v434), 1);
        v445 = rotl(v443 ^ v441 ^ v444, 5);
        v446 = rotl(v443 ^ v442 ^ (v444 << 7), 22);
        v447 = readUInt32LE(this.buffer, (134 * 4) - 104) ^ v445;
        v448 = readUInt32LE(this.buffer, (135 * 4) - 104) ^ v444;
        v449 = v448 ^ v447;
        v450 = readUInt32LE(this.buffer, (137 * 4) - 104) ^ v443;
        v451 = v450 | ~(v448 ^ v447);
        v452 = readUInt32LE(this.buffer, (136 * 4) - 104) ^ v446 ^ (v447 | ~(v448 ^ v447));
        v453 = v452 ^ v450;
        v454 = v451 ^ v448;
        v455 = v449 ^ ~(v452 ^ v450);
        v456 = v455 ^ v454 & v452;
        v457 = v454 ^ v452;
        v458 = rotl(v455 & (v454 ^ v452) ^ v452, 13);
        v459 = rotl(v453, 3);
        v460 = v456 ^ v459 ^ (8 * v458);
        v461 = v456 ^ v459 ^ v458 ^ v457;
        v462 = rotl(v460, 7);
        v463 = rotl(v461, 1);
        v464 = rotl(v462 ^ v458 ^ v463, 5);
        v465 = rotl(v462 ^ v459 ^ (v463 << 7), 22);
        v466 = readUInt32LE(this.buffer, (138 * 4) - 104) ^ v464;
        v467 = readUInt32LE(this.buffer, (139 * 4) - 104) ^ v463;
        v468 = readUInt32LE(this.buffer, (140 * 4) - 104) ^ v465;
        v469 = readUInt32LE(this.buffer, (141 * 4) - 104);
        v470 = v469 ^ v462 ^ v467 ^ v468 & ~v466;
        v471 = v466 ^ ~v468;
        v472 = (v470 ^ v468) & v467;
        v473 = v472 ^ v471;
        v474 = (v472 | v469 ^ v462) & (v470 | v471) ^ v466;
        v475 = (v469 ^ ~v462) & ~v466;
        v476 = rotl(v470, 13);
        v477 = rotl(v474, 3);
        v478 = v473 ^ v477 ^ v467 ^ v476 ^ v475 ^ v474;
        v479 = rotl(v473 ^ v477 ^ (8 * v476), 7);
        v480 = rotl(v478, 1);
        v481 = v479 ^ v476 ^ v480;
        v482 = v479 ^ v477 ^ (v480 << 7);
        v483 = rotl(v481, 5);
        v484 = rotl(v482, 22);
        v485 = readUInt32LE(this.buffer, (142 * 4) - 104) ^ v483;
        v486 = readUInt32LE(this.buffer, (143 * 4) - 104) ^ v480;
        v487 = readUInt32LE(this.buffer, (144 * 4) - 104) ^ v484;
        v488 = readUInt32LE(this.buffer, (145 * 4) - 104) ^ v479;
        v489 = v487 ^ v485 ^ v488;
        v490 = v489 & v485 ^ v488;
        v491 = v490 & v486 ^ v489;
        v492 = v488 | v486;
        v493 = (v491 | v485) & v490;
        v494 = (v488 | v485) ^ v486;
        v495 = rotl((v489 & v485 ^ (v488 | v486)) & v487 ^ v494, 13);
        v496 = rotl(v491, 3);
        v497 = v493 ^ v496 ^ (8 * v495) ^ v494 ^ v491;
        v498 = v493 ^ v496 ^ v495 ^ v492;
        v499 = rotl(v497, 7);
        v500 = rotl(v498, 1);
        v501 = v499 ^ v495 ^ v500;
        v502 = v499 ^ v496 ^ (v500 << 7);
        v503 = rotl(v501, 5);
        v504 = rotl(v502, 22);
        v505 = readUInt32LE(this.buffer, (146 * 4) - 104) ^ v503;
        v506 = readUInt32LE(this.buffer, (147 * 4) - 104) ^ v500;
        v507 = readUInt32LE(this.buffer, (149 * 4) - 104) ^ v499;
        v508 = v507 ^ v505;
        v509 = readUInt32LE(this.buffer, (148 * 4) - 104) ^ v504 ^ (v507 ^ v505) & v507;
        v510 = v509 | v506;
        v511 = v509 ^ (v507 ^ v505 | ~v506);
        v512 = v506 ^ ~(v507 ^ v505);
        v513 = v511 & v505 ^ v510 & v512;
        v514 = v513 & v512;
        v515 = rotl(v511, 13);
        v516 = rotl(v513, 3);
        v517 = rotl(v516 ^ (8 * v515) ^ v508 ^ v510, 7);
        v518 = rotl(v515 ^ v505 ^ v516 ^ v509 ^ v514, 1);
        v519 = rotl(v517 ^ v515 ^ v518, 5);
        v520 = rotl(v517 ^ v516 ^ (v518 << 7), 22);
        v521 = readUInt32LE(this.buffer, (150 * 4) - 104) ^ v519;
        v522 = readUInt32LE(this.buffer, (151 * 4) - 104) ^ v518;
        v523 = readUInt32LE(this.buffer, (153 * 4) - 104) ^ v517;
        v524 = v521 ^ ~v520 ^ readUInt32LE(this.buffer, (152 * 4) - 104) ^ (v523 ^ v521 | v522 ^ v521);
        v525 = v524 & v523;
        v526 = v524 ^ v522 ^ v521 ^ v524 & v523;
        v527 = v524 & v523 | v522 ^ v521;
        v528 = (v524 | ~v521) ^ v523 ^ v521;
        v529 = v527 ^ v528;
        v530 = v526 & v528;
        v531 = rotl(v524, 13);
        v532 = rotl(v529, 3);
        v533 = rotl(v532 ^ v522 ^ (8 * v531) ^ v525 ^ v530, 7);
        v534 = rotl(v532 ^ v531 ^ v526, 1);
        v535 = rotl(v533 ^ v531 ^ v534, 5);
        v536 = rotl(v533 ^ v532 ^ (v534 << 7), 22);
        v537 = readUInt32LE(this.buffer, (154 * 4) - 104) ^ v535;
        v538 = readUInt32LE(this.buffer, (155 * 4) - 104) ^ v534;
        v539 = readUInt32LE(this.buffer, (157 * 4) - 104) ^ v533;
        v540 = v539 ^ v537 ^ v538;
        v541 = readUInt32LE(this.buffer, (156 * 4) - 104) ^ v536 ^ (v539 ^ v537 | ~v537);
        v542 = v541 ^ v538;
        v543 = (v541 ^ v538 | v539 ^ v537) ^ v539;
        v544 = v543 & v541 ^ v540;
        v545 = v543 ^ v541;
        v546 = v545 & v540;
        v547 = rotl(v544 ^ v545, 13);
        v548 = rotl(v544, 3);
        v549 = v548 ^ (8 * v547) ^ v541 ^ ~v546;
        v550 = v548 ^ v547 ^ v542;
        v551 = rotl(v549, 7);
        v552 = rotl(v550, 1);
        v553 = rotl(v551 ^ v547 ^ v552, 5);
        resu = rotl(v551 ^ v548 ^ (v552 << 7), 22);
        v555 = readUInt32LE(this.buffer, (158 * 4) - 104) ^ v553;
        v556 = readUInt32LE(this.buffer, (159 * 4) - 104) ^ v552;
        v557 = readUInt32LE(this.buffer, (160 * 4) - 104) ^ resu;
        v558 = readUInt32LE(this.buffer, (161 * 4) - 104) ^ v551;
        v559 = v556 | ~v557;
        v560 = v559 ^ v558;
        v561 = (v559 ^ v558) & v555;
        v562 = v561 ^ v557 ^ v556;
        v563 = v558 ^ v555 ^ (v561 ^ v556 | v557 ^ v556);
        v564 = (v563 ^ v561) & v562 ^ v559 & v558;
        v565 = (v560 | ~v557) ^ readUInt32LE(this.buffer, (162 * 4) - 104) ^ v563 ^ v561 ^ v564;
        v566 = v563 ^ readUInt32LE(this.buffer, (163 * 4) - 104);
        v567 = v564 ^ readUInt32LE(this.buffer, (164 * 4) - 104);
        v568 = v562 ^ readUInt32LE(this.buffer, (165 * 4) - 104);

        var out_blk:Buffer|Uint8Array;
        if (isBuffer(block)) {
            out_blk = Buffer.alloc(16);
        } else {
            out_blk = new Uint8Array(16);
        } 
        writeUInt32LE(out_blk, (v565 >>> 0), 0);
        writeUInt32LE(out_blk, (v566 >>> 0), 4);
        writeUInt32LE(out_blk, (v567 >>> 0), 8);
        writeUInt32LE(out_blk, (v568 >>> 0), 12);

        if (this.iv_set == true) {
            this.iv = out_blk;
        }
        return out_blk;
    };

    private decrypt_block (block:Buffer|Uint8Array):Buffer|Uint8Array {
        let start_chunk = block
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block
            }
        }

        this.previous_block = start_chunk

        let v8 = 0; let v9 = 0; let v10 = 0; let v11 = 0; let v12 = 0; let v13 = 0; let v14 = 0; let v15 = 0;
        let v16 = 0; let v17 = 0; let v18 = 0; let v19 = 0; let v20 = 0; let v21 = 0; let v22 = 0; let v23 = 0;
        let v24 = 0; let v25 = 0; let v26 = 0; let v27 = 0; let v28 = 0; let v29 = 0; let v30 = 0; let v31 = 0;
        let v32 = 0; let v33 = 0; let v34 = 0; let v35 = 0; let v36 = 0; let v37 = 0; let v38 = 0; let v39 = 0;
        let v40 = 0; let v41 = 0; let v42 = 0; let v43 = 0; let v44 = 0; let v45 = 0; let v46 = 0; let v47 = 0;
        let v48 = 0; let v49 = 0; let v50 = 0; let v51 = 0; let v52 = 0; let v53 = 0; let v54 = 0; let v55 = 0;
        let v56 = 0; let v57 = 0; let v58 = 0; let v59 = 0; let v60 = 0; let v61 = 0; let v62 = 0; let v63 = 0;
        let v64 = 0; let v65 = 0; let v66 = 0; let v67 = 0; let v68 = 0; let v69 = 0; let v70 = 0; let v71 = 0;
        let v72 = 0; let v73 = 0; let v74 = 0; let v75 = 0; let v76 = 0; let v77 = 0; let v78 = 0; let v79 = 0;
        let v80 = 0; let v81 = 0; let v82 = 0; let v83 = 0; let v84 = 0; let v85 = 0; let v86 = 0; let v87 = 0;
        let v88 = 0; let v89 = 0; let v90 = 0; let v91 = 0; let v92 = 0; let v93 = 0; let v94 = 0; let v95 = 0;
        let v96 = 0; let v97 = 0; let v98 = 0; let v99 = 0; let v100 = 0; let v101 = 0; let v102 = 0; let v103 = 0;
        let v104 = 0; let v105 = 0; let v106 = 0; let v107 = 0; let v108 = 0; let v109 = 0; let v110 = 0; let v111 = 0;
        let v112 = 0; let v113 = 0; let v114 = 0; let v115 = 0; let v116 = 0; let v117 = 0; let v118 = 0; let v119 = 0;
        let v120 = 0; let v121 = 0; let v122 = 0; let v123 = 0; let v124 = 0; let v125 = 0; let v126 = 0; let v127 = 0;
        let v128 = 0; let v129 = 0; let v130 = 0; let v131 = 0; let v132 = 0; let v133 = 0; let v134 = 0; let v135 = 0;
        let v136 = 0; let v137 = 0; let v138 = 0; let v139 = 0; let v140 = 0; let v141 = 0; let v142 = 0; let v143 = 0;
        let v144 = 0; let v145 = 0; let v146 = 0; let v147 = 0; let v148 = 0; let v149 = 0; let v150 = 0; let v151 = 0;
        let v152 = 0; let v153 = 0; let v154 = 0; let v155 = 0; let v156 = 0; let v157 = 0; let v158 = 0; let v159 = 0;
        let v160 = 0; let v161 = 0; let v162 = 0; let v163 = 0; let v164 = 0; let v165 = 0; let v166 = 0; let v167 = 0;
        let v168 = 0; let v169 = 0; let v170 = 0; let v171 = 0; let v172 = 0; let v173 = 0; let v174 = 0; let v175 = 0;
        let v176 = 0; let v177 = 0; let v178 = 0; let v179 = 0; let v180 = 0; let v181 = 0; let v182 = 0; let v183 = 0;
        let v184 = 0; let v185 = 0; let v186 = 0; let v187 = 0; let v188 = 0; let v189 = 0; let v190 = 0; let v191 = 0;
        let v192 = 0; let v193 = 0; let v194 = 0; let v195 = 0; let v196 = 0; let v197 = 0; let v198 = 0; let v199 = 0;
        let v200 = 0; let v201 = 0; let v202 = 0; let v203 = 0; let v204 = 0; let v205 = 0; let v206 = 0; let v207 = 0;
        let v208 = 0; let v209 = 0; let v210 = 0; let v211 = 0; let v212 = 0; let v213 = 0; let v214 = 0; let v215 = 0;
        let v216 = 0; let v217 = 0; let v218 = 0; let v219 = 0; let v220 = 0; let v221 = 0; let v222 = 0; let v223 = 0;
        let v224 = 0; let v225 = 0; let v226 = 0; let v227 = 0; let v228 = 0; let v229 = 0; let v230 = 0; let v231 = 0;
        let v232 = 0; let v233 = 0; let v234 = 0; let v235 = 0; let v236 = 0; let v237 = 0; let v238 = 0; let v239 = 0;
        let v240 = 0; let v241 = 0; let v242 = 0; let v243 = 0; let v244 = 0; let v245 = 0; let v246 = 0; let v247 = 0;
        let v248 = 0; let v249 = 0; let v250 = 0; let v251 = 0; let v252 = 0; let v253 = 0; let v254 = 0; let v255 = 0;
        let v256 = 0; let v257 = 0; let v258 = 0; let v259 = 0; let v260 = 0; let v261 = 0; let v262 = 0; let v263 = 0;
        let v264 = 0; let v265 = 0; let v266 = 0; let v267 = 0; let v268 = 0; let v269 = 0; let v270 = 0; let v271 = 0;
        let v272 = 0; let v273 = 0; let v274 = 0; let v275 = 0; let v276 = 0; let v277 = 0; let v278 = 0; let v279 = 0;
        let v280 = 0; let v281 = 0; let v282 = 0; let v283 = 0; let v284 = 0; let v285 = 0; let v286 = 0; let v287 = 0;
        let v288 = 0; let v289 = 0; let v290 = 0; let v291 = 0; let v292 = 0; let v293 = 0; let v294 = 0; let v295 = 0;
        let v296 = 0; let v297 = 0; let v298 = 0; let v299 = 0; let v300 = 0; let v301 = 0; let v302 = 0; let v303 = 0;
        let v304 = 0; let v305 = 0; let v306 = 0; let v307 = 0; let v308 = 0; let v309 = 0; let v310 = 0; let v311 = 0;
        let v312 = 0; let v313 = 0; let v314 = 0; let v315 = 0; let v316 = 0; let v317 = 0; let v318 = 0; let v319 = 0;
        let v320 = 0; let v321 = 0; let v322 = 0; let v323 = 0; let v324 = 0; let v325 = 0; let v326 = 0; let v327 = 0;
        let v328 = 0; let v329 = 0; let v330 = 0; let v331 = 0; let v332 = 0; let v333 = 0; let v334 = 0; let v335 = 0;
        let v336 = 0; let v337 = 0; let v338 = 0; let v339 = 0; let v340 = 0; let v341 = 0; let v342 = 0; let v343 = 0;
        let v344 = 0; let v345 = 0; let v346 = 0; let v347 = 0; let v348 = 0; let v349 = 0; let v350 = 0; let v351 = 0;
        let v352 = 0; let v353 = 0; let v354 = 0; let v355 = 0; let v356 = 0; let v357 = 0; let v358 = 0; let v359 = 0;
        let v360 = 0; let v361 = 0; let v362 = 0; let v363 = 0; let v364 = 0; let v365 = 0; let v366 = 0; let v367 = 0;
        let v368 = 0; let v369 = 0; let v370 = 0; let v371 = 0; let v372 = 0; let v373 = 0; let v374 = 0; let v375 = 0;
        let v376 = 0; let v377 = 0; let v378 = 0; let v379 = 0; let v380 = 0; let v381 = 0; let v382 = 0; let v383 = 0;
        let v384 = 0; let v385 = 0; let v386 = 0; let v387 = 0; let v388 = 0; let v389 = 0; let v390 = 0; let v391 = 0;
        let v392 = 0; let v393 = 0; let v394 = 0; let v395 = 0; let v396 = 0; let v397 = 0; let v398 = 0; let v399 = 0;
        let v400 = 0; let v401 = 0; let v402 = 0; let v403 = 0; let v404 = 0; let v405 = 0; let v406 = 0; let v407 = 0;
        let v408 = 0; let v409 = 0; let v410 = 0; let v411 = 0; let v412 = 0; let v413 = 0; let v414 = 0; let v415 = 0;
        let v416 = 0; let v417 = 0; let v418 = 0; let v419 = 0; let v420 = 0; let v421 = 0; let v422 = 0; let v423 = 0;
        let v424 = 0; let v425 = 0; let v426 = 0; let v427 = 0; let v428 = 0; let v429 = 0; let v430 = 0; let v431 = 0;
        let v432 = 0; let v433 = 0; let v434 = 0; let v435 = 0; let v436 = 0; let v437 = 0; let v438 = 0; let v439 = 0;
        let v440 = 0; let v441 = 0; let v442 = 0; let v443 = 0; let v444 = 0; let v445 = 0; let v446 = 0; let v447 = 0;
        let v448 = 0; let v449 = 0; let v450 = 0; let v451 = 0; let v452 = 0; let v453 = 0; let v454 = 0; let v455 = 0;
        let v456 = 0; let v457 = 0; let v458 = 0; let v459 = 0; let v460 = 0; let v461 = 0; let v462 = 0; let v463 = 0;
        let v464 = 0; let v465 = 0; let v466 = 0; let v467 = 0; let v468 = 0; let v469 = 0; let v470 = 0; let v471 = 0;
        let v472 = 0; let v473 = 0; let v474 = 0; let v475 = 0; let v476 = 0; let v477 = 0; let v478 = 0; let v479 = 0;
        let v480 = 0; let v481 = 0; let v482 = 0; let v483 = 0; let v484 = 0; let v485 = 0; let v486 = 0; let v487 = 0;
        let v488 = 0; let v489 = 0; let v490 = 0; let v491 = 0; let v492 = 0; let v493 = 0; let v494 = 0; let v495 = 0;
        let v496 = 0; let v497 = 0; let v498 = 0; let v499 = 0; let v500 = 0; let v501 = 0; let v502 = 0; let v503 = 0;
        let v504 = 0; let v505 = 0; let v506 = 0; let v507 = 0; let v508 = 0; let v509 = 0; let v510 = 0; let v511 = 0;
        let v512 = 0; let v513 = 0; let v514 = 0; let v515 = 0; let v516 = 0; let v517 = 0; let v518 = 0; let v519 = 0;
        let v520 = 0; let v521 = 0; let v522 = 0; let v523 = 0; let v524 = 0; let v525 = 0; let v526 = 0; let v527 = 0;
        let v528 = 0; let v529 = 0; let v530 = 0; let v531 = 0; let v532 = 0; let v533 = 0; let v534 = 0; let v535 = 0;
        let v536 = 0; let v537 = 0; let v538 = 0; let v539 = 0; let v540 = 0; let v541 = 0; let v542 = 0; let v543 = 0;
        let v544 = 0; let v545 = 0; let v546 = 0; let v547 = 0; let v548 = 0; let v549 = 0; let v550 = 0; let v551 = 0;
        let v552 = 0; let v553 = 0; let v554 = 0; let v555 = 0; let v556 = 0; let v557 = 0; let v558 = 0; let v559 = 0;
        let v560 = 0; let resu = 0; let v562 = 0; let v563 = 0; let v564 = 0; let v565 = 0; let v566 = 0; let v567 = 0;
        let v568 = 0; let v569 = 0;

        let a = readUInt32LE(start_chunk, 0) ^  readUInt32LE(this.buffer, (162 * 4) - 104)
        let b = readUInt32LE(start_chunk, 4) ^  readUInt32LE(this.buffer, (163 * 4) - 104)
        let c = readUInt32LE(start_chunk, 8) ^  readUInt32LE(this.buffer, (164 * 4) - 104)
        let d = readUInt32LE(start_chunk, 12) ^ readUInt32LE(this.buffer, (165 * 4) - 104)

        v8 = b & a | c;
        v9 = d & (b | a);
        v10 = v9 ^ b;
        v11 = v10 ^ c;
        v12 = (v10 | ~(v9 ^ v8 ^ d)) ^ a;
        v13 = v11 ^ (v12 | d);
        v14 = v13 ^ readUInt32LE(this.buffer,(158 * 4) - 104);
        v15 = v12 ^ readUInt32LE(this.buffer,(159 * 4) - 104);
        v16 = readUInt32LE(this.buffer, (161 * 4) - 104) ^ v9 ^ v8;
        v17 = rotr(readUInt32LE(this.buffer,(160 * 4) - 104) ^ v8 ^ (v9 ^ v8) & a ^ v12 ^ v13, 22);
        v18 = rotr(v14, 5);
        v19 = v17 ^ v16 ^ (v15 << 7);
        v20 = v18 ^ v16 ^ v15;
        v21 = rotr(v16, 7);
        v22 = rotr(v15, 1);
        v23 = v19 ^ v21 ^ (8 * v20);
        v24 = v20 ^ v22 ^ v19;
        v25 = rotr(v19, 3);
        v26 = rotr(v20, 13);
        v27 = v24 ^ v26 ^ v25;
        v28 = v23 ^ (v25 | ~v26);
        v29 = v23 & ~v26;
        v30 = v27 & v28 ^ v24 ^ v26;
        v31 = (v30 | v24) ^ v28;
        v32 = v30 ^ readUInt32LE(this.buffer,(154 * 4) - 104) ^ (v31 | v24);
        v33 = v28 ^ readUInt32LE(this.buffer,(155 * 4) - 104) ^ v27;
        v34 = readUInt32LE(this.buffer,(156 * 4) - 104) ^ v29 ^ v27 ^ (v31 | v24);
        v35 = v31 ^ readUInt32LE(this.buffer,(157 * 4) - 104);
        v36 = rotr(v34, 22);
        v37 = rotr(v32, 5);
        v38 = v36 ^ (v33 << 7) ^ v35;
        v39 = v37 ^ v33 ^ v35;
        v40 = rotr(v35, 7);
        v41 = rotr(v33, 1);
        v42 = v38 ^ v40 ^ (8 * v39);
        v43 = v39 ^ v41 ^ v38;
        v44 = rotr(v38, 3);
        v45 = rotr(v39, 13);
        v46 = v43 & ~v44 ^ v42;
        v47 = v44 ^ ~v43 ^ v46 & v45;
        v48 = (v42 | v45) & v43;
        v49 = v46 & v45 | v45 ^ v44;
        v50 = v44 ^ ~readUInt32LE(this.buffer,(150 * 4) - 104) ^ (v42 | v45) ^ (v47 | v43);
        v51 = v46 ^  readUInt32LE(this.buffer,(151 * 4) - 104) ^ (v47 | v43) & v45;
        v52 = v47 ^  readUInt32LE(this.buffer,(153 * 4) - 104);
        v53 = rotr(v48 ^ readUInt32LE(this.buffer,(152 * 4) - 104) ^ v49, 22);
        v54 = rotr(v50, 5);
        v55 = v52 ^ v53 ^ (v51 << 7);
        v56 = v52 ^ v54 ^ v51;
        v57 = v55 ^ rotr(v52, 7) ^ (8 * v56);
        v58 = v56 ^ rotr(v51, 1) ^ v55;
        v59 = rotr(v55, 3);
        v60 = rotr(v56, 13);
        v61 = (v57 | v59) ^ v58;
        v62 = v57 | v58;
        v63 = v61 ^ (v57 ^ v60) & (v57 | v58);
        v64 = v61 & v60 | v59;
        v65 = v61 ^ readUInt32LE(this.buffer,(146 * 4) - 104) ^ (v63 ^ v59 | ~v60);
        v66 = readUInt32LE(this.buffer,(147 * 4) - 104) ^ v59 ^ v57 ^ v61 & v60;
        v67 = v63 ^ readUInt32LE(this.buffer,(149 * 4) - 104);
        v68 = rotr(v62 ^ readUInt32LE(this.buffer,(148 * 4) - 104) ^ v64 ^ (v63 | ~v60), 22);
        v69 = rotr(v65, 5);
        v70 = v67 ^ v68 ^ (v66 << 7);
        v71 = v67 ^ v69 ^ v66;
        v72 = v70 ^ rotr(v67, 7) ^ (8 * v71);
        v73 = v71 ^ rotr(v66, 1) ^ v70;
        v74 = rotr(v70, 3);
        v75 = rotr(v71, 13);
        v76 = (v73 | v74) ^ v75;
        v77 = v76 ^ v74;
        v78 = v76 ^ v72;
        v79 = (v77 | v72) ^ v73 ^ v74;
        v80 = (v77 | v72 | v73 ^ v74) ^ v78;
        v81 = (v80 & v75 ^ (v73 | v74)) & v79;
        v82 = v79 ^ readUInt32LE(this.buffer,(142 * 4) - 104);
        v83 = v77 & v75 ^ readUInt32LE(this.buffer,(143 * 4) - 104) ^ (v79 | v78);
        v84 = v77 ^ readUInt32LE(this.buffer,(145 * 4) - 104) ^ v81;
        v85 = rotr(v80 ^ readUInt32LE(this.buffer,(144 * 4) - 104), 22);
        v86 = rotr(v82, 5);
        v87 = v85 ^ (v83 << 7) ^ v84;
        v88 = v83 ^ v86 ^ v84;
        v89 = rotr(v84, 7);
        v90 = rotr(v83, 1);
        v91 = v87 ^ v89 ^ (8 * v88);
        v92 = v88 ^ v90 ^ v87;
        v93 = rotr(v87, 3);
        v94 = rotr(v88, 13);
        v95 = v94 ^ v93;
        v96 = v91 ^ v92 ^ v93;
        v97 = v96 & v92 ^ v94 ^ v93;
        v98 = v91 & ~v96;
        v99 = ((v94 | ~(v91 ^ v92)) ^ v91 | v94 ^ v93) ^ v91 ^ v92;
        v100 = v97 ^  readUInt32LE(this.buffer,(138 * 4) - 104);
        v101 = v96 ^ ~readUInt32LE(this.buffer,(139 * 4) - 104) ^ (v99 | v97);
        v102 = v99 ^  readUInt32LE(this.buffer,(141 * 4) - 104);
        v103 = rotr(  readUInt32LE(this.buffer,(140 * 4) - 104) ^ v95 ^ v98 ^ (v99 | v97), 22);
        v104 = rotr(v100, 5);
        v105 = v102 ^ v103 ^ (v101 << 7);
        v106 = v102 ^ v104 ^ v101;
        v107 = rotr(v102, 7);
        v108 = rotr(v101, 1);
        v109 = v105 ^ v107 ^ (8 * v106);
        v110 = v106 ^ v108 ^ v105;
        v111 = rotr(v105, 3);
        v112 = rotr(v106, 13);
        v113 = v112 ^ v111 ^ v110;
        v114 = v113 ^ (v109 | v110);
        v115 = ((v109 ^ v112 | v111) ^ v110) & v113;
        v116 = v115 ^ v110 & v112;
        v117 = v115 ^ v109 ^ v112;
        v118 = v116 ^ ~(readUInt32LE(this.buffer,(134 * 4) - 104) ^ v111 ^ v109 & v112);
        v119 = v117 ^   readUInt32LE(this.buffer,(135 * 4) - 104);
        v120 = v114 ^   readUInt32LE(this.buffer,(137 * 4) - 104);
        v121 = rotr(v116 ^ ~readUInt32LE(this.buffer,(136 * 4) - 104) ^ v117 & v114, 22);
        v122 = rotr(v118, 5);
        v123 = v120 ^ v121 ^ (v119 << 7);
        v124 = v120 ^ v122 ^ v119;
        v125 = rotr(v120, 7);
        v126 = rotr(v119, 1);
        v127 = v123 ^ v125 ^ (8 * v124);
        v128 = rotr(v123, 3);
        v129 = rotr(v124, 13);
        v130 = v129 ^ v126 ^ v124 ^ v123;
        v131 = (v130 | ~v129) ^ v127;
        v132 = v131 ^ v128;
        v133 = v129 ^ ~(v130 & v127);
        v134 = v131 ^ v128 ^ v130;
        v135 = v131 & v129;
        v136 = v134 & v133 ^ v131;
        v137 = (v136 | v132) ^ v135;
        v138 = v133 ^ readUInt32LE(this.buffer,(130 * 4) - 104) ^ v132 ^ v137;
        v139 = v136 ^ readUInt32LE(this.buffer,(131 * 4) - 104);
        v140 = v137 ^ readUInt32LE(this.buffer,(133 * 4) - 104);
        v141 = rotr(v134 ^ readUInt32LE(this.buffer,(132 * 4) - 104), 22);
        v142 = rotr(v138, 5);
        v143 = v141 ^ (v139 << 7) ^ v140;
        v144 = v139 ^ v142 ^ v140;
        v145 = rotr(v140, 7);
        v146 = rotr(v139, 1);
        v147 = v143 ^ v145 ^ (8 * v144);
        v148 = v144 ^ v146 ^ v143;
        v149 = rotr(v143, 3);
        v150 = rotr(v144, 13);
        v151 = v148 & v150 | v149;
        v152 = (v148 | v150) & v147;
        v153 = v152 ^ v151;
        v154 = v152 ^ v148;
        v155 = v154 ^ v149;
        v156 = (v154 | ~(v153 ^ v147)) ^ v150;
        v157 = v155 ^ (v156 | v147);
        v158 = v157 ^ readUInt32LE(this.buffer,(126 * 4) - 104);
        v159 = v156 ^ readUInt32LE(this.buffer,(127 * 4) - 104);
        v160 = v153 ^ readUInt32LE(this.buffer,(129 * 4) - 104);
        v161 = rotr(v151 ^ readUInt32LE(this.buffer,(128 * 4) - 104) ^ v153 & v150 ^ v156 ^ v157, 22);
        v162 = rotr(v158, 5);
        v163 = v160 ^ v161 ^ (v159 << 7);
        v164 = v160 ^ v162 ^ v159;
        v165 = rotr(v160, 7);
        v166 = rotr(v159, 1);
        v167 = v163 ^ v165 ^ (8 * v164);
        v168 = v164 ^ v166 ^ v163;
        v169 = rotr(v163, 3);
        v170 = rotr(v164, 13);
        v171 = v168 ^ v170 ^ v169;
        v172 = v167 ^ (v169 | ~v170);
        v173 = v167 & ~v170;
        v174 = v171 & v172 ^ v168 ^ v170;
        v175 = (v174 | v168) ^ v172;
        v176 = v174 ^ readUInt32LE(this.buffer,(122 * 4) - 104) ^ (v175 | v168);
        v177 = v172 ^ readUInt32LE(this.buffer,(123 * 4) - 104) ^ v171;
        v178 = v173 ^ readUInt32LE(this.buffer,(124 * 4) - 104) ^ v171 ^ (v175 | v168);
        v179 = v175 ^ readUInt32LE(this.buffer,(125 * 4) - 104);
        v180 = rotr(v178, 22);
        v181 = rotr(v176, 5);
        v182 = v180 ^ (v177 << 7) ^ v179;
        v183 = v177 ^ v181 ^ v179;
        v184 = rotr(v179, 7);
        v185 = rotr(v177, 1);
        v186 = v182 ^ v184 ^ (8 * v183);
        v187 = v183 ^ v185 ^ v182;
        v188 = rotr(v182, 3);
        v189 = rotr(v183, 13);
        v190 = v187 & ~v188 ^ v186;
        v191 = v188 ^ ~v187 ^ v190 & v189;
        v192 = (v186 | v189) & v187;
        v193 = v190 & v189 | v189 ^ v188;
        v194 = v188 ^ ~readUInt32LE(this.buffer,(118 * 4) - 104) ^ (v186 | v189) ^ (v191 | v187);
        v195 = v190 ^  readUInt32LE(this.buffer,(119 * 4) - 104) ^ (v191 | v187) & v189;
        v196 = v191 ^  readUInt32LE(this.buffer,(121 * 4) - 104);
        v197 = rotr(v192 ^ readUInt32LE(this.buffer,(120 * 4) - 104) ^ v193, 22);
        v198 = rotr(v194, 5);
        v199 = v196 ^ v197 ^ (v195 << 7);
        v200 = v196 ^ v198 ^ v195;
        v201 = v199 ^ rotr(v196, 7) ^ (8 * v200);
        v202 = v200 ^ rotr(v195, 1) ^ v199;
        v203 = rotr(v199, 3);
        v204 = rotr(v200, 13);
        v205 = (v201 | v203) ^ v202;
        v206 = v201 | v202;
        v207 = v205 ^ (v201 ^ v204) & (v201 | v202);
        v208 = v205 & v204 | v203;
        v209 = v205 ^ readUInt32LE(this.buffer,(114 * 4) - 104) ^ (v207 ^ v203 | ~v204);
        v210 = readUInt32LE(this.buffer,(115 * 4) - 104) ^ v203 ^ v201 ^ v205 & v204;
        v211 = v207 ^ readUInt32LE(this.buffer,(117 * 4) - 104);
        v212 = rotr(v206 ^ readUInt32LE(this.buffer,(116 * 4) - 104) ^ v208 ^ (v207 | ~v204), 22);
        v213 = rotr(v209, 5);
        v214 = v211 ^ v212 ^ (v210 << 7);
        v215 = v211 ^ v213 ^ v210;
        v216 = v214 ^ rotr(v211, 7) ^ (8 * v215);
        v217 = v215 ^ rotr(v210, 1) ^ v214;
        v218 = rotr(v214, 3);
        v219 = rotr(v215, 13);
        v220 = (v217 | v218) ^ v219;
        v221 = v220 ^ v218;
        v222 = v220 ^ v216;
        v223 = (v221 | v216) ^ v217 ^ v218;
        v224 = (v221 | v216 | v217 ^ v218) ^ v222;
        v225 = (v224 & v219 ^ (v217 | v218)) & v223;
        v226 = v223 ^ readUInt32LE(this.buffer,(110 * 4) - 104);
        v227 = v221 & v219 ^ readUInt32LE(this.buffer,(111 * 4) - 104) ^ (v223 | v222);
        v228 = v221 ^ readUInt32LE(this.buffer,(113 * 4) - 104) ^ v225;
        v229 = rotr(v224 ^ readUInt32LE(this.buffer,(112 * 4) - 104), 22);
        v230 = rotr(v226, 5);
        v231 = v229 ^ (v227 << 7) ^ v228;
        v232 = v227 ^ v230 ^ v228;
        v233 = rotr(v228, 7);
        v234 = rotr(v227, 1);
        v235 = v231 ^ v233 ^ (8 * v232);
        v236 = v232 ^ v234 ^ v231;
        v237 = rotr(v231, 3);
        v238 = rotr(v232, 13);
        v239 = v238 ^ v237;
        v240 = v235 ^ v236 ^ v237;
        v241 = v240 & v236 ^ v238 ^ v237;
        v242 = v235 & ~v240;
        v243 = ((v238 | ~(v235 ^ v236)) ^ v235 | v238 ^ v237) ^ v235 ^ v236;
        v244 = v241 ^  readUInt32LE(this.buffer,(106 * 4) - 104);
        v245 = v240 ^ ~readUInt32LE(this.buffer,(107 * 4) - 104) ^ (v243 | v241);
        v246 = v243 ^  readUInt32LE(this.buffer,(109 * 4) - 104);
        v247 = rotr(readUInt32LE(this.buffer,(108 * 4) - 104) ^ v239 ^ v242 ^ (v243 | v241), 22);
        v248 = rotr(v244, 5);
        v249 = v246 ^ v247 ^ (v245 << 7);
        v250 = v246 ^ v248 ^ v245;
        v251 = rotr(v246, 7);
        v252 = rotr(v245, 1);
        v253 = v249 ^ v251 ^ (8 * v250);
        v254 = v250 ^ v252 ^ v249;
        v255 = rotr(v249, 3);
        v256 = rotr(v250, 13);
        v257 = v256 ^ v255 ^ v254;
        v258 = v257 ^ (v253 | v254);
        v259 = ((v253 ^ v256 | v255) ^ v254) & v257;
        v260 = v259 ^ v254 & v256;
        v261 = v259 ^ v253 ^ v256;
        v262 = v260 ^ ~(readUInt32LE(this.buffer,(102 * 4) - 104) ^ v255 ^ v253 & v256);
        v263 = v261 ^ readUInt32LE(this.buffer,(103 * 4) - 104);
        v264 = v258 ^ readUInt32LE(this.buffer,(105 * 4) - 104);
        v265 = rotr(v260 ^ ~readUInt32LE(this.buffer,(104 * 4) - 104) ^ v261 & v258, 22);
        v266 = rotr(v262, 5);
        v267 = v264 ^ v265 ^ (v263 << 7);
        v268 = v264 ^ v266 ^ v263;
        v269 = rotr(v264, 7);
        v270 = rotr(v263, 1);
        v271 = v267 ^ v269 ^ (8 * v268);
        v272 = rotr(v267, 3);
        v273 = rotr(v268, 13);
        v274 = v273 ^ v270 ^ v268 ^ v267;
        v275 = (v274 | ~v273) ^ v271;
        v276 = v275 ^ v272;
        v277 = v273 ^ ~(v274 & v271);
        v278 = v275 ^ v272 ^ v274;
        v279 = v275 & v273;
        v280 = v278 & v277 ^ v275;
        v281 = (v280 | v276) ^ v279;
        v282 = v277 ^ readUInt32LE(this.buffer,(98 * 4) - 104) ^ v276 ^ v281;
        v283 = v280 ^ readUInt32LE(this.buffer,(99 * 4) - 104);
        v284 = v281 ^ readUInt32LE(this.buffer,(101 * 4) - 104);
        v285 = rotr(v278 ^ readUInt32LE(this.buffer,(100 * 4) - 104), 22);
        v286 = rotr(v282, 5);
        v287 = v285 ^ (v283 << 7) ^ v284;
        v288 = v283 ^ v286 ^ v284;
        v289 = rotr(v284, 7);
        v290 = rotr(v283, 1);
        v291 = v287 ^ v289 ^ (8 * v288);
        v292 = v288 ^ v290 ^ v287;
        v293 = rotr(v287, 3);
        v294 = rotr(v288, 13);
        v295 = v292 & v294 | v293;
        v296 = (v292 | v294) & v291;
        v297 = v296 ^ v295;
        v298 = v296 ^ v292;
        v299 = v298 ^ v293;
        v300 = (v298 | ~(v297 ^ v291)) ^ v294;
        v301 = v299 ^ (v300 | v291);
        v302 = v301 ^ readUInt32LE(this.buffer,(94 * 4) - 104);
        v303 = v300 ^ readUInt32LE(this.buffer,(95 * 4) - 104);
        v304 = v297 ^ readUInt32LE(this.buffer,(97 * 4) - 104);
        v305 = rotr(v295 ^ readUInt32LE(this.buffer,(96 * 4) - 104) ^ v297 & v294 ^ v300 ^ v301, 22);
        v306 = rotr(v302, 5);
        v307 = v304 ^ v305 ^ (v303 << 7);
        v308 = v304 ^ v306 ^ v303;
        v309 = rotr(v304, 7);
        v310 = rotr(v303, 1);
        v311 = v307 ^ v309 ^ (8 * v308);
        v312 = v308 ^ v310 ^ v307;
        v313 = rotr(v307, 3);
        v314 = rotr(v308, 13);
        v315 = v312 ^ v314 ^ v313;
        v316 = v311 ^ (v313 | ~v314);
        v317 = v311 & ~v314;
        v318 = v315 & v316 ^ v312 ^ v314;
        v319 = (v318 | v312) ^ v316;
        v320 = v318 ^ readUInt32LE(this.buffer,(90 * 4) - 104) ^ (v319 | v312);
        v321 = v316 ^ readUInt32LE(this.buffer,(91 * 4) - 104) ^ v315;
        v322 = v317 ^ readUInt32LE(this.buffer,(92 * 4) - 104) ^ v315 ^ (v319 | v312);
        v323 = v319 ^ readUInt32LE(this.buffer,(93 * 4) - 104);
        v324 = rotr(v322, 22);
        v325 = rotr(v320, 5);
        v326 = v324 ^ (v321 << 7) ^ v323;
        v327 = v321 ^ v325 ^ v323;
        v328 = rotr(v323, 7);
        v329 = rotr(v321, 1);
        v330 = v326 ^ v328 ^ (8 * v327);
        v331 = v327 ^ v329 ^ v326;
        v332 = rotr(v326, 3);
        v333 = rotr(v327, 13);
        v334 = v331 & ~v332 ^ v330;
        v335 = v332 ^ ~v331 ^ v334 & v333;
        v336 = (v330 | v333) & v331;
        v337 = v334 & v333 | v333 ^ v332;
        v338 = v332 ^ ~readUInt32LE(this.buffer,(86 * 4) - 104) ^ (v330 | v333) ^ (v335 | v331);
        v339 = v334 ^  readUInt32LE(this.buffer,(87 * 4) - 104) ^ (v335 | v331) & v333;
        v340 = v335 ^  readUInt32LE(this.buffer,(89 * 4) - 104);
        v341 = rotr(v336 ^ readUInt32LE(this.buffer,(88 * 4) - 104) ^ v337, 22);
        v342 = rotr(v338, 5);
        v343 = v340 ^ v341 ^ (v339 << 7);
        v344 = v340 ^ v342 ^ v339;
        v345 = v343 ^ rotr(v340, 7) ^ (8 * v344);
        v346 = v344 ^ rotr(v339, 1) ^ v343;
        v347 = rotr(v343, 3);
        v348 = rotr(v344, 13);
        v349 = (v345 | v347) ^ v346;
        v350 = v345 | v346;
        v351 = v349 ^ (v345 ^ v348) & (v345 | v346);
        v352 = v349 & v348 | v347;
        v353 = v349 ^ readUInt32LE(this.buffer,(82 * 4) - 104) ^ (v351 ^ v347 | ~v348);
        v354 = readUInt32LE(this.buffer,(83 * 4) - 104) ^ v347 ^ v345 ^ v349 & v348;
        v355 = v351 ^ readUInt32LE(this.buffer,(85 * 4) - 104);
        v356 = rotr(v350 ^ readUInt32LE(this.buffer,(84 * 4) - 104) ^ v352 ^ (v351 | ~v348), 22);
        v357 = rotr(v353, 5);
        v358 = v355 ^ v356 ^ (v354 << 7);
        v359 = v355 ^ v357 ^ v354;
        v360 = v358 ^ rotr(v355, 7) ^ (8 * v359);
        v361 = v359 ^ rotr(v354, 1) ^ v358;
        v362 = rotr(v358, 3);
        v363 = rotr(v359, 13);
        v364 = (v361 | v362) ^ v363;
        v365 = v364 ^ v362;
        v366 = v364 ^ v360;
        v367 = (v365 | v360) ^ v361 ^ v362;
        v368 = (v365 | v360 | v361 ^ v362) ^ v366;
        v369 = (v368 & v363 ^ (v361 | v362)) & v367;
        v370 = v367 ^ readUInt32LE(this.buffer,(78 * 4) - 104);
        v371 = v365 & v363 ^ readUInt32LE(this.buffer,(79 * 4) - 104) ^ (v367 | v366);
        v372 = v365 ^ readUInt32LE(this.buffer,(81 * 4) - 104) ^ v369;
        v373 = rotr(v368 ^ readUInt32LE(this.buffer,(80 * 4) - 104), 22);
        v374 = rotr(v370, 5);
        v375 = v373 ^ (v371 << 7) ^ v372;
        v376 = v371 ^ v374 ^ v372;
        v377 = rotr(v372, 7);
        v378 = rotr(v371, 1);
        v379 = v375 ^ v377 ^ (8 * v376);
        v380 = v376 ^ v378 ^ v375;
        v381 = rotr(v375, 3);
        v382 = rotr(v376, 13);
        v383 = v382 ^ v381;
        v384 = v379 ^ v380 ^ v381;
        v385 = v384 & v380 ^ v382 ^ v381;
        v386 = v379 & ~v384;
        v387 = ((v382 | ~(v379 ^ v380)) ^ v379 | v382 ^ v381) ^ v379 ^ v380;
        v388 = v385 ^  readUInt32LE(this.buffer,(74 * 4) - 104);
        v389 = v384 ^ ~readUInt32LE(this.buffer,(75 * 4) - 104) ^ (v387 | v385);
        v390 = v387 ^  readUInt32LE(this.buffer,(77 * 4) - 104);
        v391 = rotr(readUInt32LE(this.buffer,(76 * 4) - 104) ^ v383 ^ v386 ^ (v387 | v385), 22);
        v392 = rotr(v388, 5);
        v393 = v390 ^ v391 ^ (v389 << 7);
        v394 = v390 ^ v392 ^ v389;
        v395 = rotr(v390, 7);
        v396 = rotr(v389, 1);
        v397 = v393 ^ v395 ^ (8 * v394);
        v398 = v394 ^ v396 ^ v393;
        v399 = rotr(v393, 3);
        v400 = rotr(v394, 13);
        v401 = v400 ^ v399 ^ v398;
        v402 = v401 ^ (v397 | v398);
        v403 = ((v397 ^ v400 | v399) ^ v398) & v401;
        v404 = v403 ^ v398 & v400;
        v405 = v403 ^ v397 ^ v400;
        v406 = v404 ^ ~(readUInt32LE(this.buffer,(70 * 4) - 104) ^ v399 ^ v397 & v400);
        v407 = v405 ^ readUInt32LE(this.buffer,(71 * 4) - 104);
        v408 = v402 ^ readUInt32LE(this.buffer,(73 * 4) - 104);
        v409 = rotr(v404 ^ ~readUInt32LE(this.buffer,(72 * 4) - 104) ^ v405 & v402, 22);
        v410 = rotr(v406, 5);
        v411 = v408 ^ v409 ^ (v407 << 7);
        v412 = v408 ^ v410 ^ v407;
        v413 = rotr(v408, 7);
        v414 = rotr(v407, 1);
        v415 = v411 ^ v413 ^ (8 * v412);
        v416 = rotr(v411, 3);
        v417 = rotr(v412, 13);
        v418 = v417 ^ v414 ^ v412 ^ v411;
        v419 = (v418 | ~v417) ^ v415;
        v420 = v419 ^ v416;
        v421 = v417 ^ ~(v418 & v415);
        v422 = v419 ^ v416 ^ v418;
        v423 = v419 & v417;
        v424 = v422 & v421 ^ v419;
        v425 = (v424 | v420) ^ v423;
        v426 = v421 ^ readUInt32LE(this.buffer,(66 * 4) - 104) ^ v420 ^ v425;
        v427 = v424 ^ readUInt32LE(this.buffer,(67 * 4) - 104);
        v428 = v425 ^ readUInt32LE(this.buffer,(69 * 4) - 104);
        v429 = rotr(v422 ^ readUInt32LE(this.buffer,(68 * 4) - 104), 22);
        v430 = rotr(v426, 5);
        v431 = v429 ^ (v427 << 7) ^ v428;
        v432 = v427 ^ v430 ^ v428;
        v433 = rotr(v428, 7);
        v434 = rotr(v427, 1);
        v435 = v431 ^ v433 ^ (8 * v432);
        v436 = v432 ^ v434 ^ v431;
        v437 = rotr(v431, 3);
        v438 = rotr(v432, 13);
        v439 = v436 & v438 | v437;
        v440 = (v436 | v438) & v435;
        v441 = v440 ^ v439;
        v442 = v440 ^ v436;
        v443 = v442 ^ v437;
        v444 = (v442 | ~(v441 ^ v435)) ^ v438;
        v445 = v443 ^ (v444 | v435);
        v446 = v445 ^ readUInt32LE(this.buffer,(62 * 4) - 104);
        v447 = v444 ^ readUInt32LE(this.buffer,(63 * 4) - 104);
        v448 = v441 ^ readUInt32LE(this.buffer,(65 * 4) - 104);
        v449 = rotr(v439 ^ readUInt32LE(this.buffer,(64 * 4) - 104) ^ v441 & v438 ^ v444 ^ v445, 22);
        v450 = rotr(v446, 5);
        v451 = v448 ^ v449 ^ (v447 << 7);
        v452 = v448 ^ v450 ^ v447;
        v453 = rotr(v448, 7);
        v454 = rotr(v447, 1);
        v455 = v451 ^ v453 ^ (8 * v452);
        v456 = v452 ^ v454 ^ v451;
        v457 = rotr(v451, 3);
        v458 = rotr(v452, 13);
        v459 = v456 ^ v458 ^ v457;
        v460 = v455 ^ (v457 | ~v458);
        v461 = v459 & v460 ^ v456 ^ v458;
        v462 = (v461 | v456) ^ v460;
        v463 = v455 & ~v458 ^ readUInt32LE(this.buffer,(60 * 4) - 104);
        v464 = v461 ^ readUInt32LE(this.buffer,(58 * 4) - 104) ^ (v462 | v456);
        v465 = v460 ^ readUInt32LE(this.buffer,(59 * 4) - 104) ^ v459;
        v466 = v463 ^ v459 ^ (v462 | v456);
        v467 = v462 ^ readUInt32LE(this.buffer,(61 * 4) - 104);
        v468 = rotr(v466, 22);
        v469 = rotr(v464, 5);
        v470 = v468 ^ (v465 << 7) ^ v467;
        v471 = v465 ^ v469 ^ v467;
        v472 = rotr(v467, 7);
        v473 = rotr(v465, 1);
        v474 = v470 ^ v472 ^ (8 * v471);
        v475 = v471 ^ v473 ^ v470;
        v476 = rotr(v470, 3);
        v477 = rotr(v471, 13);
        v478 = v475 & ~v476 ^ v474;
        v479 = v476 ^ ~v475 ^ v478 & v477;
        v480 = v478 & v477 | v477 ^ v476;
        v481 = (v474 | v477) & v475;
        v482 = v476 ^ ~readUInt32LE(this.buffer,(54 * 4) - 104) ^ (v474 | v477) ^ (v479 | v475);
        v483 = v478 ^  readUInt32LE(this.buffer,(55 * 4) - 104) ^ (v479 | v475) & v477;
        v484 = v479 ^  readUInt32LE(this.buffer,(57 * 4) - 104);
        v485 = rotr(v481 ^ readUInt32LE(this.buffer,(56 * 4) - 104) ^ v480, 22);
        v486 = rotr(v482, 5);
        v487 = v484 ^ v485 ^ (v483 << 7);
        v488 = v484 ^ v486 ^ v483;
        v489 = v487 ^ rotr(v484, 7) ^ (8 * v488);
        v490 = v488 ^ rotr(v483, 1) ^ v487;
        v491 = rotr(v487, 3);
        v492 = rotr(v488, 13);
        v493 = (v489 | v491) ^ v490;
        v494 = v489 | v490;
        v495 = v493 ^ (v489 ^ v492) & (v489 | v490);
        v496 = v493 & v492 | v491;
        v497 = v493 ^ readUInt32LE(this.buffer,(50 * 4) - 104) ^ (v495 ^ v491 | ~v492);
        v498 = readUInt32LE(this.buffer,(51 * 4) - 104) ^ v491 ^ v489 ^ v493 & v492;
        v499 = v495 ^ readUInt32LE(this.buffer,(53 * 4) - 104);
        v500 = rotr(v494 ^ readUInt32LE(this.buffer,(52 * 4) - 104) ^ v496 ^ (v495 | ~v492), 22);
        v501 = rotr(v497, 5);
        v502 = v499 ^ v500 ^ (v498 << 7);
        v503 = v499 ^ v501 ^ v498;
        v504 = v502 ^ rotr(v499, 7) ^ (8 * v503);
        v505 = v503 ^ rotr(v498, 1) ^ v502;
        v506 = rotr(v502, 3);
        v507 = rotr(v503, 13);
        v508 = (v505 | v506) ^ v507;
        v509 = v508 ^ v506;
        v510 = v508 ^ v504;
        v511 = (v509 | v504) ^ v505 ^ v506;
        v512 = (v509 | v504 | v505 ^ v506) ^ v510;
        v513 = (v512 & v507 ^ (v505 | v506)) & v511;
        v514 = v511 ^ readUInt32LE(this.buffer,(46 * 4) - 104);
        v515 = v509 & v507 ^ readUInt32LE(this.buffer,(47 * 4) - 104) ^ (v511 | v510);
        v516 = v509 ^ readUInt32LE(this.buffer,(49 * 4) - 104) ^ v513;
        v517 = rotr(v512 ^ readUInt32LE(this.buffer,(48 * 4) - 104), 22);
        v518 = rotr(v514, 5);
        v519 = v517 ^ (v515 << 7) ^ v516;
        v520 = v515 ^ v518 ^ v516;
        v521 = rotr(v516, 7);
        v522 = rotr(v515, 1);
        v523 = v519 ^ v521 ^ (8 * v520);
        v524 = v520 ^ v522 ^ v519;
        v525 = rotr(v519, 3);
        v526 = rotr(v520, 13);
        v527 = v523 ^ v524 ^ v525;
        v528 = v527 & v524 ^ v526 ^ v525;
        v529 = v523 & ~v527;
        v530 = ((v526 | ~(v523 ^ v524)) ^ v523 | v526 ^ v525) ^ v523 ^ v524;
        v531 = readUInt32LE(this.buffer,(44 * 4) - 104) ^ v526 ^ v525;
        v532 = v528 ^  readUInt32LE(this.buffer,(42 * 4) - 104);
        v533 = v527 ^ ~readUInt32LE(this.buffer,(43 * 4) - 104) ^ (v530 | v528);
        v534 = v530 ^  readUInt32LE(this.buffer,(45 * 4) - 104);
        v535 = rotr(v531 ^ v529 ^ (v530 | v528), 22);
        v536 = rotr(v532, 5);
        v537 = v534 ^ v535 ^ (v533 << 7);
        v538 = v534 ^ v536 ^ v533;
        v539 = rotr(v534, 7);
        v540 = rotr(v533, 1);
        v541 = v537 ^ v539 ^ (8 * v538);
        v542 = v538 ^ v540 ^ v537;
        v543 = rotr(v537, 3);
        v544 = rotr(v538, 13);
        v545 = v544 ^ v543 ^ v542;
        v546 = v545 ^ (v541 | v542);
        v547 = ((v541 ^ v544 | v543) ^ v542) & v545;
        v548 = v547 ^ v542 & v544;
        v549 = v547 ^ v541 ^ v544;
        v550 = v548 ^ ~(readUInt32LE(this.buffer,(38 * 4) - 104) ^ v543 ^ v541 & v544);
        v551 = v549 ^ readUInt32LE(this.buffer,(39 * 4) - 104);
        v552 = v546 ^ readUInt32LE(this.buffer,(41 * 4) - 104);
        v553 = rotr(v548 ^ ~readUInt32LE(this.buffer,(40 * 4) - 104) ^ v549 & v546, 22);
        v554 = rotr(v550, 5);
        v555 = v552 ^ v553 ^ (v551 << 7);
        v556 = v552 ^ v554 ^ v551;
        v557 = rotr(v552, 7);
        v558 = rotr(v551, 1);
        v559 = v555 ^ v557 ^ (8 * v556);
        v560 = rotr(v555, 3);
        resu = rotr(v556, 13);
        v562 = resu ^ v558 ^ v556 ^ v555;
        v563 = (v562 | ~resu) ^ v559;
        v564 = v563 ^ v560;
        v565 = resu ^ ~(v562 & v559);
        v566 = v563 ^ v560 ^ v562;
        v567 = v563 & resu;
        v568 = v566 & v565 ^ v563;
        v569 = (v568 | v564) ^ v567;
        let v570 = v565 ^ readUInt32LE(this.buffer,(34 * 4) - 104) ^ v564 ^ v569;
        let v571 = v568 ^ readUInt32LE(this.buffer,(35 * 4) - 104);
        let v572 = v566 ^ readUInt32LE(this.buffer,(36 * 4) - 104);
        let v573 = v569 ^ readUInt32LE(this.buffer,(37 * 4) - 104);
        var out_blk:Buffer|Uint8Array;
        if (isBuffer(block)) {
            out_blk = Buffer.alloc(16);
        } else {
            out_blk = new Uint8Array(16);
        } 
        writeUInt32LE(out_blk, v570 >>> 0, 0)
        writeUInt32LE(out_blk, v571 >>> 0, 4)
        writeUInt32LE(out_blk, v572 >>> 0, 8);
        writeUInt32LE(out_blk, v573 >>> 0, 12);
        var return_buffer = out_blk
        if (this.iv_set == true) {
            return_buffer = xor(out_blk, this.iv)
        }
        return return_buffer
    }

    /**
     *
     * If IV is not set, runs in ECB mode.
     * If IV was set, runs in CBC mode.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @param {Number} padd - ```Number```
     * @returns ```Buffer``` or ```Uint8Array```
     */
    encrypt (data_in:Buffer|Uint8Array, padd?:number):Buffer|Uint8Array {
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
                var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
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
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.decrypt_block(block);
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
