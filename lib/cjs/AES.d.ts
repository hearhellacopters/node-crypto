/// <reference types="node" />
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
export declare class AES {
    key: any;
    key_set: boolean;
    iv: any;
    iv_set: boolean;
    private previous_block;
    AES_SubBytes(state: Array<number>, sbox: Array<number>): void;
    AES_AddRoundKey(state: Array<number>, rkey: Array<number>): void;
    AES_ShiftRows(state: Array<number>, shifttab: Array<number>): void;
    AES_MixColumns(state: Array<number>): void;
    AES_MixColumns_Inv(state: Array<number>): void;
    private AES_Sbox;
    private AES_ShiftRowTab;
    private AES_Sbox_Inv;
    private AES_xtime;
    private AES_ShiftRowTab_Inv;
    constructor();
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer|Uint8Array} key_data - ```Buffer``` or ```Uint8Array```
     */
    set_key(key_data: Buffer | Uint8Array): void;
    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     *
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv: Buffer | Uint8Array): void;
    encrypt_block(start_chunk: Buffer | Uint8Array): Buffer | Uint8Array;
    decrypt_block(start_chunk: Buffer | Uint8Array): Buffer | Uint8Array;
    /**
     *
     * If IV is not set, runs in ECB mode.
     * If IV was set, runs in CBC mode.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @param {number} padd - ```number```
     * @returns ```Buffer``` or ```Uint8Array```
     */
    encrypt(data_in: Buffer | Uint8Array, padd: number): Buffer | Uint8Array;
    /**
     *
     * If IV is not set, runs in ECB mode.
     * If IV was set, runs in CBC mode.
     *
     * @param {Buffer|Uint8Array} data_in - ```Buffer``` or ```Uint8Array```
     * @returns ```Buffer``` or ```Uint8Array```
     */
    decrypt(data_in: Buffer | Uint8Array): Buffer | Uint8Array;
}
//# sourceMappingURL=AES.d.ts.map