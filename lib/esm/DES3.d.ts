/// <reference types="node" />
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
export declare class DES3 {
    key: any;
    key_set: boolean;
    iv: any;
    iv_set: boolean;
    private previous_block;
    constructor();
    private ROUNDS;
    private KEY_LENGTH;
    private sKey;
    private INTERNAL_KEY_LENGTH;
    private SKB;
    private SP_TRANS;
    private s;
    private __static_initializer_0;
    /**
     * Key for encryption.
     *
     * Key must be 8 bytes!
     *
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     */
    set_key(key: Buffer | Uint8Array): void;
    /**
     * IV for CBC encryption.
     *
     * Must be 8 bytes!
     *
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv: Buffer | Uint8Array): void;
    private initialPermutation;
    private run_block;
    private encrypt_base;
    private decrypt_base;
    private finalPermutation;
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
//# sourceMappingURL=DES3.d.ts.map