/// <reference types="node" />
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
export declare class CHACHA20 {
    key: any;
    key_set: boolean;
    iv: any;
    iv_set: boolean;
    private previous_block;
    constructor();
    private matrix;
    private littleEndianToInt;
    private intToLittleEndian;
    private ROTATE;
    private quarterRound;
    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     *
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv: Buffer | Uint8Array): void;
    /**
     * Key for encryption.
     *
     * Key must be 32 bytes!
     * Nonce must be 12 bytes!
     *
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     * @param {Buffer|Uint8Array} nonce - ```Buffer``` or ```Uint8Array```
     */
    set_key(key: Buffer | Uint8Array, nonce: Buffer | Uint8Array): void;
    private decrypt_block;
    private encrypt_block;
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
    encrypt(data_in: Buffer | Uint8Array, padding?: number): Buffer | Uint8Array;
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
    decrypt(data_in: Buffer | Uint8Array, remove_padding?: boolean | number): Buffer | Uint8Array;
}
//# sourceMappingURL=CHACHA20.d.ts.map