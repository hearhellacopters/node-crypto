/// <reference types="node" />
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
export declare class ARIA {
    key: any;
    key_set: boolean;
    iv: any;
    iv_set: boolean;
    private previous_block;
    private C1;
    private C2;
    private C3;
    private SB1;
    private SB2;
    private SB3;
    private SB4;
    private mEK;
    private mDK;
    private mNumberRounds;
    private mKeyLength;
    constructor();
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer|Uint8Array} key - ```Buffer``` or ```Uint8Array```
     */
    set_key(key: Buffer | Uint8Array): void;
    /**
     * IV for CBC encryption.
     *
     * Must be same length as key!
     *
     * @param {Buffer|Uint8Array} iv - ```Buffer``` or ```Uint8Array```
     */
    set_iv(iv: Buffer | Uint8Array): void;
    C1_$LI$(): any;
    C2_$LI$(): any;
    C3_$LI$(): any;
    SB1_$LI$(): any;
    SB2_$LI$(): any;
    SB3_$LI$(): any;
    SB4_$LI$(): any;
    XOR(x: Uint8Array, y: Uint8Array): Uint8Array;
    ROL(array: Uint8Array, nShift: number): Uint8Array;
    ROR(array: Uint8Array, nShift: number): Uint8Array;
    unsigned(b: number): number;
    private SL1;
    private SL2;
    private FO;
    private FE;
    private A;
    private scheduleKey;
    private encrypt_block;
    private decrypt_block;
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
//# sourceMappingURL=ARIA.d.ts.map