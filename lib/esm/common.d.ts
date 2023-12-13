/// <reference types="node" />
export declare function isBufferOrUint8Array(obj: any): boolean;
export declare function isBuffer(obj: any): boolean;
export declare function extendUint8Array(array: Uint8Array, newLength: number, padValue: number): Uint8Array;
export declare function concatenateUint8Arrays(arrays: Uint8Array[]): Uint8Array;
export declare function xor(buf1: Uint8Array | Buffer, buf2: Uint8Array | Buffer): Uint8Array | Buffer;
export declare function readUInt32LE(array: Uint8Array | Buffer, index: number): number;
export declare function readUInt32BE(array: Uint8Array | Buffer, index: number): number;
export declare function readUInt16LE(array: Uint8Array | Buffer, index: number): number;
export declare function writeUInt16LE(array: Uint8Array | Buffer, value: number, offset: number): void;
export declare const readUInt16BE: (array: Uint8Array | Buffer, index: number) => number;
export declare function writeUInt16BE(array: Uint8Array | Buffer, value: number, offset: number): void;
export declare function writeUInt32LE(array: Uint8Array | Buffer, value: number, index: number): void;
export declare function writeUInt32BE(array: Uint8Array | Buffer, value: number, index: number): void;
export declare function bswap64(x: Uint8Array | Buffer): Uint8Array | Buffer;
export declare function reverse64(x: Uint8Array | Buffer): Uint8Array | Buffer;
export declare function xor_switch(x: Uint8Array | Buffer, hex2: Uint8Array | Buffer): Uint8Array | Buffer;
/**
 * for number not array
 * @param value - number
 * @returns
 */
export declare function bswap32(value: number): number;
export declare function HIBYTE(x: number): number;
export declare function BYTE2(x: number): number;
export declare function BYTE1(x: number): number;
export declare function BYTE(x: number): number;
export declare function rotl(value: number, shift: number): number;
export declare function rotr(value: number, shift: number): number;
export declare function __PAIR64__(high: number, low: number, x: number): number;
export declare function align(a: number, n: number): number;
export declare function removePKCSPadding(buffer: Uint8Array | Buffer, blockSize: number, number?: number): Uint8Array | Buffer;
//# sourceMappingURL=common.d.ts.map