export function isBufferOrUint8Array(obj: any): boolean {
    return obj instanceof Uint8Array || (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}

export function isBuffer(obj: any): boolean {
    return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}

export function extendUint8Array(array: Uint8Array, newLength: number, padValue: number): Uint8Array {
    const newArray = new Uint8Array(newLength);
    newArray.set(array);

    for (let i = array.length; i < newLength; i++) {
        newArray[i] = padValue;
    }

    return newArray;
}

export function concatenateUint8Arrays(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((length, array) => length + array.length, 0);
    const concatenatedArray = new Uint8Array(totalLength);
    let offset = 0;

    for (let i = 0; i < arrays.length; i++) {
        concatenatedArray.set(arrays[i], offset);
        offset += arrays[i].length;
    }

    return concatenatedArray;
}

export function xor(buf1: Uint8Array | Buffer, buf2: Uint8Array | Buffer): Uint8Array | Buffer {
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

export function readUInt32LE(array: Uint8Array | Buffer, index: number): number {
    return (((array[index + 3] & 0xFF) << 24) |
        ((array[index + 2] & 0xFF) << 16) |
        ((array[index + 1] & 0xFF) << 8) |
        (array[index] & 0xFF)
    ) >>> 0;
}

export function readUInt32BE(array: Uint8Array | Buffer, index: number): number {
    return (((array[index] & 0xFF) << 24) |
        ((array[index + 1] & 0xFF) << 16) |
        ((array[index + 2] & 0xFF) << 8) |
        (array[index + 3] & 0xFF)
    ) >>> 0;
}

export function readUInt16LE(array: Uint8Array | Buffer, index: number): number {
    return (array[index + 1] << 8) | array[index];
}

export function writeUInt16LE(array: Uint8Array | Buffer, value: number, offset: number) {
    array[offset] = value & 0xff;
    array[offset + 1] = (value >> 8) & 0xff;
}

export const readUInt16BE = (array: Uint8Array | Buffer, index: number): number => {
    return (array[index] << 8) | array[index + 1];
}
export function writeUInt16BE(array: Uint8Array | Buffer, value: number, offset: number): void {
    array[offset] = (value >> 8) & 0xff;
    array[offset + 1] = value & 0xff;
}

export function writeUInt32LE(array: Uint8Array | Buffer, value: number, index: number): void {
    array[index] = value & 0xFF;
    array[index + 1] = (value >> 8) & 0xFF;
    array[index + 2] = (value >> 16) & 0xFF;
    array[index + 3] = (value >> 24) & 0xFF;
}

export function writeUInt32BE(array: Uint8Array | Buffer, value: number, index: number): void {
    array[index] = (value >> 24) & 0xFF;
    array[index + 1] = (value >> 16) & 0xFF;
    array[index + 2] = (value >> 8) & 0xFF;
    array[index + 3] = value & 0xFF;
}

export function bswap64(x: Uint8Array | Buffer): Uint8Array | Buffer {
    var new_buffer = new Uint8Array([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]])
    if (isBuffer(x)) {
        new_buffer = Buffer.from([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]]);
    }
    return new_buffer
}

export function reverse64(x: Uint8Array | Buffer): Uint8Array | Buffer {
    var new_buffer = new Uint8Array([x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]])
    if (isBuffer(x)) {
        new_buffer = Buffer.from([x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]]);
    }
    return new_buffer
}

export function xor_switch(x: Uint8Array | Buffer, hex2: Uint8Array | Buffer): Uint8Array | Buffer {
    var buf1 = new Uint8Array([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]])
    var buf2 = hex2
    if (isBuffer(x)) {
        buf1 = Buffer.from([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]]);
        buf2 = Buffer.from(hex2);
    }
    let number = -1
    const bufResult = buf1.map((b: number) => {
        if (number != buf2.length - 1) {
            number = number + 1
        } else {
            number = 0
        }
        return b ^ buf2[number]
    });
    return bufResult;
}

/**
 * for number not array
 * @param value - number
 * @returns 
 */
export function bswap32(value: number): number {
    return (((value & 0xff) << 24) |
        ((value & 0xff00) << 8) |
        ((value >> 8) & 0xff00) |
        ((value >> 24) & 0xff)) >>> 0;
}

export function HIBYTE(x: number): number {
    return (x >> 24) & 0xFF
}

export function BYTE2(x: number): number {
    return (x >> 16) & 0xFF
}

export function BYTE1(x: number): number {
    return (x >> 8) & 0xFF
}

export function BYTE(x: number): number {
    return x & 0xFF
}

export function rotl(value: number, shift: number): number {
    shift &= 31; // make sure shift is between 0 and 31
    if (shift === 0) {
        return value;
    }
    const return_value = ((value << shift) | (value >>> (32 - shift))) >>> 0;
    return return_value
}

export function rotr(value: number, shift: number): number {
    shift &= 31; // make sure shift is between 0 and 31
    if (shift === 0) {
        return value;
    }
    const return_value = ((value >>> shift) | (value << (32 - shift))) >>> 0;
    return return_value
}

export function __PAIR64__(high: number, low: number, x: number): number {
    var t = (BigInt(high) << 32n) | BigInt(low)
    if (x) {
        t = t >> BigInt(x)
    }
    var final = Number(t & BigInt('0xffffffff'))
    return final;
}

export function align(a: number, n: number): number {
    var a = a % n;
    if (a) {
        return (n - a);
    } else {
        return 0;
    }
}

export function removePKCSPadding(buffer: Uint8Array | Buffer, blockSize: number, number?: number): Uint8Array | Buffer {
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