"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.__PAIR64__ = exports.rotr = exports.rotl = exports.BYTE = exports.BYTE1 = exports.BYTE2 = exports.HIBYTE = exports.bswap32 = exports.xor_switch = exports.reverse64 = exports.bswap64 = exports.writeUInt32BE = exports.writeUInt32LE = exports.writeUInt16BE = exports.readUInt16BE = exports.writeUInt16LE = exports.readUInt16LE = exports.readUInt32BE = exports.readUInt32LE = exports.xor = exports.concatenateUint8Arrays = exports.extendUint8Array = exports.isBuffer = exports.isBufferOrUint8Array = void 0;
function isBufferOrUint8Array(obj) {
    return obj instanceof Uint8Array || (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}
exports.isBufferOrUint8Array = isBufferOrUint8Array;
function isBuffer(obj) {
    return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}
exports.isBuffer = isBuffer;
function extendUint8Array(array, newLength, padValue) {
    const newArray = new Uint8Array(newLength);
    newArray.set(array);
    for (let i = array.length; i < newLength; i++) {
        newArray[i] = padValue;
    }
    return newArray;
}
exports.extendUint8Array = extendUint8Array;
function concatenateUint8Arrays(arrays) {
    const totalLength = arrays.reduce((length, array) => length + array.length, 0);
    const concatenatedArray = new Uint8Array(totalLength);
    let offset = 0;
    for (let i = 0; i < arrays.length; i++) {
        concatenatedArray.set(arrays[i], offset);
        offset += arrays[i].length;
    }
    return concatenatedArray;
}
exports.concatenateUint8Arrays = concatenateUint8Arrays;
function xor(buf1, buf2) {
    let number = -1;
    const bufResult = buf1.map((b) => {
        if (number != buf2.length - 1) {
            number = number + 1;
        }
        else {
            number = 0;
        }
        return b ^ buf2[number];
    });
    return bufResult;
}
exports.xor = xor;
function readUInt32LE(array, index) {
    return (((array[index + 3] & 0xFF) << 24) |
        ((array[index + 2] & 0xFF) << 16) |
        ((array[index + 1] & 0xFF) << 8) |
        (array[index] & 0xFF)) >>> 0;
}
exports.readUInt32LE = readUInt32LE;
function readUInt32BE(array, index) {
    return (((array[index] & 0xFF) << 24) |
        ((array[index + 1] & 0xFF) << 16) |
        ((array[index + 2] & 0xFF) << 8) |
        (array[index + 3] & 0xFF)) >>> 0;
}
exports.readUInt32BE = readUInt32BE;
function readUInt16LE(array, index) {
    return (array[index + 1] << 8) | array[index];
}
exports.readUInt16LE = readUInt16LE;
function writeUInt16LE(array, value, offset) {
    array[offset] = value & 0xff;
    array[offset + 1] = (value >> 8) & 0xff;
}
exports.writeUInt16LE = writeUInt16LE;
const readUInt16BE = (array, index) => {
    return (array[index] << 8) | array[index + 1];
};
exports.readUInt16BE = readUInt16BE;
function writeUInt16BE(array, value, offset) {
    array[offset] = (value >> 8) & 0xff;
    array[offset + 1] = value & 0xff;
}
exports.writeUInt16BE = writeUInt16BE;
function writeUInt32LE(array, value, index) {
    array[index] = value & 0xFF;
    array[index + 1] = (value >> 8) & 0xFF;
    array[index + 2] = (value >> 16) & 0xFF;
    array[index + 3] = (value >> 24) & 0xFF;
}
exports.writeUInt32LE = writeUInt32LE;
function writeUInt32BE(array, value, index) {
    array[index] = (value >> 24) & 0xFF;
    array[index + 1] = (value >> 16) & 0xFF;
    array[index + 2] = (value >> 8) & 0xFF;
    array[index + 3] = value & 0xFF;
}
exports.writeUInt32BE = writeUInt32BE;
function bswap64(x) {
    var new_buffer = new Uint8Array([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]]);
    if (isBuffer(x)) {
        new_buffer = Buffer.from([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]]);
    }
    return new_buffer;
}
exports.bswap64 = bswap64;
function reverse64(x) {
    var new_buffer = new Uint8Array([x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]]);
    if (isBuffer(x)) {
        new_buffer = Buffer.from([x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]]);
    }
    return new_buffer;
}
exports.reverse64 = reverse64;
function xor_switch(x, hex2) {
    var buf1 = new Uint8Array([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]]);
    var buf2 = hex2;
    if (isBuffer(x)) {
        buf1 = Buffer.from([x[3], x[2], x[1], x[0], x[7], x[6], x[5], x[4]]);
        buf2 = Buffer.from(hex2);
    }
    let number = -1;
    const bufResult = buf1.map((b) => {
        if (number != buf2.length - 1) {
            number = number + 1;
        }
        else {
            number = 0;
        }
        return b ^ buf2[number];
    });
    return bufResult;
}
exports.xor_switch = xor_switch;
/**
 * for number not array
 * @param value - number
 * @returns
 */
function bswap32(value) {
    return (((value & 0xff) << 24) |
        ((value & 0xff00) << 8) |
        ((value >> 8) & 0xff00) |
        ((value >> 24) & 0xff)) >>> 0;
}
exports.bswap32 = bswap32;
function HIBYTE(x) {
    return (x >> 24) & 0xFF;
}
exports.HIBYTE = HIBYTE;
function BYTE2(x) {
    return (x >> 16) & 0xFF;
}
exports.BYTE2 = BYTE2;
function BYTE1(x) {
    return (x >> 8) & 0xFF;
}
exports.BYTE1 = BYTE1;
function BYTE(x) {
    return x & 0xFF;
}
exports.BYTE = BYTE;
function rotl(value, shift) {
    shift &= 31; // make sure shift is between 0 and 31
    if (shift === 0) {
        return value;
    }
    const return_value = ((value << shift) | (value >>> (32 - shift))) >>> 0;
    return return_value;
}
exports.rotl = rotl;
function rotr(value, shift) {
    shift &= 31; // make sure shift is between 0 and 31
    if (shift === 0) {
        return value;
    }
    const return_value = ((value >>> shift) | (value << (32 - shift))) >>> 0;
    return return_value;
}
exports.rotr = rotr;
function __PAIR64__(high, low, x) {
    var t = (BigInt(high) << 32n) | BigInt(low);
    if (x) {
        t = t >> BigInt(x);
    }
    var final = Number(t & BigInt('0xffffffff'));
    return final;
}
exports.__PAIR64__ = __PAIR64__;
//# sourceMappingURL=common.js.map