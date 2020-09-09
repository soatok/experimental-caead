const crypto = require('crypto');
const blake3 = require('blake3');
const {ChaCha20} = require('xchacha20-js');

const DOMAIN_ENCRYPT = new Uint8Array([0x53, 0x6f, 0x61, 0x74, 0x6f, 0x6b, 0x30, 0x31]);
const DOMAIN_AUTH =    new Uint8Array([0x53, 0x6f, 0x61, 0x74, 0x6f, 0x6b, 0x7d, 0x7e]);

const engine = new ChaCha20();

/**
 * @param {Uint8Array|string} msg
 * @param {Uint8Array} nonce
 * @param {Uint8Array} aad
 * @param {Uint8Array} key
 * @returns {Uint8Array[]}
 */
async function crypto_caead_chacha20blake3_encrypt(
    msg,
    nonce,
    aad,
    key
) {
    if (key.length !== 32) {
        throw new Error('Key must be 32 bytes');
    }
    if (nonce.length !== 32) {
        throw new Error('Nonce must be 32 bytes');
    }
    const [encKey, authKey] = splitKeys(nonce.slice(0, 20), key);
    const cipher = await engine.ietfStreamXorIc(
        Buffer.from(msg),
        Buffer.from(nonce.slice(20, 32)),
        Buffer.from(encKey),
        0
    );
    const aadLength = store64le(aad.length);
    const cipherLength = store64le(cipher.length);
    const mac = blake3.keyedHash(
        authKey,
        concatUint8Array(aad, aadLength, cipher, cipherLength)
    );
    return [cipher, mac];
}

/**
 * @param {Uint8Array} cipher
 * @param {Uint8Array} tag
 * @param {Uint8Array} nonce
 * @param {Uint8Array} aad
 * @param {Uint8Array} key
 * @returns {Uint8Array}
 */
async function crypto_caead_chacha20blake3_decrypt(
    cipher,
    tag,
    nonce,
    aad,
    key
) {
    if (nonce.length !== 32) {
        throw new Error('Nonce must be 32 bytes');
    }
    const [encKey, authKey] = splitKeys(nonce.slice(0, 20), key);
    const aadLength = store64le(aad.length);
    const cipherLength = store64le(cipher.length);
    const calc = blake3.keyedHash(
        authKey,
        concatUint8Array(aad, aadLength, cipher, cipherLength)
    );
    if (!crypto.timingSafeEqual(tag, calc)) {
        throw new Error('Invalid authentication tag');
    }
    return engine.ietfStreamXorIc(
        Buffer.from(cipher),
        Buffer.from(nonce.slice(20, 32)),
        Buffer.from(encKey),
        0
    );
}

/**
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @returns {Buffer[]}
 */
function splitKeys(nonce, key) {
    const encKey  = blake3.keyedHash(
        key,
        concatUint8Array(DOMAIN_ENCRYPT, nonce)
    );
    const authKey = blake3.keyedHash(
        key,
        concatUint8Array(DOMAIN_AUTH, nonce)
    );
    return [encKey, authKey];
}

function store64le(num) {
    const out = new Uint8Array(8);
    out[0] = num & 0xff;
    out[1] = (num >>> 8) & 0xff;
    out[2] = (num >>> 16) & 0xff;
    out[3] = (num >>> 24) & 0xff;
    return out;
}

/**
 * Concatenate a variadic series of Uint8Array objects
 *
 * @returns {Uint8Array}
 */
function concatUint8Array(/* ... arguments ... */) {
    let piece;
    let sum = 0n;
    for (piece of arguments) {
        if (!(piece instanceof Uint8Array)) {
            throw new TypeError('Must be an instance of Uint8Array');
        }
        sum += BigInt(piece.length);
    }
    if (sum > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('Input arrays too large for JavaScript');
    }
    const out = new Uint8Array(parseInt(sum.toString()));
    let position = 0;
    for (piece of arguments) {
        out.set(piece, position);
        position += piece.length;
    }
    return out;
}

module.exports = {
    concatUint8Array,
    crypto_caead_chacha20blake3_decrypt,
    crypto_caead_chacha20blake3_encrypt
};
