const {
    concatUint8Array,
    crypto_caead_chacha20blake3_decrypt,
    crypto_caead_chacha20blake3_encrypt
} = require('./crypto_caead');

const CRYPTO_CAEAD_CHACHA20BLAKE3_DOMAIN_ENCRYPT = "Soatok01";
const CRYPTO_CAEAD_CHACHA20BLAKE3_DOMAIN_AUTH = "Soatok}~";
const CRYPTO_CAEAD_CHACHA20BLAKE3_KEY_BYTES = 32;
const CRYPTO_CAEAD_CHACHA20BLAKE3_NONCE_BYTES = 32;
const CRYPTO_CAEAD_CHACHA20BLAKE3_TAG_BYTES = 32;

/**
 * @param {Uint8Array} cipherWithTag
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {string|Uint8Array|null} aad
 * @returns {Uint8Array}
 */
async function crypto_caead_decrypt(cipherWithTag, nonce, key, aad = null) {
    if (!aad) {
        aad = new Uint8Array([]);
    } else if (!(aad instanceof Uint8Array)) {
        aad = new Uint8Array(aad);
    }
    return crypto_caead_chacha20blake3_decrypt(
        cipherWithTag.slice(32),
        cipherWithTag.slice(0, 32),
        nonce,
        aad,
        key
    );
}

/**
 * @param {string|Uint8Array} message
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {string|Uint8Array|null} aad
 * @returns {Uint8Array}
 */
async function crypto_caead_encrypt(message, nonce, key, aad = null) {
    if (!aad) {
        aad = new Uint8Array([]);
    } else if (!(aad instanceof Uint8Array)) {
        aad = new Uint8Array(aad);
    }
    if (!(message instanceof Uint8Array)) {
        message = new Uint8Array(message);
    }
    const [ciphertext, tag] = await crypto_caead_chacha20blake3_encrypt(
        message,
        nonce,
        aad,
        key
    );
    return concatUint8Array(tag, ciphertext);
}

module.exports = {
    crypto_caead_decrypt,
    crypto_caead_encrypt,
    CRYPTO_CAEAD_CHACHA20BLAKE3_DOMAIN_ENCRYPT,
    CRYPTO_CAEAD_CHACHA20BLAKE3_DOMAIN_AUTH,
    CRYPTO_CAEAD_CHACHA20BLAKE3_KEY_BYTES,
    CRYPTO_CAEAD_CHACHA20BLAKE3_NONCE_BYTES,
    CRYPTO_CAEAD_CHACHA20BLAKE3_TAG_BYTES
};
