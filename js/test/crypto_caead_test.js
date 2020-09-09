const expect = require('chai').expect;
const crypto = require('crypto');
const {crypto_caead_chacha20blake3_decrypt, crypto_caead_chacha20blake3_encrypt} = require('../crypto_caead');

describe('cAEAD', function() {
    it('Encrypt / Decrypt', async function() {
        const message = Buffer.from('Soatok Dreamseeker thinks you are cool', 'utf-8');
        const aad = new Uint8Array([]);
        const key = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(32);

        let encrypted, tag;
        [encrypted, tag] = await crypto_caead_chacha20blake3_encrypt(message, nonce, aad, key);
        const decrypted = await crypto_caead_chacha20blake3_decrypt(encrypted, tag, nonce, aad, key);
        expect(Buffer.from(decrypted).toString('hex'))
            .to.be.equal(message.toString('hex'));

        encrypted[0] = (encrypted[0] ^ 0x13) & 0xff; // Flip some bits
        let thrown = false;
        let exception = '';
        try {
            await crypto_caead_chacha20blake3_decrypt(encrypted, tag, nonce, aad, key);
        } catch (e) {
            thrown = true;
            exception = e.message;
        }
        expect(true).to.be.equal(thrown, 'Invalid MAC accepted');
        expect('Invalid authentication tag').to.be.equal(exception);
    });

    it('AAD affects authentication', async function () {
        const message = Buffer.from('Soatok Dreamseeker thinks you are cool', 'utf-8');
        const aad1 = new Uint8Array([]);
        const aad2 = Buffer.from('Test', 'utf-8');
        const key = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(32);

        const [cipher1, tag1] = await crypto_caead_chacha20blake3_encrypt(message, nonce, aad1, key);
        const [cipher2, tag2] = await crypto_caead_chacha20blake3_encrypt(message, nonce, aad2, key);

        expect(tag1.toString('hex'))
            .to.not.equal(tag2.toString('hex'));

        expect(cipher1.toString('hex'))
            .to.be.equal(cipher2.toString('hex'));
    });
});
