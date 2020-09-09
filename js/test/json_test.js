const expect = require('chai').expect;
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const {crypto_caead_chacha20blake3_decrypt, crypto_caead_chacha20blake3_encrypt} = require('../crypto_caead');


describe('JSON Test Vectors', function() {
    it('test-vectors.json', async function () {
        const testVectors = JSON.parse(
            (await fs.readFile(path.join(__dirname, 'test-vectors.json')))
                .toString('utf-8')
        );
        let plaintext, key, nonce, aad, ciphertext, tag, cPrime, tPrime, pPrime;
        /**
         * @var {object<string, string|object<string, string>>>} tVect
         */
        for (tVect of testVectors) {
            plaintext = Buffer.from(tVect.params['plaintext'], 'hex');
            key = Buffer.from(tVect.params['key'], 'hex');
            nonce = Buffer.from(tVect.params['nonce'], 'hex');
            aad = Buffer.from(tVect.params['aad'], 'hex');
            ciphertext = Buffer.from(tVect.params['ciphertext'], 'hex');
            tag = Buffer.from(tVect.params['tag'], 'hex');

            // Verify encryption
            [cPrime, tPrime] = await crypto_caead_chacha20blake3_encrypt(plaintext, nonce, aad, key);
            expect(Buffer.from(cPrime).toString('hex'))
                .to.be.equal(ciphertext.toString('hex'), tVect.name + " - Encrypt Ciphertext");
            expect(Buffer.from(tPrime).toString('hex'))
                .to.be.equal(tag.toString('hex'), tVect.name + " - Encrypt Tag");

            // Verify decryption
            pPrime = await crypto_caead_chacha20blake3_decrypt(ciphertext, tag, nonce, aad, key);
            expect(Buffer.from(pPrime).toString('hex'))
                .to.be.equal(plaintext.toString('hex'), tVect.name + " - Decrypt Ciphertext");
        }
    });
});