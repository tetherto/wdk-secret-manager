// Copyright 2024 Tether Operations Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import b4a from 'b4a'
import bip39 from 'bip39-mnemonic'
import crypto from 'crypto'
import sodium from 'sodium-universal'

/**
 *
 * @type {{generate: (function(): Buffer)}}
 */
export const wdkSaltGenerator = {
  generate: () => {
    const resultBuffer = b4a.alloc(16)
    sodium.randombytes_buf(resultBuffer)
    return resultBuffer
  }
}

export class WdkSecretManager {
  /**
   *
   * @param {Buffer | ArrayBuffer | string} passKey - The user's password (e.g., "password123").
   */
  #passkey = null
  /**
   * @param {Buffer} salt - A unique, random 16-byte salt. This should be
   * generated once per user and stored alongside the
   * encrypted data. It is not a secret.
   */
  #salt = null

  /**
   *
   * @param {Buffer | ArrayBuffer | Uint8Array | string} passKey - The user's password (e.g., "password123").
   * @param {Buffer} salt - A unique, random 16-byte salt. This should be
   * generated once per user and stored alongside the
   * encrypted data. It is not a secret.
   */
  constructor (passKey, salt = null) {
    this.#passKeyValidator(passKey)
    this.#saltValidator(salt)
    this.#passkey = passKey
    this.#salt = salt
  }

  /**
   * Derives a strong, 32-byte (256-bit) cryptographic key from a user's password
   * Salt for preventing rainbow table attacks.
   * using the PBKDF2 algorithm.
   * @return {Buffer}
   */
  #deriveKeyFromPassKey () {
    this.#passKeyValidator(this.#passkey)
    this.#saltValidator(this.#salt) // Ensure this.#salt is a 16-byte Buffer

    // Key size in bytes (256-bit = 32 bytes)
    const keySizeInBytes = 32

    // The number of iterations
    const iterations = 100000

    // The digest algorithm
    const digest = 'sha256'

    const key = crypto.pbkdf2Sync(
      this.#passkey,
      this.#salt,
      iterations,
      keySizeInBytes,
      digest
    )

    return key
  }

  /**
   * Generate randomBytes(16) Entropy
   * Convert Entropy to BIP39 mnemonic phrase
   * Convert BIP39 mnemonic phrase to seed buffer
   * Encrypt a seed buffer
   * Encrypt a randomBytes(16) Entropy
   * @param {Buffer} [payload=null] - Optional randomBytes(16) entropy. If not provided, it will be generated.
   * @param {Buffer} [derivedKey=null] - Optional ArrayBuffer(32) bytes cryptographic key.
   * @returns {{encryptedSeed: Buffer, encryptedEntropy: Buffer}} A Object containing the encrypted seed and entropy.
   */
  async generateAndEncrypt (payload = null, derivedKey = null) {
    if (payload) if (!b4a.isBuffer(payload)) throw new Error('Payload is not a buffer!')
    const entropy = payload || this.generateRandomBuffer()
    const seedBuffer = await bip39.mnemonicToSeed(bip39.entropyToMnemonic(entropy))

    const encryptedSeed = this.#encrypt(seedBuffer, seedBuffer.byteLength, derivedKey)
    const encryptedEntropy = this.#encrypt(entropy, entropy.byteLength, derivedKey)

    return { encryptedSeed, encryptedEntropy }
  }

  /**
   * Encrypt entropy or seed buffer
   * @param {Buffer} buffer.
   * @param {number} buffLength.
   * @param {Buffer} [derivedKey=null] - Optional ArrayBuffer(32) bytes cryptographic key.
   * @return {Buffer} A Buffer containing the encrypted payload.
   */
  #encrypt (buffer, buffLength, derivedKey = null) {
    if (!b4a.isBuffer(buffer)) throw new Error('Payload is not a buffer!')
    if (!buffLength) throw new Error('Incorrect buffer length')
    if (derivedKey) if (!b4a.isBuffer(derivedKey)) throw new Error('derivedKey is not a buffer!')
    const key = derivedKey || this.#deriveKeyFromPassKey()
    if (buffer.byteLength > 64 || buffer.byteLength < 16) { throw new Error('Buffer size must be between 16 and 64') }

    const nonce = b4a.alloc(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)

    const payload = b4a.alloc(
      1 + sodium.crypto_secretbox_NONCEBYTES + 1 + buffLength + sodium.crypto_secretbox_MACBYTES
    )
    payload[0] = 0 // version
    payload.set(nonce, 1)

    const cipher = payload.subarray(1 + nonce.byteLength)
    const plain = cipher.subarray(0, cipher.byteLength - sodium.crypto_secretbox_MACBYTES)
    plain[0] = buffer.byteLength
    plain.set(buffer, 1)

    sodium.sodium_memzero(buffer)
    // encrypt in-place
    sodium.crypto_secretbox_easy(cipher, plain, nonce, key)

    return payload
  }

  /**
   * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
   * @param {Buffer} payload - The encrypted payload.
   * @param {Buffer} [derivedKey=null] - Optional ArrayBuffer(32) bytes cryptographic key.
   * @return {Buffer} The decrypted mnemonic phrase.
   */
  decrypt (payload, derivedKey = null) {
    if (!b4a.isBuffer(payload)) {
      throw new Error('Payload is not a buffer!')
    }
    if (derivedKey) if (!b4a.isBuffer(derivedKey)) throw new Error('derivedKey is not a buffer!')
    const minLength = 1 + sodium.crypto_secretbox_NONCEBYTES + 1 + sodium.crypto_secretbox_MACBYTES
    if (payload.byteLength < minLength) {
      throw new Error('Invalid payload: too short')
    }

    if (payload[0] !== 0) {
      throw new Error('Invalid version')
    }
    const key = derivedKey || this.#deriveKeyFromPassKey()
    const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES)
    const cipher = payload.subarray(1 + nonce.byteLength)

    const plain = b4a.alloc(cipher.byteLength - sodium.crypto_secretbox_MACBYTES)
    if (!sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key)) {
      throw new Error('Decryption failed')
    }
    const bytes = plain[0]
    if (bytes > 64) {
      throw new Error('Invalid decrypted payload')
    }

    if (plain.byteLength < 1 + bytes) {
      throw new Error('Invalid decrypted payload: inconsistent length')
    }
    const resultBuffer = b4a.alloc(bytes)
    resultBuffer.set(plain.subarray(1, 1 + bytes))
    sodium.sodium_memzero(plain)
    return resultBuffer
  }

  /**
   * Generates a random 128 bits buffer
   * @return {Buffer} Which can be converted BIP39 mnemonic phrase (12 words).
   */
  generateRandomBuffer () {
    const resultBuffer = b4a.alloc(16)
    sodium.randombytes_buf(resultBuffer)
    return resultBuffer
  }

  /**
   *
   * @param {Buffer} entropy - 128 bits entropy buffer.
   * @return {string} - BIP39 mnemonic phrase (12 words by default for 128 bits).
   */
  entropyToMnemonic (entropy) {
    if (!b4a.isBuffer(entropy)) throw new Error('Payload is not a buffer!')
    return bip39.entropyToMnemonic(entropy)
  }

  /**
   *
   * @param {string} seedPhrase
   * @return {Buffer}
   */
  mnemonicToEntropy (seedPhrase) {
    const entropy = bip39.mnemonicToEntropy(seedPhrase)
    return b4a.from(entropy, 'hex')
  }

  #passKeyValidator (passKey) {
    if (!passKey) {
      throw new Error('Pass key must not be empty!')
    }
    if (typeof passKey !== 'string' && !b4a.isBuffer(passKey)) {
      throw new Error('Pass key must be a string or Buffer!')
    }
  }

  #saltValidator (salt) {
    if (!salt) {
      throw new Error('Salt must not be empty!')
    }
    if (!b4a.isBuffer(salt)) {
      throw new Error('Salt must be a buffer!')
    }
    if (salt.byteLength < 16) {
      throw new Error('Salt must be at least 16 bytes!')
    }
  }

  /**
   * Erase the salt and passkey from memory.
   */
  dispose () {
    sodium.sodium_memzero(this.#salt)
    if (b4a.isBuffer(this.#passkey)) sodium.sodium_memzero(this.#passkey)
    this.#passkey = null
    this.#salt = null
  }
}
