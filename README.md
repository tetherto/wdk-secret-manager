# @tetherto/wdk-secret-manager

**Note**: This package is currently in beta. Please test thoroughly in development environments before using in production.

A small, security-focused utility for generating, encrypting, and managing wallet secrets. It provides:
- Versioned, self-describing payloads
- PBKDF2-SHA256 key derivation
- Authenticated encryption using libsodium `crypto_secretbox`
- BIP-39 mnemonic/seed helpers
- Memory zeroization utilities

### 🔍 About WDK

This module is part of WDK (Wallet Development Kit) by Tether, which empowers developers to build secure, non-custodial wallets with unified blockchain access, stateless architecture, and full user control.

See the [Secret Manager documentation](https://docs.wdk.tether.io/tools/secret-manager/). For the complete ecosystem, see the [general WDK documentation](https://docs.wdk.tether.io/).

### 🌟 Features

- **PBKDF2-SHA256 KDF**: Derives strong keys from user passkeys and a 16-byte salt
- **Versioned Payloads**: Header includes version, KDF algorithm, iterations, salt, and nonce
- **Authenticated Encryption**: Uses libsodium `crypto_secretbox` (XSalsa20-Poly1305)
- **BIP-39 Support**: Convert entropy ↔ mnemonic and derive the standard 64-byte seed
- **Master-Key Override**: Optionally provide a 32-byte key to skip PBKDF2
- **Secure Memory Handling**: Zeroizes sensitive buffers and supports `dispose()`
- **Bare Runtime Support**: Ships a `bare` build for `bare-wdk-runtime`

## ⬇️ Installation

Install with npm:

```bash
npm install @tetherto/wdk-secret-manager
```

## 🚀 Quick Start

### Importing

```javascript
import WdkSecretManager from '@tetherto/wdk-secret-manager'
```

If you are using the `bare` runtime, import as usual; the `bare` export is provided for compatible bundlers/environments.

### Creating a Secret Manager

```javascript
import WdkSecretManager from '@tetherto/wdk-secret-manager'

const passkey = 'correct horse battery staple' // minimum 12 characters
const salt = WdkSecretManager.generateSalt()   // 16-byte Buffer

// Optional: tune PBKDF2 iterations
const sm = new WdkSecretManager(passkey, salt, { iterations: 100_000 })
```

### Generating and Encrypting Entropy + Seed

```javascript
// Generates 16-byte entropy, converts to BIP-39 mnemonic, derives 64-byte seed,
// and encrypts both with the manager's settings
const { encryptedEntropy, encryptedSeed } = await sm.generateAndEncrypt()

// Decrypt later
const entropy = sm.decrypt(encryptedEntropy) // 16 bytes
const seed = sm.decrypt(encryptedSeed)       // 64 bytes
```

### Encrypting and Decrypting Arbitrary Data

```javascript
// Accepts payloads between 16 and 64 bytes
const data = crypto.getRandomValues(new Uint8Array(32))
const payload = sm.encrypt(Buffer.from(data))
const out = sm.decrypt(payload)
```

### Using a Pre-Derived Master Key (Skip PBKDF2)

```javascript
import { pbkdf2Sync } from 'crypto'
import b4a from 'b4a'

const masterKey = b4a.from(pbkdf2Sync(b4a.from(passkey), b4a.from(salt), 100_000, 32, 'sha256'))

const cipher = sm.encrypt(Buffer.from('0123456789abcdef0123456789abcdef'), masterKey)
const plain = sm.decrypt(cipher, masterKey)
```

### Mnemonic Helpers

```javascript
const entropy16 = sm.generateRandomBuffer()                 // 16 bytes
const mnemonic = sm.entropyToMnemonic(entropy16)            // 12 words
const entropyRoundTrip = sm.mnemonicToEntropy(mnemonic)     // back to 16 bytes
```

### Memory Management

```javascript
// Wipes internal passkey/salt/iteration state from memory
sm.dispose()
```

## 📚 API Reference

### Table of Contents

| Class | Description | Methods |
|-------|-------------|---------|
| `WdkSecretManager` | High-level manager for secret generation, encryption, and decryption. | `constructor`, `generateSalt`, `generateAndEncrypt`, `encrypt`, `decrypt`, `entropyToMnemonic`, `mnemonicToEntropy`, `generateRandomBuffer`, `dispose` |

### WdkSecretManager

The main class for generating and managing encrypted secrets.

#### Constructor

```javascript
new WdkSecretManager(passKey, salt, kdfParams?)
```

**Parameters:**
- `passKey` (`string | Buffer | Uint8Array`): User passkey (min 12 characters/bytes)
- `salt` (`Buffer`): 16-byte salt used for key derivation
- `kdfParams` (`object`, optional):
  - `iterations` (`number`, optional): PBKDF2 iterations (default: 100_000)

#### Static Methods

- `generateSalt(): Buffer`
  - Returns a new 16-byte random salt.

#### Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `generateAndEncrypt(entropyOpt?, masterKeyOpt?)` | Generates 16-byte entropy, derives mnemonic + 64-byte seed, encrypts both. | `{ encryptedSeed: Buffer, encryptedEntropy: Buffer }` |
| `encrypt(data, masterKeyOpt?)` | Encrypts 16–64 byte payload with header and MAC. | `Buffer` (payload) |
| `decrypt(payload, masterKeyOpt?)` | Decrypts a payload produced by this manager. | `Buffer` (plaintext) |
| `generateRandomBuffer()` | Returns 16 random bytes. | `Buffer` |
| `entropyToMnemonic(entropy)` | Converts 16-byte entropy to 12-word mnemonic. | `string` |
| `mnemonicToEntropy(mnemonic)` | Converts 12-word mnemonic to 16-byte entropy. | `Buffer` |
| `dispose()` | Zeroizes internal state; instance becomes unusable. | `void` |

#### Payload Format

Header `[version(1), kdf_alg(1), iterations(u32le), reserved(u32le=0), salt(16), nonce(24)]` followed by `cipher = secretbox( [len(1) | data(16..64)], nonce, key)`.

#### `generateAndEncrypt(entropyOpt?, masterKeyOpt?)`

Generates 16-byte entropy, converts it to a BIP-39 12-word mnemonic, derives the 64-byte BIP-39 seed, and encrypts both values.

**Parameters:**
- `entropyOpt` (`Buffer | null`, optional): If provided, must be exactly 16 bytes. When not provided, secure random entropy is generated.
- `masterKeyOpt` (`Buffer | null`, optional): A 32-byte key. If provided, PBKDF2 derivation is skipped and this key is used for encryption.

**Returns:** `{ encryptedSeed: Buffer, encryptedEntropy: Buffer }`

**Example:**
```javascript
const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt()
const seed = sm.decrypt(encryptedSeed)       // 64 bytes
const entropy = sm.decrypt(encryptedEntropy) // 16 bytes
```

#### `encrypt(data, masterKeyOpt?)`

Encrypts a 16–64 byte payload using a versioned header and `crypto_secretbox`. The plaintext is prefixed with a single-byte length before encryption.

**Parameters:**
- `data` (`Buffer`): Plaintext data. Must be between 16 and 64 bytes inclusive.
- `masterKeyOpt` (`Buffer | null`, optional): 32-byte master key. If omitted, a key is derived via PBKDF2-SHA256 from the manager's passkey + salt.

**Returns:** `Buffer` - Encrypted payload with header and MAC.

**Throws:** on invalid input length, missing/invalid passkey or salt, or other validation errors.

**Example:**
```javascript
const data = Buffer.from('0123456789abcdef0123456789abcdef') // 32 bytes
const payload = sm.encrypt(data)
```

#### `decrypt(payload, masterKeyOpt?)`

Decrypts a payload produced by this manager, validates the header, and returns the original plaintext.

**Parameters:**
- `payload` (`Buffer`): Encrypted payload produced by `encrypt`.
- `masterKeyOpt` (`Buffer | null`, optional): 32-byte master key. If omitted, a key is derived via PBKDF2-SHA256 using the header's salt and iteration count.

**Returns:** `Buffer` - Decrypted plaintext.

**Throws:** when authentication fails, payload is malformed, length prefix is out of bounds, or inputs are invalid.

**Example:**
```javascript
const plain = sm.decrypt(payload)
```

#### `generateRandomBuffer()`

Generates 16 bytes of cryptographically secure random data using libsodium.

**Returns:** `Buffer`

**Example:**
```javascript
const entropy16 = sm.generateRandomBuffer()
```

#### `entropyToMnemonic(entropy)`

Converts 16-byte entropy into a 12-word BIP-39 mnemonic.

**Parameters:**
- `entropy` (`Buffer`): Exactly 16 bytes.

**Returns:** `string` - 12-word mnemonic.

**Throws:** on invalid type or length.

**Example:**
```javascript
const mnemonic = sm.entropyToMnemonic(entropy16)
```

#### `mnemonicToEntropy(mnemonic)`

Converts a 12-word mnemonic into its original 16-byte entropy buffer.

**Parameters:**
- `mnemonic` (`string`): Non-empty 12-word BIP-39 mnemonic.

**Returns:** `Buffer` - 16-byte entropy.

**Throws:** on invalid/empty string or non-12-word mnemonics.

**Example:**
```javascript
const entropy = sm.mnemonicToEntropy(mnemonic)
```

#### `dispose()`

Securely wipes internal state (passkey, salt, iterations) from memory. The instance should not be used after calling this.

**Returns:** `void`

**Example:**
```javascript
sm.dispose()
```

## 🌐 Supported Runtimes

- **Node.js**: Uses `sodium-native` and Node `crypto` for PBKDF2
- **Bare Runtime**: Ships a `bare` build; PBKDF2 provided by `bare-crypto`

## 🔒 Security Considerations

- **Passkey Strength**: Enforce long, high-entropy user passkeys (min 12 characters)
- **Salt Handling**: Use a unique 16-byte salt per user/passkey, store it with the payload
- **KDF Parameters**: Tune PBKDF2 iterations to balance security and performance
- **Integrity & Confidentiality**: `crypto_secretbox` provides authenticated encryption
- **Master Key**: Only use a 32-byte master key if you securely derive/transport it
- **Memory Hygiene**: Call `dispose()` after use to wipe sensitive state

## 🛠️ Development

### Building

```bash
# Install dependencies
npm install

# Build TypeScript definitions
npm run build:types

# Lint code
npm run lint

# Fix linting issues
npm run lint:fix
```

### Testing

```bash
# Run bare runtime tests
npm run test:bare
```

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🆘 Support

For support, please open an issue on the repository.

---
