# keythereum-node

Keythereum-node is a Node.js library to generate, import and export Ethereum keys.

It is 8 times faster than the JavaScript-only [keythereum](https://github.com/ethereumjs/keythereum), but it does not run inside a browser, only in Node.js.

This provides a simple way to use the same account inside web apps and in web wallets, for example, for off-chain encryption or for manipulation of stored key files (e.g. changing the password).

Keythereum-node uses the same key derivation functions (PBKDF2-SHA256 or scrypt), symmetric ciphers (AES-128-CTR or AES-128-CBC), and message authentication codes as [geth](https://github.com/ethereum/go-ethereum).  You can export your generated key to file, copy it to your data directory's keystore, and immediately start using it in your local Ethereum client.

Parity keyfiles are partially supported -- the `recover` API supports Parity keyfile objects, but reading and writing of Parity keyfiles isn't supported.

## Installation

```
npm install --save keythereum-node
```

## Usage

To use keythereum in Node.js, just `require` it:

```javascript
const keythereum = require("keythereum-node");
```

### Key import

Importing a key from geth's keystore can only be done on Node.  The JSON file is parsed into an object with the same structure as `keyObject` above.

```javascript
// Specify a data directory (optional; defaults to ~/.ethereum)
var datadir = "/home/jack/.ethereum-test";

// Using a Promise
keythereum.importFromFile(address, datadir)
.then(keyObject => {
  // do stuff
})

// Or with a callback
keythereum.importFromFile(address, datadir, function (err, keyObject) {
  // do stuff
});
```

This has been tested with version 3 and version 1, but not version 2, keys.  (Please send me a version 2 keystore file if you have one, so I can test it!)

To recover the plaintext private key from the key object, use `keythereum.recover`.  The private key is returned as a Buffer.

```javascript
// Using a Promise
keythereum.recover(password, keyObject)
.then(privateKey => {
  // privateKey:
  <Buffer ...>
})

// Or with a callback
keythereum.recover(password, keyObject, function (privateKey) {
  // do stuff
});
```

### Key export

You will need to specify a password and (optionally) a key derivation function.  If unspecified, PBKDF2-SHA256 will be used to derive the AES secret key.

```javascript
var password = "wheethereum";
var kdf = "pbkdf2"; // or "scrypt" to use the scrypt kdf
```

The `dump` function is used to export key info to keystore ["secret-storage" format](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).  If a callback function is supplied as the sixth parameter to `dump`, it will run asynchronously:

```javascript
// Note: if options is unspecified, the values in keythereum.constants are used.
var options = {
  kdf: "pbkdf2",
  cipher: "aes-128-ctr",
  kdfparams: {
    c: 262144,
    dklen: 32,
    prf: "hmac-sha256"
  }
};

// Using a Promise
keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options)
.then(keyObject => {
  // keyObject:
  {
    address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
    Crypto: {
      cipher: "aes-128-ctr",
      ciphertext: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
      cipherparams: {
        iv: "6087dab2f9fdbbfaddc31a909735c1e6"
      },
      mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
      kdf: "pbkdf2",
      kdfparams: {
        c: 262144,
        dklen: 32,
        prf: "hmac-sha256",
        salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
      }
    },
    id: "e13b209c-3b2f-4327-bab0-3bef2e51630d",
    version: 3
  }
} )

// Or with a callback
keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options, function (err, keyObject) {
  // do stuff!
});
```

`dump` creates an object and not a JSON string.  In Node, the `exportToFile` method provides an easy way to export this formatted key object to file.  It creates a JSON file in the `keystore` sub-directory, and uses geth's current file-naming convention (ISO timestamp concatenated with the key's derived Ethereum address).

```javascript
keythereum.exportToFile(keyObject);
```

### Key creation

Generate a new random private key (256 bit), as well as the salt (256 bit) used by the key derivation function, and the initialization vector (128 bit) used to AES-128-CTR encrypt the key.  `create` is asynchronous if it is passed a callback function, and synchronous otherwise.

```javascript
// optional private key and initialization vector sizes in bytes
// (if params is not passed to create, keythereum.constants is used by default)
var params = { keyBytes: 32, ivBytes: 16 };

// Using a Promise
keythereum.create(params).then(dk => {
  // dk:
  {
      privateKey: <Buffer ...>,
      iv: <Buffer ...>,
      salt: <Buffer ...>
  }
})

// Or with a callback
keythereum.create(params, function (err, dk) {
    // do stuff!
});
```


## Tests

Unit tests are in the `test` directory, and can be run with mocha:

```
npm test
```
