/**
 * Create, import, and export ethereum keys.
 * @author Jack Peterson (jack@tinybike.net)
 * @author Rustam Abdullaev (me@rustyx.org)
 */

"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const uuid = require("uuid");
const keccak = require("keccak");
const scrypt = require("scrypt");

function isFunction(f) {
  return typeof f === "function";
}

function keccak256(buffer) {
  return keccak("keccak256").update(buffer).digest();
}

module.exports = {

  version: "2.0.0",

  browser: typeof process === "undefined" || !process.nextTick || Boolean(process.browser),

  crypto: crypto,

  constants: {

    // Suppress logging
    quiet: false,

    // Symmetric cipher for private key encryption
    cipher: "aes-128-ctr",

    // Initialization vector size in bytes
    ivBytes: 16,

    // ECDSA private key size in bytes
    keyBytes: 32,

    // Key derivation function parameters
    pbkdf2: {
      c: 262144,
      dklen: 32,
      hash: "sha256",
      prf: "hmac-sha256"
    },
    scrypt: {
      dklen: 32,
      n: 262144,
      r: 1,
      p: 8
    }
  },

  /**
   * Check whether a string is valid hex.
   * @param {string} str String to validate.
   * @return {boolean} True if the string is valid hex, false otherwise.
   */
  isHex: function (str) {
    if (str.length % 2 === 0 && str.match(/^[0-9a-f]+$/i)) return true;
    return false;
  },

  /**
   * Check whether a string is valid base-64.
   * @param {string} str String to validate.
   * @return {boolean} True if the string is valid base-64, false otherwise.
   */
  isBase64: function (str) {
    var index;
    if (str.length % 4 > 0 || str.match(/[^0-9a-z+\/=]/i)) return false;
    index = str.indexOf("=");
    if (index === -1 || str.slice(index).match(/={1,2}/)) return true;
    return false;
  },

  /**
   * Convert a string to a Buffer.  If encoding is not specified, hex-encoding
   * will be used if the input is valid hex.  If the input is valid base64 but
   * not valid hex, base64 will be used.  Otherwise, utf8 will be used.
   * @param {string} str String to be converted.
   * @param {string=} enc Encoding of the input string (optional).
   * @return {buffer} Buffer (bytearray) containing the input data.
   */
  str2buf: function (str, enc) {
    if (!str || str.constructor !== String) return str;
    if (!enc && this.isHex(str)) enc = "hex";
    if (!enc && this.isBase64(str)) enc = "base64";
    return Buffer.from(str, enc);
  },

  /**
   * Check if the selected cipher is available.
   * @param {string} algo Encryption algorithm.
   * @return {boolean} If available true, otherwise false.
   */
  isCipherAvailable: function (cipher) {
    return crypto.getCiphers().some(function (name) { return name === cipher; });
  },

  /**
   * Symmetric private key encryption using secret (derived) key.
   * @param {buffer|string} plaintext Data to be encrypted.
   * @param {buffer|string} key Secret key.
   * @param {buffer|string} iv Initialization vector.
   * @param {string=} algo Encryption algorithm (default: constants.cipher).
   * @return {buffer} Encrypted data.
   */
  encrypt: function (plaintext, key, iv, algo) {
    var cipher, ciphertext;
    algo = algo || this.constants.cipher;
    cipher = crypto.createCipheriv(algo, this.str2buf(key), this.str2buf(iv));
    ciphertext = cipher.update(this.str2buf(plaintext));
    return Buffer.concat([ciphertext, cipher.final()]);
  },

  /**
   * Symmetric private key decryption using secret (derived) key.
   * @param {buffer|string} ciphertext Data to be decrypted.
   * @param {buffer|string} key Secret key.
   * @param {buffer|string} iv Initialization vector.
   * @param {string=} algo Encryption algorithm (default: constants.cipher).
   * @return {buffer} Decrypted data.
   */
  decrypt: function (ciphertext, key, iv, algo) {
    var decipher, plaintext;
    algo = algo || this.constants.cipher;
    decipher = crypto.createDecipheriv(algo, this.str2buf(key), this.str2buf(iv));
    plaintext = decipher.update(this.str2buf(ciphertext));
    return Buffer.concat([plaintext, decipher.final()]);
  },

  /**
   * Derive Ethereum address from private key.
   * @param {buffer|string} privateKey ECDSA private key.
   * @return {string} Hex-encoded Ethereum address.
   */
  privateKeyToAddress: function (privateKey) {
    var privateKeyBuffer = this.str2buf(privateKey);
    if (privateKeyBuffer.length < 32) {
      privateKeyBuffer = Buffer.concat([
        Buffer.alloc(32 - privateKeyBuffer.length, 0),
        privateKeyBuffer
      ]);
    }
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(privateKeyBuffer);
    const publicKey = ecdh.getPublicKey(null, "uncompressed").slice(1);
    return "0x" + keccak256(publicKey).slice(-20).toString("hex");
  },

  /**
   * Calculate message authentication code from secret (derived) key and
   * encrypted text.  The MAC is the keccak-256 hash of the byte array
   * formed by concatenating the second 16 bytes of the derived key with
   * the ciphertext key's contents.
   * @param {buffer|string} derivedKey Secret key derived from password.
   * @param {buffer|string} ciphertext Text encrypted with secret key.
   * @return {string} Hex-encoded MAC.
   */
  getMAC: function (derivedKey, ciphertext) {
    if (typeof derivedKey !== "undefined" && derivedKey !== null && typeof ciphertext !== "undefined" && ciphertext !== null) {
      return keccak256(Buffer.concat([
        this.str2buf(derivedKey).slice(16, 32),
        this.str2buf(ciphertext)
      ])).toString("hex");
    }
  },

  /**
   * Derive secret key from password with key dervation function.
   * @param {string|buffer} password User-supplied password.
   * @param {string|buffer} salt Randomly generated salt.
   * @param {Object=} options Encryption parameters.
   * @param {string=} options.kdf Key derivation function (default: pbkdf2).
   * @param {string=} options.cipher Symmetric cipher (default: constants.cipher).
   * @param {Object=} options.kdfparams KDF parameters (default: constants.<kdf>).
   * @param {function=} cb Callback function (optional).
   * @return {Promise<buffer>} Secret key derived from password.
   */
  deriveKey: function (password, salt, options, cb) {
    var rc, prf;
    const self = this;
    if (typeof password === "undefined" || password === null || !salt) {
      throw new Error("Must provide password and salt to derive a key");
    }

    options = options || {};
    options.kdfparams = options.kdfparams || {};

    // use scrypt as key derivation function
    if (options.kdf === "scrypt") {
      rc = scrypt.hash(
        this.str2buf(password, "utf8"),
        {
          N: options.kdfparams.n || self.constants.scrypt.n,
          r: options.kdfparams.r || self.constants.scrypt.r,
          p: options.kdfparams.p || self.constants.scrypt.p
        },
        options.kdfparams.dklen || self.constants.scrypt.dklen,
        this.str2buf(salt)
      );

    // use default key derivation function (PBKDF2)
    } else {
      prf = options.kdfparams.prf || this.constants.pbkdf2.prf;
      if (prf === "hmac-sha256") prf = "sha256";
      rc = new Promise((resolve, reject) => {
        crypto.pbkdf2(
          self.str2buf(password, "utf8"),
          self.str2buf(salt),
          options.kdfparams.c || self.constants.pbkdf2.c,
          options.kdfparams.dklen || self.constants.pbkdf2.dklen,
          prf,
          (err, derivedKey) => {
            if (err) return reject(err);
            resolve(derivedKey);
          }
        );
      });
    }
    return isFunction(cb) ? rc.then(res => cb(null, res), err => cb(err)) : rc;
  },

  /**
   * Generate random numbers for private key, initialization vector,
   * and salt (for key derivation).
   * @param {Object=} params Encryption options (defaults: constants).
   * @param {string=} params.keyBytes Private key size in bytes.
   * @param {string=} params.ivBytes Initialization vector size in bytes.
   * @param {function=} cb Callback function (optional).
   * @return {Object<string,buffer>} Private key, IV and salt.
   */
  create: function (params, cb) {
    params = params || {};
    const keyBytes = params.keyBytes || this.constants.keyBytes;
    const ivBytes = params.ivBytes || this.constants.ivBytes;
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.generateKeys();
    const privateKey = ecdh.getPrivateKey();
    const result = {
      privateKey: privateKey.length < 32 ? Buffer.concat([Buffer.alloc(32 - privateKey.length), privateKey]) : privateKey,
      iv: crypto.randomBytes(ivBytes),
      salt: crypto.randomBytes(keyBytes)
    };
    return isFunction(cb) ? cb(null, result) : result;
  },

  /**
   * Assemble key data object in secret-storage format.
   * @param {buffer} derivedKey Password-derived secret key.
   * @param {buffer} privateKey Private key.
   * @param {buffer} salt Randomly generated salt.
   * @param {buffer} iv Initialization vector.
   * @param {Object=} options Encryption parameters.
   * @param {string=} options.kdf Key derivation function (default: pbkdf2).
   * @param {string=} options.cipher Symmetric cipher (default: constants.cipher).
   * @param {Object=} options.kdfparams KDF parameters (default: constants.<kdf>).
   * @return {Object}
   */
  marshal: function (derivedKey, privateKey, salt, iv, options) {
    var ciphertext, keyObject, algo;
    options = options || {};
    options.kdfparams = options.kdfparams || {};
    algo = options.cipher || this.constants.cipher;

    // encrypt using first 16 bytes of derived key
    ciphertext = this.encrypt(privateKey, derivedKey.slice(0, 16), iv, algo).toString("hex");

    keyObject = {
      address: this.privateKeyToAddress(privateKey).slice(2),
      crypto: {
        cipher: options.cipher || this.constants.cipher,
        ciphertext: ciphertext,
        cipherparams: { iv: iv.toString("hex") },
        mac: this.getMAC(derivedKey, ciphertext)
      },
      id: uuid.v4(), // random 128-bit UUID
      version: 3
    };

    if (options.kdf === "scrypt") {
      keyObject.crypto.kdf = "scrypt";
      keyObject.crypto.kdfparams = {
        dklen: options.kdfparams.dklen || this.constants.scrypt.dklen,
        n: options.kdfparams.n || this.constants.scrypt.n,
        r: options.kdfparams.r || this.constants.scrypt.r,
        p: options.kdfparams.p || this.constants.scrypt.p,
        salt: salt.toString("hex")
      };

    } else {
      keyObject.crypto.kdf = "pbkdf2";
      keyObject.crypto.kdfparams = {
        c: options.kdfparams.c || this.constants.pbkdf2.c,
        dklen: options.kdfparams.dklen || this.constants.pbkdf2.dklen,
        prf: options.kdfparams.prf || this.constants.pbkdf2.prf,
        salt: salt.toString("hex")
      };
    }

    return keyObject;
  },

  /**
   * Export private key to keystore secret-storage format.
   * @param {string|buffer} password User-supplied password.
   * @param {string|buffer} privateKey Private key.
   * @param {string|buffer} salt Randomly generated salt.
   * @param {string|buffer} iv Initialization vector.
   * @param {Object=} options Encryption parameters.
   * @param {string=} options.kdf Key derivation function (default: pbkdf2).
   * @param {string=} options.cipher Symmetric cipher (default: constants.cipher).
   * @param {Object=} options.kdfparams KDF parameters (default: constants.<kdf>).
   * @param {function=} cb Callback function (optional).
   * @return {Promise<Object>}
   */
  dump: function (password, privateKey, salt, iv, options, cb) {
    options = options || {};
    iv = this.str2buf(iv);
    privateKey = this.str2buf(privateKey);

    const result = this.deriveKey(password, salt, options)
    .then(derivedKey => this.marshal(derivedKey, privateKey, salt, iv, options));

    return isFunction(cb) ? result.then(key => cb(null, key), err => cb(err)) : result;
  },

  /**
   * Recover plaintext private key from secret-storage key object.
   * @param {Object} keyObject Keystore object.
   * @param {function=} cb Callback function (optional).
   * @return {Promise<buffer>} Plaintext private key.
   */
  recover: function (password, keyObject, cb) {
    const self = this;
    const keyObjectCrypto = keyObject.Crypto || keyObject.crypto;

    const iv = this.str2buf(keyObjectCrypto.cipherparams.iv);
    const salt = this.str2buf(keyObjectCrypto.kdfparams.salt);
    const ciphertext = this.str2buf(keyObjectCrypto.ciphertext);
    const algo = keyObjectCrypto.cipher;

    if (keyObjectCrypto.kdf === "pbkdf2" && keyObjectCrypto.kdfparams.prf !== "hmac-sha256") {
      throw new Error("PBKDF2 only supported with HMAC-SHA256");
    }

    // derive secret key from password
    const result = this.deriveKey(password, salt, keyObjectCrypto).then(
      // verify that message authentication codes match, then decrypt
      derivedKey => {
        var key;
        if (self.getMAC(derivedKey, ciphertext) !== keyObjectCrypto.mac) {
          throw new Error("message authentication code mismatch");
        }
        key = derivedKey.slice(0, 16);
        if (keyObject.version === "1") {
          key = keccak256(key).slice(0, 16);
        }
        return self.decrypt(ciphertext, key, iv, algo);
      }
    );
    return isFunction(cb) ? result.then(key => cb(null, key), err => cb(err)) : result;
  },

  /**
   * Generate filename for a keystore file.
   * @param {string} address Ethereum address.
   * @return {string} Keystore filename.
   */
  generateKeystoreFilename: function (address) {
    var filename = "UTC--" + new Date().toISOString() + "--" + address;

    // Windows does not permit ":" in filenames, replace all with "-"
    if (process.platform === "win32") filename = filename.replace(":", "-");

    return filename;
  },

  /**
   * Export formatted JSON to keystore file.
   * @param {Object} keyObject Keystore object.
   * @param {string=} keystore Path to keystore folder (default: "keystore").
   * @param {function=} cb Callback function (optional).
   * @return {Promise<string>} JSON filename
   */
  exportToFile: function (keyObject, keystore, cb) {

    keystore = keystore || "keystore";
    const outfile = this.generateKeystoreFilename(keyObject.address);
    const outpath = keystore + "/" + outfile;
    const json = JSON.stringify(keyObject);

    const result = new Promise((resolve, reject) => {
      fs.writeFile(outpath, json, function (err) {
        if (err) return reject(err);
        resolve(outpath);
      });
    });

    return isFunction(cb) ? result.then(res => cb(null, res), err => cb(err)) : result;

  },

  /**
   * Import key data object from keystore JSON file.
   * @param {string} address Ethereum address to import.
   * @param {string=} datadir Ethereum data directory (default: ~/.ethereum).
   * @param {function=} cb Callback function (optional).
   * @return {Promise<Object>} Keystore data file's contents.
   */
  importFromFile: function (address, datadir, cb) {
    address = address.toLowerCase().replace("0x", "");

    function findKeyfile(keystore, address, files) {
      var i, len, filepath = null;
      for (i = 0, len = files.length; i < len; ++i) {
        if (files[i].indexOf(address) > -1) {
          filepath = path.join(keystore, files[i]);
          if ((fs.lstatSync(filepath)).isDirectory()) {
            filepath = path.join(filepath, files[i]);
          }
          break;
        }
      }
      return filepath;
    }

    datadir = datadir || path.join(process.env.HOME, ".ethereum");
    const keystore = path.join(datadir, "keystore");
    const filepath = findKeyfile(keystore, address, fs.readdirSync(keystore));
    if (!filepath) {
      throw new Error("could not find key file for address " + address);
    }
    const result = new Promise((resolve, reject) => {
      fs.readFile(filepath, (err, data) => {
        if (err) return reject(err);
        resolve(JSON.parse(data));
      });
    });
    return isFunction(cb) ? result.then(res => cb(null, res), err => cb(err)) : result;
  }

};
