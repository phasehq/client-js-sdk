import { KeyPair } from "libsodium-wrappers";
const _sodium = require("libsodium-wrappers");

const PH_VERSION = "v1";
type PhaseCiphertext = `ph:${string}:${string}:${string}:${string}`;

/**
 * Returns an ephemeral key exchange keypair
 *
 * @returns {KeyPair}
 */
const randomKeyPair = async () => {
  await _sodium.ready;
  const sodium = _sodium;
  const keypair = await sodium.crypto_kx_keypair();

  return keypair;
};

/**
 * Carries out diffie-hellman key exchange and returns a pair of symmetric encryption keys
 *
 * @param {KeyPair} ephemeralKeyPair
 * @param {Uint8Array} recipientPubKey
 * @returns
 */
const sessionKeys = async (
  ephemeralKeyPair: KeyPair,
  recipientPubKey: Uint8Array
) => {
  await _sodium.ready;
  const sodium = _sodium;

  const keys = await sodium.crypto_kx_client_session_keys(
    ephemeralKeyPair.publicKey,
    ephemeralKeyPair.privateKey,
    recipientPubKey
  );
  return keys;
};

/**
 * XChaCha20-Poly1305 encrypt
 *
 * @param {String} plaintext
 * @param {Uint8Array} key
 * @returns {Uint8Array} - Ciphertext with appended nonce
 */
const encryptRaw = async (plaintext: String, key: Uint8Array) => {
  await _sodium.ready;
  const sodium = _sodium;

  let nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  let ciphertext3 = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null,
    null,
    nonce,
    key
  );
  return new Uint8Array([...ciphertext3, ...nonce]);
};

/**
 * Encrypts a single string with the given key. Returns the ciphertext as a hex string
 *
 * @param {string} plaintext - Plaintext string to encrypt
 * @param {Uint8Array} key - Symmetric encryption key
 * @returns {string}
 */
const encryptString = async (plaintext: string, key: Uint8Array) => {
  await _sodium.ready;
  const sodium = _sodium;

  return sodium.to_hex(await encryptRaw(sodium.from_string(plaintext), key));
};

export default class Phase {
  appPubKey: string;

  constructor(appId: string) {
    const appIdRegex = /^phApp:v(\d+):([a-fA-F0-9]{64})$/;
    if (!appIdRegex.test(appId)) {
      throw new Error("Invalid Phase appID");
    }
    this.appPubKey = appId.split(":")[2];
  }

  encrypt = async (
    plaintext: string,
    tag: string = ""
  ): Promise<PhaseCiphertext> => {
    await _sodium.ready;
    const sodium = _sodium;

    return new Promise<PhaseCiphertext>(async (resolve, reject) => {
      try {
        const oneTimeKeyPair = await randomKeyPair();
        const symmetricKeys = await sessionKeys(
          oneTimeKeyPair,
          sodium.from_hex(this.appPubKey)
        );
        const ciphertext = await encryptString(
          plaintext,
          symmetricKeys.sharedTx
        );

        // Use sodium.memzero to wipe the keys from memory
        sodium.memzero(oneTimeKeyPair.privateKey);
        sodium.memzero(symmetricKeys.sharedTx);
        sodium.memzero(symmetricKeys.sharedRx);

        resolve(
          `ph:${PH_VERSION}:${sodium.to_hex(
            oneTimeKeyPair.publicKey
          )}:${ciphertext}:${tag}`
        );
      } catch (error) {
        reject(`Something went wrong: ${error}`);
      }
    });
  };
}
