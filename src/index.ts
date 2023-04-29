import { randomKeyPair, sessionKeys, encryptString } from "./utils/crypto";
const _sodium = require("libsodium-wrappers");

const PH_VERSION = "v1";
type PhaseCiphertext = `ph:${string}:${string}:${string}:${string}`;

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
