import * as openpgp from "openpgp";
import { SRP_MODULUS_KEY_FINGERPRINT } from "./constants";

export interface GPGDecryptResult {
  valid: boolean;
  fingerprint: string;
  data: string;
}

export interface GPG {
  import_keys(key: string): Promise<void>;
  decrypt(data: string): Promise<GPGDecryptResult>;
  decryptEncryptedMessage(
    armoredEncryptedMessage: string,
    armoredPrivateKey: string,
    password?: string,
  ): Promise<string | null>;
  readArmoredPrivateKey(armoredKey: string): Promise<openpgp.PrivateKey>;
  tryUnlockKey(privateKeyObject: openpgp.PrivateKey, password: string): Promise<openpgp.PrivateKey>;
}

export interface SessionInterface {
  gnupg: GPG;
  verifyModulus(armoredModulus: string): Promise<Uint8Array>;
}

export class OpenPGPImplementation implements GPG {
  private publicKeys: openpgp.PublicKey[] = [];

  public async import_keys(armoredKey: string): Promise<void> {
    try {
      const key = await openpgp.readKey({ armoredKey });
      if (!key.isPrivate()) {
        this.publicKeys.push(key as openpgp.PublicKey);
      }
    } catch (error: any) {
      throw new Error(`Failed to import key: ${error.message}`);
    }
  }

  public async decrypt(armoredCleartextMessage: string): Promise<GPGDecryptResult> {
    try {
      const cleartextMessage = await openpgp.readCleartextMessage({
        cleartextMessage: armoredCleartextMessage,
      });
      const messageText = cleartextMessage.getText();

      if (this.publicKeys.length === 0) {
        throw new Error("No public keys available for verification. Import public keys first.");
      }
      const verificationResults = await cleartextMessage.verify(this.publicKeys, new Date());
      if (!verificationResults || verificationResults.length === 0) {
        return { valid: false, fingerprint: "", data: messageText || "" };
      }
      const firstResult = verificationResults[0];
      const sigKeyID = firstResult.keyID.toHex().toLowerCase();
      try {
        await firstResult.verified;
        return { valid: true, fingerprint: sigKeyID, data: messageText };
      } catch (verifyError: any) {
        return { valid: false, fingerprint: sigKeyID, data: messageText };
      }
    } catch (error: any) {
      throw new Error(`Failed to process cleartext signed message: ${error.message}`);
    }
  }

  public async decryptEncryptedMessage(
    armoredEncryptedMessage: string,
    armoredPrivateKeyString: string,
    password?: string,
  ): Promise<string | null> {
    let privateKeyObject: openpgp.PrivateKey;
    let unlockedPrivateKey: openpgp.PrivateKey;

    try {
      privateKeyObject = await this.readArmoredPrivateKey(armoredPrivateKeyString);

      if (!privateKeyObject.isDecrypted()) {
        if (!password || password.length === 0) {
          throw new Error("Private key is password-protected, but no password was provided.");
        }
        unlockedPrivateKey = await this.tryUnlockKey(privateKeyObject, password);
      } else {
        unlockedPrivateKey = privateKeyObject;
      }

      const primaryKeyID = unlockedPrivateKey.getKeyID().toHex().toUpperCase();
      const messageObject = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
      const messageTargetKeyIDs = messageObject
        .getEncryptionKeyIDs()
        .map((keyid: { toHex: () => string }) => keyid.toHex().toUpperCase());

      let overallSuitableKeyFoundAndDecrypted = false;

      for (const targetID of messageTargetKeyIDs) {
        let foundMatchingPrivateKeyMaterialThisIteration = false;

        if (
          primaryKeyID === targetID ||
          unlockedPrivateKey.getFingerprint().toUpperCase().endsWith(targetID)
        ) {
          foundMatchingPrivateKeyMaterialThisIteration = true;
          if (unlockedPrivateKey.isDecrypted()) {
            overallSuitableKeyFoundAndDecrypted = true;
          } else {
            // Critical issue, but handled by the check below
          }
        }

        const subkeys = unlockedPrivateKey.getSubkeys();
        for (const subKey of subkeys) {
          const subKeyID = subKey.getKeyID().toHex().toUpperCase();
          if (subKeyID === targetID || subKey.getFingerprint().toUpperCase().endsWith(targetID)) {
            foundMatchingPrivateKeyMaterialThisIteration = true;
            if (subKey.keyPacket instanceof openpgp.SecretSubkeyPacket && subKey.isDecrypted()) {
              overallSuitableKeyFoundAndDecrypted = true;
            } else if (
              subKey.keyPacket instanceof openpgp.SecretSubkeyPacket &&
              !subKey.isDecrypted()
            ) {
             // Critical issue, but handled by the check below
            }
            break;
          }
        }
        if (!foundMatchingPrivateKeyMaterialThisIteration) {
            // No match found for this specific target ID
        }
      }

      if (!overallSuitableKeyFoundAndDecrypted && messageTargetKeyIDs.length > 0) {
        throw new Error("No suitable and decrypted private key found for message targets.");
      }

      const decryptionResult = await openpgp.decrypt({
        message: messageObject,
        decryptionKeys: unlockedPrivateKey,
        date: new Date(),
      });

      const { data: decryptedData, signatures } = decryptionResult;

      if (decryptedData === null || typeof decryptedData === "undefined") {
        return null;
      }

      if (signatures && signatures.length > 0) {
        for (const sigResult of signatures) {
          try {
            await sigResult.verified;
          } catch (sigError: any) {
          }
        }
      }

      if (typeof decryptedData === "string") {
        return decryptedData;
      } else if (decryptedData instanceof Uint8Array) {
        return new TextDecoder().decode(decryptedData);
      }

      return null;
    } catch (error: any) {
      return null;
    }
  }

  public async readArmoredPrivateKey(armoredKey: string): Promise<openpgp.PrivateKey> {
    if (!armoredKey || typeof armoredKey !== "string" || armoredKey.trim() === "") {
      throw new Error("Invalid armored private key provided: not a string or is empty.");
    }
    try {
      const privateKeyObject = await openpgp.readPrivateKey({ armoredKey });
      return privateKeyObject;
    } catch (error: any) {
      throw new Error(`Failed to read/parse armored private key: ${error.message}`);
    }
  }

  public async tryUnlockKey(
    privateKeyObject: openpgp.PrivateKey,
    password: string,
  ): Promise<openpgp.PrivateKey> {
    const primaryKeyIDForLog = privateKeyObject.getKeyID().toHex().toUpperCase();

    if (privateKeyObject.isDecrypted()) {
      return privateKeyObject;
    }

    try {
      const unlockedKey = await openpgp.decryptKey({
        privateKey: privateKeyObject,
        passphrase: password,
      });

      let allEssentialKeysDecrypted = unlockedKey.isDecrypted();

      const unlockedSubkeys = unlockedKey.getSubkeys();
      if (unlockedSubkeys.length > 0) {
        unlockedSubkeys.forEach((sk) => {
          let isSecret = false;
          if (sk.keyPacket instanceof openpgp.SecretSubkeyPacket) {
            isSecret = true;
          }
          if (isSecret && !sk.isDecrypted()) {
            allEssentialKeysDecrypted = false;
          }
        });
      }

      if (!allEssentialKeysDecrypted) {
        throw new Error(
          `Failed to fully unlock key ${primaryKeyIDForLog}: Key or an essential subkey remained encrypted. Incorrect password?`,
        );
      }

      return unlockedKey;
    } catch (error: any) {
      throw new Error(`Error unlocking key ${primaryKeyIDForLog}: ${error.message}`);
    }
  }
}

export class Base64Utils {
  static decode(str: string): Uint8Array {
    try {
      const binaryString = atob(str);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes;
    } catch (e: any) {
      throw new Error("Invalid Base64 string for decoding.");
    }
  }
  static encode(buffer: Uint8Array): string {
    const binString = Array.from(buffer)
      .map((byte) => String.fromCharCode(byte))
      .join("");
    return btoa(binString);
  }
}

export async function verifyModulus(
  gnupg: GPG,
  armoredModulus: string,
  _expectedFingerprint: string = SRP_MODULUS_KEY_FINGERPRINT,
): Promise<Uint8Array> {
  const verified = await gnupg.decrypt(armoredModulus);
  if (!verified || !verified.valid) {
    const actualFingerprint = verified?.fingerprint || "unknown";
    throw new Error(
      `Modulus signature verification failed or key mismatch. Expected fingerprint ${_expectedFingerprint}, got ${actualFingerprint}. Valid: ${verified?.valid}`,
    );
  }
  if (!verified.data) {
    throw new Error("Modulus verification returned no data.");
  }
  return Base64Utils.decode(verified.data.trim());
}