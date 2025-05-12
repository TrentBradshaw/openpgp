import * as fs from 'fs-extra';
import * as path from 'node:path';
import * as openpgp from 'openpgp';
import { OpenPGPImplementation } from './openpgp';

export async function executePgpDecryptionTest(environmentLabel: string): Promise<void> {
  const logPrefix = `[PGP_TEST] [${environmentLabel}]`;

  try {
    const nodeCrypto = require('node:crypto');
  } catch (e: any) {

  }


  const baseDir = process.cwd();
  const keyFilePath = path.join(baseDir, "src", "privatekey.asc"); // add your privatekey to the src dir and ref it
  const messageFilePath = path.join(baseDir, "src", "messageTest.txt"); // add your encrypted message body to src dir and ref it
  const privateKeyPassword = ""; // add password

  let armoredPrivateKey: string;
  let armoredEncryptedMessage: string;

  try {
    armoredPrivateKey = await fs.readFile(keyFilePath, "utf8");
    armoredEncryptedMessage = await fs.readFile(messageFilePath, "utf8");
  } catch (error: any) {

    return;
  }

  const pgpTool = new OpenPGPImplementation();
  try {
    const decryptedMessage = await pgpTool.decryptEncryptedMessage(
      armoredEncryptedMessage,
      armoredPrivateKey,
      privateKeyPassword,
    );

    if (decryptedMessage !== null) {
        console.log(decryptedMessage);
    } else {

      throw new Error("Decryption returned null");
    }
  } catch (error: any) {

    throw error;
  }

}