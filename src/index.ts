import { executePgpDecryptionTest } from './openpgptest'; 

async function runIsolatedTest() {
    console.log("Starting isolated project PGP test execution...");
    await executePgpDecryptionTest("Isolated Node.js Project");
    console.log("Isolated project PGP test execution finished.");
}

runIsolatedTest();
