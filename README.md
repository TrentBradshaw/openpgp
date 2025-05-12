```
in openpgptest.ts
// add your privatekey to the src dir and ref it
const keyFilePath = path.join(baseDir, "src", "privatekey.asc");
// add your encrypted message body to src dir and ref it
const messageFilePath = path.join(baseDir, "src", "messageTest.txt");
// add password which was used to export the key
const privateKeyPassword = "";
```
