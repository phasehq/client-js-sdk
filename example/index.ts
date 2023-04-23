import Phase from "../dist/main/index.js";

const phase = new Phase(
  "phApp:v1:6c26e3a375aff204958574d1a04a949fd97411151c76a03cbc0922a21faf580a"
);

const testData = "hello world";

phase.encrypt(testData, "test").then((encryptedData) => {
  console.log(`encrypted ${testData}`);
  console.log(encryptedData);
});
