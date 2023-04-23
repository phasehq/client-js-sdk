"use strict";
const phase = require('../dist/index');
const testData = 'hello world';
phase.encrypt(testData, 'test').then((encryptedData) => {
    console.log(`encrypted ${testData}`);
    console.log(encryptedData);
});
