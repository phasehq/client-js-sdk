# Javscript Client SDK for Phase
Phase SDK to encrypt data in client-side JavaScript applications

## Install

`npm i @phase.dev/phase-js` or `yarn add @phase.dev/phase-js`

## Import

```js
import Phase from '@phase.dev/phase-js'
```

## Initialize

Initialize the SDK with your `APP_ID`:

```js
const phase = new Phase(`${APP_ID}`)
```
## Usage 

```js
const ciphertext = await phase.encrypt('hello world')
```