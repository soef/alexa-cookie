# alexa-cookie

Library to generate a cookie including a csrf for alexa remote

<!--
[![NPM version](http://img.shields.io/npm/v/alexa-remote.svg)](https://www.npmjs.com/package/alexa-remote)
[![Tests](http://img.shields.io/travis/soef/alexa-remote/master.svg)](https://travis-ci.org/soef/alexa-remote)
-->
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/soef/alexa-remote/blob/master/LICENSE)

## Example:
```javascript 1.8
const alexaCookie = require('alexa-cookie');

const options = { // options is optional at all
    logger: console.log,      // optional: Logger instance to get (debug) logs
    amazonPage: 'amazon.com', // optional: possible to use with different countries, default is 'amazon.de'
    acceptLanguage: 'en-US',  // optional: webpage language, should match to amazon-Page, default is 'de-DE'
    userAgent: '...'          // optional: own userAgent to use for all request, overwrites default one
}

alexaCookie('amazon-email', 'password', options, function (err, result) {
    console.log('cookie: ' + result.cookie);
    console.log('csrf: '   + result.csrf);
});

````

## Info:
Partly based on [Amazon Alexa Remote Control](http://blog.loetzimmer.de/2017/10/amazon-alexa-hort-auf-die-shell-echo.html) (PLAIN shell) and [alexa-remote-control](https://github.com/thorsten-gehrig/alexa-remote-control)
Thank you for that work.

## Changelog:

### 0.1.x
* (Apollon77) 0.1.2: Log the used user-Agent, Accept-Language and Login-URL
* (Apollon77) 0.1.1: update to get it working again and sync to [alexa-remote-control](https://github.com/thorsten-gehrig/alexa-remote-control)

### 0.0.x
* Versions by soef
