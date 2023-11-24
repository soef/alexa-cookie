/* jshint -W097 */
/* jshint -W030 */
/* jshint strict: false */
/* jslint node: true */
/* jslint esversion: 6 */

const alexaCookie = require('../alexa-cookie');

const config = {
    logger: console.log,
    proxyOwnIp: '...',         // required if proxy enabled: provide the own IP with which you later access the proxy.
                               // Providing/Using a hostname here can lead to issues!
                               // Needed to set up all rewriting and proxy stuff internally

    // The following options are optional. Try without them first and just use really needed ones!!

    amazonPage: 'amazon.de',   // optional: possible to use with different countries, default is 'amazon.de'
    acceptLanguage: 'de-DE',   // optional: webpage language, should match to amazon-Page, default is 'de-DE'
    userAgent: '...',          // optional: own userAgent to use for all request, overwrites default one, should not be needed
    proxyOnly: true,           // optional: should only the proxy method be used? When no email/password are provided this will set to true automatically, default: false
    setupProxy: true,          // optional: should the library setup a proxy to get cookie when automatic way did not worked? Default false!
    proxyPort: 3456,           // optional: use this port for the proxy, default is 0 means random port is selected
    proxyListenBind: '0.0.0.0',// optional: set this to bind the proxy to a special IP, default is '0.0.0.0'
    proxyLogLevel: 'info',     // optional: Loglevel of Proxy, default 'warn'
    baseAmazonPage: 'amazon.com', // optional: Change the Proxy Amazon Page - all "western countries" directly use amazon.com including australia! Change to amazon.co.jp for Japan
    amazonPageProxyLanguage: 'de_DE', // optional: language to be used for the Amazon Sign-in page the proxy calls. default is "de_DE")
    deviceAppName: '...',       // optional: name of the device app name which will be registered with Amazon, leave empty to use a default one
    formerDataStorePath: '...', // optional: overwrite path where some of the formerRegistrationData are persisted to optimize against Amazon security measures
    formerRegistrationData: { ... }, // optional/preferred: provide the result object from subsequent proxy usages here and some generated data will be reused for next proxy call too
    proxyCloseWindowHTML: '...' //  optional: use in order to override the default html displayed when the proxy window can be closed, default is '<b>Amazon Alexa Cookie successfully retrieved. You can close the browser.</b>'
};


alexaCookie.generateAlexaCookie(/*'amazon@email.de', 'amazon-password',*/ config, (err, result) => {
    console.log('RESULT: ' + err + ' / ' + JSON.stringify(result));
    if (result && result.csrf) {
        alexaCookie.stopProxyServer();
    }
});
