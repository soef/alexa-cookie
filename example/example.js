/* jshint -W097 */
/* jshint -W030 */
/* jshint strict: false */
/* jslint node: true */
/* jslint esversion: 6 */

alexaCookie = require('../alexa-cookie');

alexaCookie('amazon@email.de', 'amazon-password', {logger: console.log}, (err, obj) => console.log('RESULT: ' + err + ' / ' + JSON.stringify(obj)));
