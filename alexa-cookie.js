/* jshint -W097 */
/* jshint -W030 */
/* jshint strict: false */
/* jslint node: true */
/* jslint esversion: 6 */
"use strict";

/**
 * partly based on Amazon Alexa Remote Control (PLAIN shell)
 * http://blog.loetzimmer.de/2017/10/amazon-alexa-hort-auf-die-shell-echo.html AND on
 * https://github.com/thorsten-gehrig/alexa-remote-control
 */

const https = require('https');
const querystring = require('querystring');
const url = require('url');

const defaultAmazonPage = 'amazon.de';
const defaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0';
const defaultAcceptLanguage = 'de-DE';

function generateAlexaCookies (email, password, _options, callback) {

     function request(options, info, callback) {

        _options.logger && _options.logger('Alexa-Cookie: Sending Request with ' + JSON.stringify(options));
        if (typeof info === 'function') {
            callback = info;
            info = {
                requests: []
            };
        }

        let removeContentLength;
        if (options.headers && options.headers['Content-Length']) {
            if (!options.body) delete options.headers['Content-Length'];
        } else if (options.body) {
            if (!options.headers) options.headers = {};
            options.headers['Content-Length'] = options.body.length;
            removeContentLength = true;
        }

        let req = https.request(options, function (res) {
            let body  = "";
            let r = res;
            info.requests.push({options: options, response: res});

            if (options.followRedirects !== false && res.statusCode >= 300 && res.statusCode < 400) {
                _options.logger && _options.logger('Alexa-Cookie: Response (' + res.statusCode + ')' + (res.headers.location ? ' - Redirect to ' + res.headers.location : ''));
                //options.url = res.headers.location;
                let u = url.parse(res.headers.location);
                options.host = u.host;
                options.path = u.path;
                options.method = 'GET';
                options.body = '';
                options.headers.Cookie = addCookies (res.headers);

                res.connection.end();
                return request (options, info, callback);
            } else {
                _options.logger && _options.logger('Alexa-Cookie: Response (' + res.statusCode + ')');
                res.on ('data', function (chunk) {
                    body += chunk;
                });

                res.on ('end', function () {
                    if (removeContentLength) delete options.headers['Content-Length'];
                    res.connection.end();
                    callback && callback(0, res, body, info);
                });
            }
        });

        req.on('error', function(e) {
            if(typeof callback === 'function' && callback.length >= 2) {
                return callback (e, null, null, info);
            }
        });
        if (options && options.body) {
            req.write(options.body);
        }
        req.end();
    }

    if (typeof _options === 'function') {
        callback = _options;
        _options = {};
    }

    let Cookie = '';

    function addCookies (headers) {
        if (!headers || !headers['set-cookie']) return Cookie;
        for (let cookie of headers['set-cookie']) {
            cookie = cookie.replace (/(^[^;]+;).*/, '$1') + ' ';
            if (Cookie.indexOf (cookie) === -1 && cookie !== 'ap-fid=""; ') {
                if (Cookie && !Cookie.endsWith ('; ')) Cookie += '; ';
                Cookie += cookie;
            }
        }
        Cookie = Cookie.replace (/[; ]*$/, '');
        return Cookie;
    }

    function getFields (body) {
        body = body.replace (/[\n\r]/g, ' ');
        let re = /^.*?("hidden"\s*name=".*$)/;
        let ar = re.exec (body);
        if (!ar || ar.length < 2) return {};
        let h;
        re = /.*?name="([^"]+)"[\s^\s]*value="([^"]+).*?"/g;
        let data = {};
        while ((h = re.exec (ar[1])) !== null) {
            if (h[1] !== 'rememberMe') {
                data[h[1]] = h[2];
            }
        }
        return data;
    }

    _options.amazonPage = _options.amazonPage || defaultAmazonPage;
    _options.userAgent = _options.userAgent || defaultUserAgent;
    _options.acceptLanguage = _options.acceptLanguage || defaultAcceptLanguage;

    // get first cookie and write redirection target into referer
    let options = {
        host: 'alexa.' + _options.amazonPage,
        path: '',
        method: 'GET',
        headers: {
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': _options.userAgent,
            'Accept-Language': _options.acceptLanguage,
            'Connection': 'keep-alive',
            //'Accept-Encoding': 'deflate, gzip',
            'Accept': '*/*'
        },
    };
    _options.logger && _options.logger('Alexa-Cookie: Step 1: get first cookie and authentication redirect');
    request (options, (error, response, body, info) => {

        let lastRequestOptions = info.requests[info.requests.length-1].options;
        // login empty to generate session
        let options = {
            host: 'www.' + _options.amazonPage,
            path: '/ap/signin',
            method: 'POST',
            headers: {
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': _options.userAgent,
                'Accept-Language': _options.acceptLanguage,
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'https://' + lastRequestOptions.host + lastRequestOptions.path,
                'Cookie': addCookies (response.headers),
                //'Accept-Encoding': 'deflate, gzip',
                'Accept': '*/*'
            },
            gzip: true,
            body: querystring.stringify (getFields (body))
        };
        _options.logger && _options.logger('Alexa-Cookie: Step 2: login empty to generate session');
        request (options, (error, response, body, info) => {
            // login with filled out form
            //  !!! referer now contains session in URL
            options.host = 'www.' + _options.amazonPage;
            options.path = '/ap/signin';
            options.method = 'POST';
            options.headers.Cookie = addCookies (response.headers);
            let ar = options.headers.Cookie.match (/session-id=([^;]+)/);
            options.headers.Referer = `https://www.${_options.amazonPage}/ap/signin/${ar[1]}`;
            options.body = getFields (body);
            options.body.email = email;
            options.body.password = password;
            options.body = querystring.stringify (options.body);

            _options.logger && _options.logger('Alexa-Cookie: Step 3: login with filled form, referer contains session id');
            request (options, (error, response, body, info) => {
                let lastRequestOptions = info.requests[info.requests.length-1].options;

                // check whether the login has been successful or exit otherwise
                if (!lastRequestOptions.host.startsWith('alexa') || !lastRequestOptions.path.endsWith('.html')) {
                    let err = new Error('Authentication failed');
                    if (body.indexOf('Zum besseren Schutz Ihres Kontos geben Sie bitte nochmals Ihr Passwort ein, und geben Sie dann die Zeichen ein, die in der Abbildung unten gezeigt werden.')) {
                        err = new Error('Captcha needed');
                    }
                    callback(err, null);
                    return;
                }

                // get CSRF
                options.method = 'GET';
                options.headers.Referer = 'https://alexa.' + _options.amazonPage + '/spa/index.html';
                options.headers.Origin = 'https://alexa.' + _options.amazonPage;
                options.host = 'layla.' + _options.amazonPage;
                options.path = '/api/language';
                options.body = '';
                options.headers.Cookie = addCookies (null);
                delete options.headers['Upgrade-Insecure-Requests'];
                delete options.headers['Accept-Language'];
                delete options.headers['Content-type'];

                _options.logger && _options.logger('Alexa-Cookie: Step 4: get CSRF');
                request (options, (error, response, body, info) => {
                    let cookie = addCookies (response.headers);
                    let ar = /csrf=([^;]+)/.exec (cookie);
                    let csrf = ar ? ar[1] : undefined;
                    callback && callback(null, {
                        cookie: cookie,
                        csrf: csrf
                    });
                });
            });
        });
    });
}

module.exports = generateAlexaCookies;
