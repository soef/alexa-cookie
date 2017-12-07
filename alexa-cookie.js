"use strict";

/**
 * partly based on Amazon Alexa Remote Control (PLAIN shell)
 * http://blog.loetzimmer.de/2017/10/amazon-alexa-hort-auf-die-shell-echo.html
 */

let https = require('https');
let querystring = require('querystring');
let url = require('url');


let request = function (options, callback) {

    // options.path = options.url.replace(/^https:\/\//, '');
    // let ar = options.path.match(/^([^\/]+)([\/]*.*$)/);
    // options.host = ar[1];
    // options.path = ar[2];
    // delete options.url;

    let removeContentLength;
    if (options.headers && options.headers['Content-Length']) {
        if (!options.body) delete options.headers['Content-Length'];
    } else if (options.body) {
        if (!options.headers) options.headers = {};
        options.headers['Content-Length'] = options.body.length;
        removeContentLength = true;
    }

    let req = https.request(options, function getDevices(res) {
        let body  = "";
        let r = res;

        if (options.followRedirects !== false && res.statusCode >= 300 && res.statusCode < 400) {
            //options.url = res.headers.location;
            let u = url.parse(res.headers.location);
            options.host = u.host;
            options.path = u.path;
            return request (options, callback);
        } else {
            res.on ('data', function (chunk) {
                body += chunk;
            });

            res.on ('end', function () {
                if (removeContentLength) delete options.headers['Content-Length'];
                callback && callback(0, res, body);
            });
        }
    });

    req.on('error', function(e) {
        if(typeof callback === 'function' && callback.length >= 2) {
            return callback (e.message, null, null);
        }
    });
    if (options && options.body) {
        req.write(options.body);
    }
    req.end();
};


function generateAlexaCookies (email, password, _options, callback) {

    if (typeof _options === 'function') {
        callback = _options;
        _options = undefined;
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

    let options = {
        host: 'alexa.amazon.de',
        path: '',
        method: 'GET',
        headers: {
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0',
            'Accept-Language': 'de,en',
            'Connection': 'keep-alive',
        },
    };

    request (options, function (error, response, body) {
        let options = {
            host: 'www.amazon.de',
            path: '/ap/signin',
            method: 'POST',
            headers: {
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0',
                'Accept-Language': 'de,en',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                Referer: response.req._header.host + response.req.path,
                Cookie: addCookies (response.headers),
                //'Accept-Encoding': 'deflate, gzip',
            },
            gzip: true,
            body: querystring.stringify (getFields (body))
        };

        request (options, function (error, response, body) {
            options.host = 'www.amazon.de';
            options.path = '/ap/signin';
            options.method = 'POST';
            options.headers.Cookie = addCookies (response.headers);
            let ar = options.headers.Cookie.match (/session-id=([^;]+)/);
            options.headers.Referer = `https://www.amazon.de/ap/signin/${ar[1]}`;
            options.body = getFields (body);
            options.body.email = email;
            options.body.password = password;
            options.body = querystring.stringify (options.body);
            options.followRedirects = false;

            request (options, function (error, response, body) {
                options.method = 'GET';
                options.headers.Referer = 'https://alexa.amazon.de/spa/index.html';
                options.headers.Origin = 'https://alexa.amazon.de';
                options.host = 'layla.amazon.de';
                options.path = '/api/language';
                options.body = '';
                options.headers.Cookie = addCookies (response.headers);
                delete options['Upgrade-Insecure-Requests'];
                request (options, function (error, response, body) {
                    let cookie = addCookies (response.headers);
                    let ar = /csrf=([^;]+)/.exec (cookie);
                    let csrf = ar ? ar[1] : undefined;
                    callback && callback(0, {
                        cookie: cookie,
                        csrf: csrf
                    })
                });
            })
        })
    });
}

module.exports = generateAlexaCookies;