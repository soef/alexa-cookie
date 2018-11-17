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
 * and much enhanced ...
 */

const https = require('https');
const querystring = require('querystring');
const url = require('url');
const os = require('os');
const modifyResponse = require('http-proxy-response-rewrite');
const express = require('express');
const proxy = require('http-proxy-middleware');
const cookieFunc = require('cookie');

const defaultAmazonPage = 'amazon.de';
const defaultAlexaServiceHost = 'layla.amazon.de';
const defaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0';
const defaultUserAgentLinux = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36';
//const defaultUserAgentMacOs = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36';
const defaultAcceptLanguage = 'de-DE';

let proxyServer;

function customStringify(v, func, intent) {
    const cache = new Map();
    return JSON.stringify(v, function(key, value) {
        if (typeof value === 'object' && value !== null) {
            if (cache.get(value)) {
                // Circular reference found, discard key
                return;
            }
            // Store value in our map
            cache.set(value, true);
        }
        return value;
    }, intent);
}

function addCookies(Cookie, headers) {
    if (!headers || !headers['set-cookie']) return Cookie;
    for (let cookie of headers['set-cookie']) {
        cookie = cookie.replace(/(^[^;]+;).*/, '$1') + ' ';
        if (Cookie.indexOf(cookie) === -1 && cookie !== 'ap-fid=""; ') {
            if (Cookie && !Cookie.endsWith('; ')) Cookie += '; ';
            Cookie += cookie;
        }
    }
    Cookie = Cookie.replace(/[; ]*$/, '');
    return Cookie;
}

function generateAlexaCookie(email, password, _options, callback) {

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

        let req = https.request(options, function(res) {
            let body = "";
            let r = res;
            info.requests.push({
                options: options,
                response: res
            });

            if (options.followRedirects !== false && res.statusCode >= 300 && res.statusCode < 400) {
                _options.logger && _options.logger('Alexa-Cookie: Response (' + res.statusCode + ')' + (res.headers.location ? ' - Redirect to ' + res.headers.location : ''));
                //options.url = res.headers.location;
                let u = url.parse(res.headers.location);
                if (u.host) options.host = u.host;
                options.path = u.path;
                options.method = 'GET';
                options.body = '';
                options.headers.Cookie = Cookie = addCookies(Cookie, res.headers);

                res.connection.end();
                return request(options, info, callback);
            } else {
                _options.logger && _options.logger('Alexa-Cookie: Response (' + res.statusCode + ')');
                res.on('data', function(chunk) {
                    body += chunk;
                });

                res.on('end', function() {
                    if (removeContentLength) delete options.headers['Content-Length'];
                    res.connection.end();
                    callback && callback(0, res, body, info);
                });
            }
        });

        req.on('error', function(e) {
            if (typeof callback === 'function' && callback.length >= 2) {
                return callback(e, null, null, info);
            }
        });
        if (options && options.body) {
            req.write(options.body);
        }
        req.end();
    }

    function getFields(body) {
        body = body.replace(/[\n\r]/g, ' ');
        let re = /^.*?("hidden"\s*name=".*$)/;
        let ar = re.exec(body);
        if (!ar || ar.length < 2) return {};
        let h;
        re = /.*?name="([^"]+)"[\s^\s]*value="([^"]+).*?"/g;
        let data = {};
        while ((h = re.exec(ar[1])) !== null) {
            if (h[1] !== 'rememberMe') {
                data[h[1]] = h[2];
            }
        }
        return data;
    }

    function getCSRFFromCookies(cookie, _options, callback) {
        // get CSRF
        let options = {
            'host': _options.alexaServiceHost,
            'path': '/api/language',
            'method': 'GET',
            'headers': {
                'DNT': '1',
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36',
                'Connection': 'keep-alive',
                'Referer': 'https://alexa.' + _options.amazonPage + '/spa/index.html',
                'Cookie': cookie,
                'Accept': '*/*',
                'Origin': 'https://alexa.' + _options.amazonPage
            }
        };

        _options.logger && _options.logger('Alexa-Cookie: Step 4: get CSRF');
        request(options, (error, response, body, info) => {
            cookie = addCookies(cookie, response.headers);
            let ar = /csrf=([^;]+)/.exec(cookie);
            let csrf = ar ? ar[1] : undefined;
            _options.logger && _options.logger('Alexa-Cookie: Result: csrf=' + csrf + ', Cookie=' + cookie);
            callback && callback(null, {
                cookie: cookie,
                csrf: csrf
            });
        });
    }

    function initConfig() {
        _options.amazonPage = _options.amazonPage || defaultAmazonPage;
        _options.logger && _options.logger('Alexa-Cookie: Use as Login-Amazon-URL: ' + _options.amazonPage);

        _options.alexaServiceHost = _options.alexaServiceHost || defaultAlexaServiceHost;
        _options.logger && _options.logger('Alexa-Cookie: Use as Alexa-Service-Host: ' + _options.alexaServiceHost);

        if (!_options.userAgent) {
            let platform = os.platform();
            if (platform === 'win32') {
                _options.userAgent = defaultUserAgent;
            }
            /*else if (platform === 'darwin') {
                _options.userAgent = defaultUserAgentMacOs;
            }*/
            else {
                _options.userAgent = defaultUserAgentLinux;
            }
        }
        _options.logger && _options.logger('Alexa-Cookie: Use as User-Agent: ' + _options.userAgent);

        _options.acceptLanguage = _options.acceptLanguage || defaultAcceptLanguage;
        _options.logger && _options.logger('Alexa-Cookie: Use as Accept-Language: ' + _options.acceptLanguage);

        if (_options.setupProxy && !_options.proxyOwnIp) {
            _options.logger && _options.logger('Alexa-Cookie: Own-IP Setting muissing for Proxy. Disabling!');
            _options.setupProxy = false;
        }
        if (_options.setupProxy) {
            _options.setupProxy = true;
            _options.proxyPort = _options.proxyPort || 0;
            _options.proxyListenBind = _options.proxyListenBind || '0.0.0.0';
            _options.logger && _options.logger('Alexa-Cookie: Proxy-Mode enabled if needed: ' + _options.proxyOwnIp + ':' + _options.proxyPort + ' to listen on ' + _options.proxyListenBind);
        } else {
            _options.setupProxy = false;
            _options.logger && _options.logger('Alexa-Cookie: Proxy mode disabled');
        }
        _options.proxyLogLevel = _options.proxyLogLevel || 'warn';
        _options.amazonPageProxyLanguage = _options.amazonPageProxyLanguage || 'de';
    }

    if (typeof _options === 'function') {
        callback = _options;
        _options = {};
    }

    let Cookie = '';

    initConfig();

    if (!_options.proxyOnly) {

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
                'Accept': '*/*'
            },
        };
        _options.logger && _options.logger('Alexa-Cookie: Step 1: get first cookie and authentication redirect');
        request(options, (error, response, body, info) => {
            if (error) {
                callback && callback(error, null);
                return;
            }

            let lastRequestOptions = info.requests[info.requests.length - 1].options;
            // login empty to generate session
            Cookie = addCookies(Cookie, response.headers);
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
                    'Cookie': Cookie,
                    'Accept': '*/*'
                },
                gzip: true,
                body: querystring.stringify(getFields(body))
            };
            _options.logger && _options.logger('Alexa-Cookie: Step 2: login empty to generate session');
            request(options, (error, response, body, info) => {
                if (error) {
                    callback && callback(error, null);
                    return;
                }

                // login with filled out form
                //  !!! referer now contains session in URL
                options.host = 'www.' + _options.amazonPage;
                options.path = '/ap/signin';
                options.method = 'POST';
                options.headers.Cookie = Cookie = addCookies(Cookie, response.headers);
                let ar = options.headers.Cookie.match(/session-id=([^;]+)/);
                options.headers.Referer = `https://www.${_options.amazonPage}/ap/signin/${ar[1]}`;
                options.body = getFields(body);
                options.body.email = email || '';
                options.body.password = password || '';
                options.body = querystring.stringify(options.body, null, null, {
                    encodeURIComponent: encodeURIComponent
                });

                _options.logger && _options.logger('Alexa-Cookie: Step 3: login with filled form, referer contains session id');
                request(options, (error, response, body, info) => {
                    if (error) {
                        callback && callback(error, null);
                        return;
                    }

                    let lastRequestOptions = info.requests[info.requests.length - 1].options;

                    // check whether the login has been successful or exit otherwise
                    if (!lastRequestOptions.host.startsWith('alexa') || !lastRequestOptions.path.endsWith('.html')) {
                        let errMessage = 'Login unsuccessfull. Please check credentials.';
                        const amazonMessage = body.match(/auth-warning-message-box[\S\s]*"a-alert-heading">([^<]*)[\S\s]*<li><[^>]*>\s*([^<\n]*)\s*</);
                        if (amazonMessage && amazonMessage[1] && amazonMessage[2]) {
                            errMessage = `Amazon-Login-Error: ${amazonMessage[1]}: ${amazonMessage[2]}`;
                        }
                        if (_options.setupProxy) {
                            if (proxyServer) {
                                errMessage += ` You can try to get the cookie manually by opening http://${_options.proxyOwnIp}:${_options.proxyPort}/ with your browser.`;
                            } else {
                                initAmazonProxy(_options, email, password, prepareResult, (server) => {
                                    proxyServer = server;
                                    if (_options.proxyPort === 0) {
                                        _options.proxyPort = proxyServer.address().port;
                                    }
                                    errMessage += ` You can try to get the cookie manually by opening http://${_options.proxyOwnIp}:${_options.proxyPort}/ with your browser.`;
                                    callback && callback(new Error(errMessage), null);
                                });
                                return;
                            }
                        }
                        callback && callback(new Error(errMessage), null);
                        return;
                    }

                    return getCSRFFromCookies(Cookie, _options, callback);
                });
            });
        });
    } else {
        initAmazonProxy(_options, email, password, prepareResult, (server) => {
            proxyServer = server;
            if (_options.proxyPort === 0) {
                _options.proxyPort = proxyServer.address().port;
            }
            const errMessage = `You can try to get the cookie manually by opening http://${_options.proxyOwnIp}:${_options.proxyPort}/ with your browser.`;
            callback && callback(new Error(errMessage), null);

            const cookie = 'frc=2Nojc+vglmV9FvW/R+MAi/MVxRp3oXsoT7icWQKRieyBZmfUWQaxwnYmZqZdlTIt2oD397pgwJT8f2SuJwdtm63RyzPGy+tvgoeznF/IMimHm73JFnu/Q/bPBjEtFIyN1IJd6mfxm17115cnGqsljLExRGCltStG4OJ1pwbh5VD5zl2CZTRsclZPB+G6tqX5vbGIVKf+qLl82ruhV+dcr+MV5VhL6BjPT4i5Z+Cx6Z+r4zX4zlgojcmuprG0fN0cE/mTjTuEIbVGfBiFnhosR3JjbspJd6u5QEcHUM+sPORL6DI1KS+qYIwy9SZ1EJiKowya0UamjMn8cc6cToTLP0n78+memnTc/d1HiUeOfTHFwN9lDOZQ0kUkwM6KJsrGAKI7SFikkxIYtzx207IQIA4LaTH9VV+AEQ==; map-md=eyJkZXZpY2VfdXNlcl9kaWN0aW9uYXJ5IjpbXSwiZGV2aWNlX3JlZ2lzdHJhdGlvbl9kYXRhIjp7InNvZnR3YXJlX3ZlcnNpb24iOiIxIn0sImFwcF9pZGVudGlmaWVyIjp7ImFwcF92ZXJzaW9uIjoiMi4yLjIyMzgzMCIsImJ1bmRsZV9pZCI6ImNvbS5hbWF6b24uZWNobyJ9fQ==; session-id=140-0501137-6350005; session-id-time=2173017173l; session-id=140-0501137-6350005; session-id-time=2173017173l; csm-hit=tb:WG92449GJ6QPQQ2DHC76+s-WG92449GJ6QPQQ2DHC76|1542297177066&adb:adblk_no; frc=2Nojc+vglmV9FvW/R+MAi/MVxRp3oXsoT7icWQKRieyBZmfUWQaxwnYmZqZdlTIt2oD397pgwJT8f2SuJwdtm63RyzPGy+tvgoeznF/IMimHm73JFnu/Q/bPBjEtFIyN1IJd6mfxm17115cnGqsljLExRGCltStG4OJ1pwbh5VD5zl2CZTRsclZPB+G6tqX5vbGIVKf+qLl82ruhV+dcr+MV5VhL6BjPT4i5Z+Cx6Z+r4zX4zlgojcmuprG0fN0cE/mTjTuEIbVGfBiFnhosR3JjbspJd6u5QEcHUM+sPORL6DI1KS+qYIwy9SZ1EJiKowya0UamjMn8cc6cToTLP0n78+memnTc/d1HiUeOfTHFwN9lDOZQ0kUkwM6KJsrGAKI7SFikkxIYtzx207IQIA4LaTH9VV+AEQ==; map-md=eyJkZXZpY2VfdXNlcl9kaWN0aW9uYXJ5IjpbXSwiZGV2aWNlX3JlZ2lzdHJhdGlvbl9kYXRhIjp7InNvZnR3YXJlX3ZlcnNpb24iOiIxIn0sImFwcF9pZGVudGlmaWVyIjp7ImFwcF92ZXJzaW9uIjoiMi4yLjIyMzgzMCIsImJ1bmRsZV9pZCI6ImNvbS5hbWF6b24uZWNobyJ9fQ==; ubid-main=130-5144968-3386309; x-main=LdOjJ0cqyQwwDTP6pGKPW3DV88Xob3Ju; at-main=Atza|IwEBIOeQbHLysF0r1Pw7ad_I5RRFgoO2QeYqslBHG_jonsWyYHdJ9EKslMO7A12kRJNmWwVlOQXth-6-4TD6NmItXNxrW_fzylB_K8sObJEEN7e3NYljuVT9KcNBXnVMizuz1x9UUH797YIOBEUnb6HPtiLpN_8xIVQ2x_FoKhLe8vpZpXCHUdqx5Pz5mmdmp9_m3aumi1sH13CZ7Czyk5qn9iAgdGMzQ7_GxdQ4cvDbt_ODM14eKU_kx2oz1-OYVqA6dmONPMB2hNl5c9zeQxPf6esTuY1AiLmCZOeJoY4lvN19lzbgfjl2ujk9_SHbFENpHOSI4dp3rwBbt2IJJ4eN3PS9q6fkOeDyJ-BJ1dNsw_IfgHBUnGXZC5Q_Bm-Kl1FIJ62ntIKqe7BCD0VK8Tg6HEuI; sess-at-main="FjYfhki0vYbIvKUTFzLzkplD3TIUbfJ1IeIfOHmfFl8="';
            const queryParams = {
                "openid.assoc_handle": "amzn_dp_project_dee_ios",
                "aToken": "Atza|IwEBIPMfK3sviMP7z-rg6hup33cbV-s7UnHhqul-iQNhnlB7Fvx4tClMok7B8YdPcpMj0x3l2VcAiiNQp4iB5EtSf2LaG7yLbrclSe09J6tbPIK97TXimNPv3HQs5o-Arzi_Vn3KpDqf-J8aYXMEq8DqgF7G8yW6xW7wuJROqfIYHisIWElMuvEtlvr_YUvfrwEFLHwJi7M24EHLwgywlKqSpKVr9Xc1p_h2aoxRvS-JdWuL0C30oC39HSeWZzsyZsA2HxZPzVVyIOU-IkGuifa0vW1etBu61zE6NtzKw-HNQazPfzI_coV3O1oU8oAY06vLRxkRaIySTDS3sR2TkAQiDkvdJDX7Kgh7vVHkjRIcDqiH4Fgs9lRyJabjnOJZOXt-wAmrQRbP9lpngdqDhqQQY5mk",
                "openid.claimed_id": "https://www.amazon.com/ap/id/amzn1.account.AETCXLYA7IMWWOY5RB7AC6G2JPDQ",
                "openid.identity": "https://www.amazon.com/ap/id/amzn1.account.AETCXLYA7IMWWOY5RB7AC6G2JPDQ",
                "openid.mode": "id_res",
                "openid.ns": "http://specs.openid.net/auth/2.0",
                "openid.op_endpoint": "https://www.amazon.com/ap/signin",
                "openid.response_nonce": "2018-11-15T15:25:50Z5046798436609149016",
                "openid.return_to": "https://www.amazon.com/ap/maplanding",
                "openid.signed": "assoc_handle,aToken,claimed_id,identity,mode,ns,op_endpoint,response_nonce,return_to,ns.pape,pape.auth_policies,pape.auth_time,oa2.access_token,oa2.token_type,oa2.scope,signed",
                "openid.ns.pape": "http://specs.openid.net/extensions/pape/1.0",
                "openid.pape.auth_policies": "http://schemas.openid.net/pape/policies/2007/06/none",
                "openid.pape.auth_time": "2018-11-15T15:25:50Z",
                "openid.sig": "54zBRuPRKgZz2gnC2IDzeef40wfYyPhra9uWlewt4wY=",
                "serial": "",
                "openid.oa2.access_token": "Atna|EwICILLrI-mCEfBn7wcLNgd7_0Ub1x8B-2ynGJ95WvC2uP0CCSca3mowGKItPPTh1XkzHIpZYeteZbHDGdipzt_tuvBepPPkzKpPQemnHOyNSiZBfHVzGze7kXUOYdq1tWzIj39n4UHS-ohd_UNj57HIhulS1p3ExtKN9XzhvEna0lTGau3-tdtw5JB9hkGMu0hagWvaOAy8rMOUr7WnrS8BQVHK3D8Vaa3l4sJAOGaofQR0IBrOW635ip-Zo6-Dgvzz9pkFcnwV4dKQqEuw4fV-QFBv9rGkRkKrpjmoLLd01ie3_w6E3sv3lMPpKOq8vvrViLZ2x5Zhepw6FYEbzp_W7XQm",
                "openid.oa2.token_type": "bearer",
                "openid.ns.oa2": "http://www.amazon.com/ap/ext/oauth/2",
                "openid.oa2.scope": "device_auth_access"
            };
            handleTokenRegistration(cookie, queryParams, _options, callback);
        });
    }

    function prepareResult(err, cookie, queryParams) {
        if (err || !queryParams['openid.oa2.access_token']) {
            callback && callback(err, cookie);
            return;
        }
        handleTokenRegistration(cookie, queryParams, _options, callback);
    }

    function handleTokenRegistration(cookie, queryParams, _options, callback) {
        const deviceSerialBuffer = Buffer.alloc(16);
        for (let i = 0; i < 16; i++) {
            deviceSerialBuffer.writeUInt8(Math.floor(Math.random() * 255), i);
        }
        const deviceSerial = deviceSerialBuffer.toString('hex');
        const cookies = cookieFunc.parse(cookie);

        const registerData = {
            "requested_extensions": [
                "device_info",
                "customer_info"
            ],
            "cookies": {
                "website_cookies": [
                    /*{
                        "Value": cookies["session-id-time"],
                        "Name": "session-id-time"
                    }*/
                ],
                "domain": ".amazon.com"
            },
            "registration_data": {
                "domain": "Device",
                "app_version": "2.2.223830.0",
                "device_type": "A2IVLV5VM2W81",
                "device_name": "%FIRST_NAME%\u0027s%DUPE_STRATEGY_1ST%ioBroker Alexa2",
                "os_version": "11.4.1",
                "device_serial": deviceSerial,
                "device_model": "iPhone",
                "app_name ": "ioBroker Alexa2",
                "software_version": "1"
            },
            "auth_data": {
                "access_token": queryParams['openid.oa2.access_token']
            },
            "user_context_map": {
                "frc": cookies.frc
            },
            "requested_token_type": [
                "bearer",
                "mac_dms",
                "website_cookies"
            ]
        };
        for (let key in cookies) {
            if (!cookies.hasOwnProperty(key)) continue;
            registerData.cookies.website_cookies.push({
                "Value": cookies[key],
                "Name": key
            });
        }

        let options = {
            host: 'api.amazon.com',
            path: '/auth/register',
            method: 'POST',
            headers: {
                'User-Agent': 'AmazonWebView/Amazon Alexa/2.2.223830.0/iOS/11.4.1/iPhone',
                'Accept-Language': _options.acceptLanguage,
                'Accept-Charset': 'utf-8',
                'Connection': 'keep-alive',
                'Content-Type': 'application/json',
                'Cookie': cookie,
                'Accept': '*/*',
                'x-amzn-identity-auth-domain': 'api.amazon.com'
            },
            body: JSON.stringify(registerData)
        };
        _options.logger && _options.logger('Alexa-Cookie: Register App');
        _options.logger && _options.logger(JSON.stringfy(options));
        request(options, (error, response, body, info) => {
            if (error) {
                callback && callback(error, null);
                return;
            }
            _options.logger && _options.logger('Register App Response: ' + JSON.stringify(body));
            if (typeof body !== 'object') body = JSON.parse(body);

            if (!body.response || !body.response.success || !body.response.success.tokens || !body.response.success.tokens.bearer) {
                callback && callback(new Error('No tokens in Register response'), null);
                return;
            }
            const refreshToken = body.response.success.tokens.bearer.refresh_token;
            const tokenExpiresIn = body.response.success.tokens.bearer.expires_in;

            const exchangeParams = {
                'di.os.name': 'iOS',
                'app_version': '2.2.223830.0',
                'domain': '.' + _options.amazonPage,
                'source_token': refreshToken,
                'requested_token_type': 'auth_cookies',
                'source_token_type': 'refresh_token',
                'di.hw.version': 'iPhone',
                'di.sdk.version': '6.10.0',
                'cookies': Buffer.from('{„cookies“:{".' + _options.amazonPage + '":[]}}').toString('base64'),
                'app_name': 'Amazon Alexa',
                'di.os.version': '11.4.1'
            };
            // Exchange token
            let options = {
                host: 'www.' + _options.amazonPage,
                path: '/ap/exchangetoken',
                method: 'POST',
                headers: {
                    'User-Agent': 'AmazonWebView/Amazon Alexa/2.2.223830.0/iOS/11.4.1/iPhone',
                    'Accept-Language': _options.acceptLanguage,
                    'Accept-Charset': 'utf-8',
                    'Connection': 'keep-alive',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': cookie,
                    'Accept': '*/*'
                },
                body: querystring.stringify(exchangeParams, null, null, {
                    encodeURIComponent: encodeURIComponent
                })
            };
            _options.logger && _options.logger('Alexa-Cookie: Exchange tokens');
            _options.logger && _options.logger(JSON.stringfy(options));
            request(options, (error, response, body, info) => {
                if (error) {
                    callback && callback(error, null);
                    return;
                }
                _options.logger && _options.logger('Exchange Token Response: ' + JSON.stringify(body));
                if (typeof body !== 'object') body = JSON.parse(body);

            });
        });

    }
}


function initAmazonProxy(_options, email, password, callbackCookie, callbackListening) {
    const initialCookies = {};
    // frc contains 313 random bytes, encoded as base64
    const frcBuffer = Buffer.alloc(313);
    for (let i = 0; i < 313; i++) {
        frcBuffer.writeUInt8(Math.floor(Math.random() * 255), i);
    }
    initialCookies.frc = frcBuffer.toString('base64');
    initialCookies['map-md'] = Buffer.from('{"device_user_dictionary":[],"device_registration_data":{"software_version":"1"},"app_identifier":{"app_version":"2.2.223830","bundle_id":"com.amazon.echo"}}').toString('base64');

    let proxyCookies = "";
    let deviceId = '';
    for (let i = 0; i < 64; i++) {
        deviceId += Math.floor(Math.random() * 9).toString();
    }
    deviceId += '23413249564c5635564d32573831';

    // proxy middleware options
    const optionsAlexa = {
        target: `https://alexa.amazon.com`,
        changeOrigin: true,
        ws: false,
        pathRewrite: {}, // enhanced below
        router: router,
        hostRewrite: true,
        followRedirects: false,
        logLevel: _options.proxyLogLevel,
        onError: onError,
        onProxyRes: onProxyRes,
        onProxyReq: onProxyReq,
        headers: {
            'user-agent': _options.userAgent,
            'accept-language': _options.acceptLanguage
        },
        cookieDomainRewrite: { // enhanced below
            "*": ""
        }
    };
    optionsAlexa.pathRewrite[`^/www.amazon.com`] = '';
    optionsAlexa.pathRewrite[`^/alexa..amazon.com`] = '';
    optionsAlexa.cookieDomainRewrite[`.amazon.com`] = _options.proxyOwnIp;
    optionsAlexa.cookieDomainRewrite['amazon.com'] = _options.proxyOwnIp;
    if (_options.logger) optionsAlexa.logProvider = function logProvider(provider) {
        return {
            log: _options.logger.log || _options.logger,
            debug: _options.logger.debug || _options.logger,
            info: _options.logger.info || _options.logger,
            warn: _options.logger.warn || _options.logger,
            error: _options.logger.error || _options.logger
        };
    };

    function router(req) {
        const url = (req.originalUrl || req.url);
        _options.logger && _options.logger('Router: ' + url + ' / ' + req.method + ' / ' + JSON.stringify(req.headers));
        if (req.headers.host === `${_options.proxyOwnIp}:${_options.proxyPort}`) {
            if (url.startsWith(`/www.amazon.com/`)) {
                return `https://www.amazon.com`;
            } else if (url.startsWith(`/alexa.amazon.com/`)) {
                return `https://alexa.amazon.com`;
            } else if (req.headers.referer) {
                if (req.headers.referer.startsWith(`http://${_options.proxyOwnIp}:${_options.proxyPort}/www.amazon.com/`)) {
                    return `https://www.amazon.com`;
                } else if (req.headers.referer.startsWith(`http://${_options.proxyOwnIp}:${_options.proxyPort}/alexa.amazon.com/`)) {
                    return `https://alexa.amazon.com`;
                }
            }
            if (url === '/') {
                return `https://www.amazon.com/ap/signin?openid.return_to=https%3A%2F%2Fwww.amazon.com%2Fap%2Fmaplanding&openid.assoc_handle=amzn_dp_project_dee_ios&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=amzn_dp_project_dee_ios&accountStatusPolicy=P1&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid.ns.oa2=http%3A%2F%2Fwww.amazon.com%2Fap%2Fext%2Foauth%2F2&openid.oa2.client_id=device%3A${deviceId}&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.oa2.response_type=token&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.pape.max_auth_age=0&openid.oa2.scope=device_auth_access&language=${_options.amazonPageProxyLanguage}`;
            }
        }
        return `https://alexa.amazon.com`;
    }

    function onError(err, req, res) {
        _options.logger && _options.logger('ERROR: ' + err);
        res.writeHead(500, {
            'Content-Type': 'text/plain'
        });
        res.end('Proxy-Error: ' + err);
    }

    function replaceHosts(data) {
        //const dataOrig = data;
        const amazonRegex = new RegExp(`https?://www.amazon.com/`.replace(/\./g, "\\."), 'g');
        const alexaRegex = new RegExp(`https?://alexa.amazon.com/`.replace(/\./g, "\\."), 'g');
        data = data.replace(/&#x2F;/g, '/');
        data = data.replace(amazonRegex, `http://${_options.proxyOwnIp}:${_options.proxyPort}/www.amazon.com/`);
        data = data.replace(alexaRegex, `http://${_options.proxyOwnIp}:${_options.proxyPort}/alexa.amazon.com/`);
        //_options.logger && _options.logger('REPLACEHOSTS: ' + dataOrig + ' --> ' + data);
        return data;
    }

    function replaceHostsBack(data) {
        const amazonRegex = new RegExp(`http://${_options.proxyOwnIp}:${_options.proxyPort}/www.amazon.com/`.replace(/\./g, "\\."), 'g');
        const alexaRegex = new RegExp(`http://${_options.proxyOwnIp}:${_options.proxyPort}/alexa.amazon.com/`.replace(/\./g, "\\."), 'g');
        data = data.replace(amazonRegex, `https://www.amazon.com/`);
        data = data.replace(alexaRegex, `https://alexa.amazon.com/`);
        return data;
    }

    function onProxyReq(proxyReq, req, res) {
        const url = req.originalUrl || req.url;
        if (url.endsWith('.ico') || url.endsWith('.js') || url.endsWith('.ttf') || url.endsWith('.svg') || url.endsWith('.png') || url.endsWith('.appcache')) return;
        if (url.startsWith('/ap/uedata')) return;

        _options.logger && _options.logger('Alexa-Cookie: Proxy-Request: ' + req.method + ' ' + url);
        //_options.logger && _options.logger('Alexa-Cookie: Proxy-Request-Data: ' + customStringify(proxyReq, null, 2));

        if (proxyReq._headers) {
            _options.logger && _options.logger('Alexa-Cookie: Headers: ' + JSON.stringify(proxyReq._headers));
            let reqCookie = proxyReq._headers.cookie;
            if (reqCookie === undefined) {
                reqCookie = "";
            }
            for (var cookie in initialCookies) {
                if (!initialCookies.hasOwnProperty(cookie)) continue;
                if (!reqCookie.includes(cookie + '=')) {
                    reqCookie += '; ' + cookie + '=' + initialCookies[cookie];
                }
            }
            if (reqCookie.startsWith('; ')) {
                reqCookie = reqCookie.substr(2);
            }
            proxyReq.setHeader('cookie', reqCookie);
            if (!proxyCookies.length) {
                proxyCookies = reqCookie;
            } else {
                proxyCookies += '; ' + reqCookie;
            }
            _options.logger && _options.logger('Alexa-Cookie: Headers: ' + JSON.stringify(proxyReq._headers));
        }

        let modified = false;
        if (req.method === 'POST') {
            if (proxyReq._headers && proxyReq._headers.referer) {
                proxyReq._headers.referer = replaceHostsBack(proxyReq._headers.referer);
                _options.logger && _options.logger('Alexa-Cookie: Modify headers: Changed Referer');
                modified = true;
            }
            if (proxyReq._headers && proxyReq._headers.origin !== 'https://' + proxyReq._headers.host) {
                delete proxyReq._headers.origin;
                _options.logger && _options.logger('Alexa-Cookie: Modify headers: Delete Origin');
                modified = true;
            }

            let postBody = '';
            req.on('data', chunk => {
                postBody += chunk.toString(); // convert Buffer to string
            });
            req.on('end', () => {
                //_options.proxyLogLevel === 'debug' && _options.logger && _options.logger('Alexa-Cookie: Catched POST parameter: ' + postBody);
                const postParams = querystring.parse(postBody);
                if (email && email.length && postParams.email !== email) {
                    let errMessage = 'Alexa-Cookie: Email entered on Login Page via Proxy differs from set email! You should use the same email to allow automatic cookie retrieval.';
                    _options.logger && _options.logger(errMessage);
                    callbackCookie && callbackCookie(new Error(errMessage), null, null);
                }
                if (password && password.length && postParams.password !== password) {
                    let errMessage = 'Alexa-Cookie: Password entered on Login Page via Proxy differs from set email! You should use the same password to allow automatic cookie retrieval.';
                    _options.logger && _options.logger(errMessage);
                    callbackCookie && callbackCookie(new Error(errMessage), null, null);
                }
            });
        }
        _options.proxyLogLevel === 'debug' && _options.logger && _options.logger('Alexa-Cookie: Proxy-Request: (modified:' + modified + ')' + customStringify(proxyReq, null, 2));
    }

    function onProxyRes(proxyRes, req, res) {
        const url = req.originalUrl || req.url;
        if (url.endsWith('.ico') || url.endsWith('.js') || url.endsWith('.ttf') || url.endsWith('.svg') || url.endsWith('.png') || url.endsWith('.appcache')) return;
        if (url.startsWith('/ap/uedata')) return;
        //_options.logger && _options.logger('Proxy-Response: ' + customStringify(proxyRes, null, 2));
        let reqestHost = null;
        if (proxyRes.socket && proxyRes.socket._host) reqestHost = proxyRes.socket._host;
        _options.logger && _options.logger('Alexa-Cookie: Proxy Response from Host: ' + reqestHost);
        _options.proxyLogLevel === 'debug' && _options.logger && _options.logger('Alexa-Cookie: Proxy-Response Headers: ' + customStringify(proxyRes._headers, null, 2));
        _options.proxyLogLevel === 'debug' && _options.logger && _options.logger('Alexa-Cookie: Proxy-Response Outgoing: ' + customStringify(proxyRes.socket.parser.outgoing, null, 2));
        //_options.logger && _options.logger('Proxy-Response RES!!: ' + customStringify(res, null, 2));

        if (proxyRes && proxyRes.headers && proxyRes.headers['set-cookie']) {
            // make sure cookies are also sent to http by remove secure flags
            for (let i = 0; i < proxyRes.headers['set-cookie'].length; i++) {
                proxyRes.headers['set-cookie'][i] = proxyRes.headers['set-cookie'][i].replace('Secure;', '');
            }
            proxyCookies = addCookies(proxyCookies, proxyRes.headers);
        }

        if (
            (proxyRes.socket && proxyRes.socket._host === `www.amazon.com` && proxyRes.socket.parser.outgoing && proxyRes.socket.parser.outgoing.method === 'GET' && proxyRes.socket.parser.outgoing.path.startsWith('/ap/maplanding')) ||
            (proxyRes.socket && proxyRes.socket.parser.outgoing && proxyRes.socket.parser.outgoing._headers.location && proxyRes.socket.parser.outgoing._headers.location.endsWith('/ap/maplanding')) ||
            (proxyRes.headers.location && proxyRes.headers.location.endsWith('/ap/maplanding'))
        ) {
            _options.logger && _options.logger('Alexa-Cookie: Proxy detected SUCCESS!!');

            const finalCookie = proxyCookies; //proxyRes.headers.cookie || proxyRes.socket.parser.outgoing._headers.cookie;
            const queryParams = querystring.parse(proxyRes.headers.location);

            proxyRes.statusCode = 302;
            proxyRes.headers.location = `http://${_options.proxyOwnIp}:${_options.proxyPort}/cookie-success`;
            delete proxyRes.headers.referer;

            _options.logger && _options.logger('Alexa-Cookie: Proxy catched cookie: ' + finalCookie);
            _options.logger && _options.logger('Alexa-Cookie: Proxy catched parameters: ' + JSON.stringify(queryParams));

            callbackCookie && callbackCookie(null, finalCookie, queryParams);
            return;
        }

        // If we detect a redirect, rewrite the location header
        if (proxyRes.headers.location) {
            _options.logger && _options.logger('Redirect: Original Location ----> ' + proxyRes.headers.location);
            proxyRes.headers.location = replaceHosts(proxyRes.headers.location);
            if (reqestHost && proxyRes.headers.location.startsWith('/')) {
                proxyRes.headers.location = `http://${_options.proxyOwnIp}:${_options.proxyPort}/` + reqestHost + proxyRes.headers.location;
            }
            _options.logger && _options.logger('Redirect: Final Location ----> ' + proxyRes.headers.location);
            return;
        }
        if (!proxyRes || !proxyRes.headers || !proxyRes.headers['content-encoding']) return;

        modifyResponse(res, proxyRes.headers['content-encoding'], function(body) {
            if (body) {
                const bodyOrig = body;
                body = replaceHosts(body);
                if (body !== bodyOrig) _options.logger && _options.logger('Alexa-Cookie: MODIFIED Response Body to rewrite URLs');
            }
            return body;
        });
    }

    // create the proxy (without context)
    const myProxy = proxy('!/cookie-success', optionsAlexa);

    // mount `exampleProxy` in web server
    const app = express();

    app.use(myProxy);
    app.get('/cookie-success', function(req, res) {
        res.send('<b>Amazon Alexa Cookie successfully retrieved. You can close the browser.</b>');
    });
    let server = app.listen(_options.proxyPort, _options.proxyListenBind, function() {
        _options.logger && _options.logger('Alexa-Cookie: Proxy-Server listening on port ' + server.address().port);
        callbackListening(server);
    });
}

function stopProxyServer(callback) {
    if (proxyServer) {
        proxyServer.close(() => {
            callback && callback();
        });
    }
    proxyServer = null;
}

module.exports.generateAlexaCookie = generateAlexaCookie;
module.exports.stopProxyServer = stopProxyServer;
