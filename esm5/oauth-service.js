import { __awaiter, __decorate, __extends, __generator, __metadata, __param, __read, __values } from "tslib";
import { Injectable, NgZone, Optional, OnDestroy, Inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Subject, of, race, from } from 'rxjs';
import { filter, delay, first, tap, map, switchMap, debounceTime } from 'rxjs/operators';
import { DOCUMENT } from '@angular/common';
import { ValidationHandler, ValidationParams } from './token-validation/validation-handler';
import { UrlHelperService } from './url-helper.service';
import { OAuthInfoEvent, OAuthErrorEvent, OAuthSuccessEvent } from './events';
import { OAuthLogger, OAuthStorage, LoginOptions, ParsedIdToken, OidcDiscoveryDoc, TokenResponse, UserInfo } from './types';
import { b64DecodeUnicode, base64UrlEncode } from './base64-helper';
import { AuthConfig } from './auth.config';
import { WebHttpUrlEncodingCodec } from './encoder';
import { HashHandler } from './token-validation/hash-handler';
/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
var OAuthService = /** @class */ (function (_super) {
    __extends(OAuthService, _super);
    function OAuthService(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto, document) {
        var _a, _b, _c, _d;
        var _this = _super.call(this) || this;
        _this.ngZone = ngZone;
        _this.http = http;
        _this.config = config;
        _this.urlHelper = urlHelper;
        _this.logger = logger;
        _this.crypto = crypto;
        _this.document = document;
        /**
         * @internal
         * Deprecated:  use property events instead
         */
        _this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        _this.state = '';
        _this.eventsSubject = new Subject();
        _this.discoveryDocumentLoadedSubject = new Subject();
        _this.grantTypesSupported = [];
        _this.inImplicitFlow = false;
        _this.saveNoncesInLocalStorage = false;
        _this.debug('angular-oauth2-oidc v8-beta');
        _this.discoveryDocumentLoaded$ = _this.discoveryDocumentLoadedSubject.asObservable();
        _this.events = _this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            _this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            _this.configure(config);
        }
        try {
            if (storage) {
                _this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                _this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).' +
                'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        // in IE, sessionStorage does not always survive a redirect
        if (typeof window !== 'undefined' &&
            typeof window['localStorage'] !== 'undefined') {
            var ua = (_b = (_a = window) === null || _a === void 0 ? void 0 : _a.navigator) === null || _b === void 0 ? void 0 : _b.userAgent;
            var msie = ((_c = ua) === null || _c === void 0 ? void 0 : _c.includes('MSIE ')) || ((_d = ua) === null || _d === void 0 ? void 0 : _d.includes('Trident'));
            if (msie) {
                _this.saveNoncesInLocalStorage = true;
            }
        }
        _this.setupRefreshTimer();
        return _this;
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    OAuthService.prototype.configure = function (config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign({}, new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    };
    OAuthService.prototype.configChanged = function () {
        this.setupRefreshTimer();
    };
    OAuthService.prototype.restartSessionChecksIfStillLoggedIn = function () {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    };
    OAuthService.prototype.restartRefreshTimerIfStillLoggedIn = function () {
        this.setupExpirationTimers();
    };
    OAuthService.prototype.setupSessionCheck = function () {
        var _this = this;
        this.events.pipe(filter(function (e) { return e.type === 'token_received'; })).subscribe(function (e) {
            _this.initSessionCheck();
        });
    };
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    OAuthService.prototype.setupAutomaticSilentRefresh = function (params, listenTo, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        var shouldRunSilentRefresh = true;
        this.events
            .pipe(tap(function (e) {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        }), filter(function (e) { return e.type === 'token_expires'; }), debounceTime(1000))
            .subscribe(function (e) {
            var event = e;
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) &&
                shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                _this.refreshInternal(params, noPrompt).catch(function (_) {
                    _this.debug('Automatic silent refresh did not work');
                });
            }
        });
        this.restartRefreshTimerIfStillLoggedIn();
    };
    OAuthService.prototype.refreshInternal = function (params, noPrompt) {
        if (!this.useSilentRefresh && this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    OAuthService.prototype.loadDiscoveryDocumentAndTryLogin = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        return this.loadDiscoveryDocument().then(function (doc) {
            return _this.tryLogin(options);
        });
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initLoginFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    OAuthService.prototype.loadDiscoveryDocumentAndLogin = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        if (!options) {
            options = { state: '' };
        }
        return this.loadDiscoveryDocumentAndTryLogin(options).then(function (_) {
            if (!_this.hasValidIdToken() || !_this.hasValidAccessToken()) {
                if (_this.responseType === 'code') {
                    _this.initCodeFlow();
                }
                else {
                    _this.initImplicitFlow();
                }
                return false;
            }
            else {
                return true;
            }
        });
    };
    OAuthService.prototype.debug = function () {
        var args = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            args[_i] = arguments[_i];
        }
        if (this.showDebugInformation) {
            this.logger.debug.apply(this.logger, args);
        }
    };
    OAuthService.prototype.validateUrlFromDiscoveryDocument = function (url) {
        var errors = [];
        var httpsCheck = this.validateUrlForHttps(url);
        var issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    };
    OAuthService.prototype.validateUrlForHttps = function (url) {
        if (!url) {
            return true;
        }
        var lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    };
    OAuthService.prototype.assertUrlNotNullAndCorrectProtocol = function (url, description) {
        if (!url) {
            throw new Error("'" + description + "' should not be null");
        }
        if (!this.validateUrlForHttps(url)) {
            throw new Error("'" + description + "' must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
    };
    OAuthService.prototype.validateUrlAgainstIssuer = function (url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    };
    OAuthService.prototype.setupRefreshTimer = function () {
        var _this = this;
        if (typeof window === 'undefined') {
            this.debug('timer not supported on this plattform');
            return;
        }
        if (this.hasValidIdToken() || this.hasValidAccessToken()) {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }
        if (this.tokenReceivedSubscription)
            this.tokenReceivedSubscription.unsubscribe();
        this.tokenReceivedSubscription = this.events
            .pipe(filter(function (e) { return e.type === 'token_received'; }))
            .subscribe(function (_) {
            _this.clearAccessTokenTimer();
            _this.clearIdTokenTimer();
            _this.setupExpirationTimers();
        });
    };
    OAuthService.prototype.setupExpirationTimers = function () {
        if (this.hasValidAccessToken()) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            this.setupIdTokenTimer();
        }
    };
    OAuthService.prototype.setupAccessTokenTimer = function () {
        var _this = this;
        var expiration = this.getAccessTokenExpiration();
        var storedAt = this.getAccessTokenStoredAt();
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(function () {
            _this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe(function (e) {
                _this.ngZone.run(function () {
                    _this.eventsSubject.next(e);
                });
            });
        });
    };
    OAuthService.prototype.setupIdTokenTimer = function () {
        var _this = this;
        var expiration = this.getIdTokenExpiration();
        var storedAt = this.getIdTokenStoredAt();
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(function () {
            _this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(function (e) {
                _this.ngZone.run(function () {
                    _this.eventsSubject.next(e);
                });
            });
        });
    };
    /**
     * Stops timers for automatic refresh.
     * To restart it, call setupAutomaticSilentRefresh again.
     */
    OAuthService.prototype.stopAutomaticRefresh = function () {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    };
    OAuthService.prototype.clearAccessTokenTimer = function () {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    };
    OAuthService.prototype.clearIdTokenTimer = function () {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    };
    OAuthService.prototype.calcTimeout = function (storedAt, expiration) {
        var now = Date.now();
        var delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    };
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param storage
     */
    OAuthService.prototype.setStorage = function (storage) {
        this._storage = storage;
        this.configChanged();
    };
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    OAuthService.prototype.loadDiscoveryDocument = function (fullUrl) {
        var _this = this;
        if (fullUrl === void 0) { fullUrl = null; }
        return new Promise(function (resolve, reject) {
            if (!fullUrl) {
                fullUrl = _this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!_this.validateUrlForHttps(fullUrl)) {
                reject("issuer  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
                return;
            }
            _this.http.get(fullUrl).subscribe(function (doc) {
                if (!_this.validateDiscoveryDocument(doc)) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                _this.loginUrl = doc.authorization_endpoint;
                _this.logoutUrl = doc.end_session_endpoint || _this.logoutUrl;
                _this.grantTypesSupported = doc.grant_types_supported;
                _this.issuer = doc.issuer;
                _this.tokenEndpoint = doc.token_endpoint;
                _this.userinfoEndpoint =
                    doc.userinfo_endpoint || _this.userinfoEndpoint;
                _this.jwksUri = doc.jwks_uri;
                _this.sessionCheckIFrameUrl =
                    doc.check_session_iframe || _this.sessionCheckIFrameUrl;
                _this.discoveryDocumentLoaded = true;
                _this.discoveryDocumentLoadedSubject.next(doc);
                if (_this.sessionChecksEnabled) {
                    _this.restartSessionChecksIfStillLoggedIn();
                }
                _this.loadJwks()
                    .then(function (jwks) {
                    var result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    var event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    _this.eventsSubject.next(event);
                    resolve(event);
                    return;
                })
                    .catch(function (err) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                });
            }, function (err) {
                _this.logger.error('error loading discovery document', err);
                _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            });
        });
    };
    OAuthService.prototype.loadJwks = function () {
        var _this = this;
        return new Promise(function (resolve, reject) {
            if (_this.jwksUri) {
                _this.http.get(_this.jwksUri).subscribe(function (jwks) {
                    _this.jwks = jwks;
                    _this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }, function (err) {
                    _this.logger.error('error loading jwks', err);
                    _this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        });
    };
    OAuthService.prototype.validateDiscoveryDocument = function (doc) {
        var errors;
        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            this.logger.error('invalid issuer in discovery document', 'expected: ' + this.issuer, 'current: ' + doc.issuer);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating authorization_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating end_session_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating token_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating userinfo_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            this.logger.error('error validating jwks_uri in discovery document', errors);
            return false;
        }
        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            this.logger.warn('sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field');
        }
        return true;
    };
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlowAndLoadUserProfile = function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then(function () { return _this.loadUserProfile(); });
    };
    /**
     * Uses external token and provider for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param provider
     * @param external_token
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingExternalTokenAndLoadUserProfile = function (provider, external_token, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        return this.fetchTokenUsingUsingExternalToken(provider, external_token, headers).then(function () { return _this.loadUserProfile(); });
    };
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    OAuthService.prototype.loadUserProfile = function () {
        var _this = this;
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error("userinfoEndpoint must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        return new Promise(function (resolve, reject) {
            var headers = new HttpHeaders().set('Authorization', 'Bearer ' + _this.getAccessToken());
            _this.http
                .get(_this.userinfoEndpoint, { headers: headers })
                .subscribe(function (info) {
                _this.debug('userinfo received', info);
                var existingClaims = _this.getIdentityClaims() || {};
                if (!_this.skipSubjectCheck) {
                    if (_this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        var err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                _this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                _this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }, function (err) {
                _this.logger.error('error loading user info', err);
                _this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            });
        });
    };
    /**
     * Uses provider and external token for an access_token.
     * @param provider
     * @param external_token
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingUsingExternalToken = function (provider, external_token, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise(function (resolve, reject) {
            var e_1, _a;
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            var params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'external')
                .set('scope', _this.scope)
                .set('provider', provider)
                .set('external_token', external_token);
            if (_this.useHttpBasicAuth) {
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_1_1) { e_1 = { error: e_1_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_1) throw e_1.error; }
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .subscribe(function (tokenResponse) {
                _this.debug('tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, function (err) {
                _this.logger.error('Error performing external token flow', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    };
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlow = function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise(function (resolve, reject) {
            var e_2, _a;
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            var params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', _this.scope)
                .set('username', userName)
                .set('password', password);
            if (_this.useHttpBasicAuth) {
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_2_1) { e_2 = { error: e_2_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_2) throw e_2.error; }
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .subscribe(function (tokenResponse) {
                _this.debug('tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, function (err) {
                _this.logger.error('Error performing password flow', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    };
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    OAuthService.prototype.refreshToken = function () {
        var _this = this;
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise(function (resolve, reject) {
            var e_3, _a;
            var params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('scope', _this.scope)
                .set('refresh_token', _this._storage.getItem('refresh_token'));
            var headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            if (_this.useHttpBasicAuth) {
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_3_1) { e_3 = { error: e_3_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_3) throw e_3.error; }
                }
            }
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .pipe(switchMap(function (tokenResponse) {
                if (tokenResponse.id_token) {
                    return from(_this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true)).pipe(tap(function (result) { return _this.storeIdToken(result); }), map(function (_) { return tokenResponse; }));
                }
                else {
                    return of(tokenResponse);
                }
            }))
                .subscribe(function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }, function (err) {
                _this.logger.error('Error refreshing token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    };
    OAuthService.prototype.removeSilentRefreshEventListener = function () {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    };
    OAuthService.prototype.setupSilentRefreshEventListener = function () {
        var _this = this;
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = function (e) {
            var message = _this.processMessageEventMessage(e);
            _this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                customRedirectUri: _this.silentRefreshRedirectUri || _this.redirectUri
            }).catch(function (err) { return _this.debug('tryLogin during silent refresh failed', err); });
        };
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    };
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    OAuthService.prototype.silentRefresh = function (params, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        var claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        if (typeof document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        var existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        var iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        var redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then(function (url) {
            iframe.setAttribute('src', url);
            if (!_this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        });
        var errors = this.events.pipe(filter(function (e) { return e instanceof OAuthErrorEvent; }), first());
        var success = this.events.pipe(filter(function (e) { return e.type === 'token_received'; }), first());
        var timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(map(function (e) {
            if (e instanceof OAuthErrorEvent) {
                if (e.type === 'silent_refresh_timeout') {
                    _this.eventsSubject.next(e);
                }
                else {
                    e = new OAuthErrorEvent('silent_refresh_error', e);
                    _this.eventsSubject.next(e);
                }
                throw e;
            }
            else if (e.type === 'token_received') {
                e = new OAuthSuccessEvent('silently_refreshed');
                _this.eventsSubject.next(e);
            }
            return e;
        }))
            .toPromise();
    };
    /**
     * This method exists for backwards compatibility.
     * {@link OAuthService#initLoginFlowInPopup} handles both code
     * and implicit flows.
     */
    OAuthService.prototype.initImplicitFlowInPopup = function (options) {
        return this.initLoginFlowInPopup(options);
    };
    OAuthService.prototype.initLoginFlowInPopup = function (options) {
        var _this = this;
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then(function (url) {
            return new Promise(function (resolve, reject) {
                /**
                 * Error handling section
                 */
                var checkForPopupClosedInterval = 500;
                var windowRef = window.open(url, '_blank', _this.calculatePopupFeatures(options));
                var checkForPopupClosedTimer;
                var checkForPopupClosed = function () {
                    if (!windowRef || windowRef.closed) {
                        cleanup();
                        reject(new OAuthErrorEvent('popup_closed', {}));
                    }
                };
                if (!windowRef) {
                    reject(new OAuthErrorEvent('popup_blocked', {}));
                }
                else {
                    checkForPopupClosedTimer = window.setInterval(checkForPopupClosed, checkForPopupClosedInterval);
                }
                var cleanup = function () {
                    window.clearInterval(checkForPopupClosedTimer);
                    window.removeEventListener('message', listener);
                    if (windowRef !== null) {
                        windowRef.close();
                    }
                    windowRef = null;
                };
                var listener = function (e) {
                    var message = _this.processMessageEventMessage(e);
                    if (message && message !== null) {
                        _this.tryLogin({
                            customHashFragment: message,
                            preventClearHashAfterLogin: true,
                            customRedirectUri: _this.silentRefreshRedirectUri
                        }).then(function () {
                            cleanup();
                            resolve();
                        }, function (err) {
                            cleanup();
                            reject(err);
                        });
                    }
                    else {
                        console.log('false event firing');
                    }
                };
                window.addEventListener('message', listener);
            });
        });
    };
    OAuthService.prototype.calculatePopupFeatures = function (options) {
        // Specify an static height and width and calculate centered position
        var height = options.height || 470;
        var width = options.width || 500;
        var left = window.screenLeft + (window.outerWidth - width) / 2;
        var top = window.screenTop + (window.outerHeight - height) / 2;
        return "location=no,toolbar=no,width=" + width + ",height=" + height + ",top=" + top + ",left=" + left;
    };
    OAuthService.prototype.processMessageEventMessage = function (e) {
        var expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        var prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    };
    OAuthService.prototype.canPerformSessionCheck = function () {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        var sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    };
    OAuthService.prototype.setupSessionCheckEventListener = function () {
        var _this = this;
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = function (e) {
            var origin = e.origin.toLowerCase();
            var issuer = _this.issuer.toLowerCase();
            _this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                _this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer, 'event', e);
                return;
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    _this.handleSessionUnchanged();
                    break;
                case 'changed':
                    _this.ngZone.run(function () {
                        _this.handleSessionChange();
                    });
                    break;
                case 'error':
                    _this.ngZone.run(function () {
                        _this.handleSessionError();
                    });
                    break;
            }
            _this.debug('got info from session check inframe', e);
        };
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular(function () {
            window.addEventListener('message', _this.sessionCheckEventListener);
        });
    };
    OAuthService.prototype.handleSessionUnchanged = function () {
        this.debug('session check', 'session unchanged');
    };
    OAuthService.prototype.handleSessionChange = function () {
        var _this = this;
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (!this.useSilentRefresh && this.responseType === 'code') {
            this.refreshToken()
                .then(function (_) {
                _this.debug('token refresh after session change worked');
            })
                .catch(function (_) {
                _this.debug('token refresh did not work after session changed');
                _this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                _this.logOut(true);
            });
        }
        else if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch(function (_) {
                return _this.debug('silent refresh failed after session changed');
            });
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    };
    OAuthService.prototype.waitForSilentRefreshAfterSessionChange = function () {
        var _this = this;
        this.events
            .pipe(filter(function (e) {
            return e.type === 'silently_refreshed' ||
                e.type === 'silent_refresh_timeout' ||
                e.type === 'silent_refresh_error';
        }), first())
            .subscribe(function (e) {
            if (e.type !== 'silently_refreshed') {
                _this.debug('silent refresh did not work after session changed');
                _this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                _this.logOut(true);
            }
        });
    };
    OAuthService.prototype.handleSessionError = function () {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    };
    OAuthService.prototype.removeSessionCheckEventListener = function () {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    };
    OAuthService.prototype.initSessionCheck = function () {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        var existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        var iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        var url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    };
    OAuthService.prototype.startSessionCheckTimer = function () {
        var _this = this;
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular(function () {
            _this.sessionCheckTimer = setInterval(_this.checkSession.bind(_this), _this.sessionCheckIntervall);
        });
    };
    OAuthService.prototype.stopSessionCheckTimer = function () {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    };
    OAuthService.prototype.checkSession = function () {
        var iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        var sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        var message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    };
    OAuthService.prototype.createLoginUrl = function (state, loginHint, customRedirectUri, noPrompt, params) {
        if (state === void 0) { state = ''; }
        if (loginHint === void 0) { loginHint = ''; }
        if (customRedirectUri === void 0) { customRedirectUri = ''; }
        if (noPrompt === void 0) { noPrompt = false; }
        if (params === void 0) { params = {}; }
        return __awaiter(this, void 0, void 0, function () {
            var that, redirectUri, nonce, seperationChar, scope, url, _a, challenge, verifier, _b, _c, key, _d, _e, key;
            var e_4, _f, e_5, _g;
            return __generator(this, function (_h) {
                switch (_h.label) {
                    case 0:
                        that = this;
                        if (customRedirectUri) {
                            redirectUri = customRedirectUri;
                        }
                        else {
                            redirectUri = this.redirectUri;
                        }
                        return [4 /*yield*/, this.createAndSaveNonce()];
                    case 1:
                        nonce = _h.sent();
                        if (state) {
                            state =
                                nonce + this.config.nonceStateSeparator + encodeURIComponent(state);
                        }
                        else {
                            state = nonce;
                        }
                        if (!this.requestAccessToken && !this.oidc) {
                            throw new Error('Either requestAccessToken or oidc or both must be true');
                        }
                        if (this.config.responseType) {
                            this.responseType = this.config.responseType;
                        }
                        else {
                            if (this.oidc && this.requestAccessToken) {
                                this.responseType = 'id_token token';
                            }
                            else if (this.oidc && !this.requestAccessToken) {
                                this.responseType = 'id_token';
                            }
                            else {
                                this.responseType = 'token';
                            }
                        }
                        seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
                        scope = that.scope;
                        if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                            scope = 'openid ' + scope;
                        }
                        url = that.loginUrl +
                            seperationChar +
                            'response_type=' +
                            encodeURIComponent(that.responseType) +
                            '&client_id=' +
                            encodeURIComponent(that.clientId) +
                            '&state=' +
                            encodeURIComponent(state) +
                            '&redirect_uri=' +
                            encodeURIComponent(redirectUri) +
                            '&scope=' +
                            encodeURIComponent(scope);
                        if (!(this.responseType === 'code' && !this.disablePKCE)) return [3 /*break*/, 3];
                        return [4 /*yield*/, this.createChallangeVerifierPairForPKCE()];
                    case 2:
                        _a = __read.apply(void 0, [_h.sent(), 2]), challenge = _a[0], verifier = _a[1];
                        if (this.saveNoncesInLocalStorage &&
                            typeof window['localStorage'] !== 'undefined') {
                            localStorage.setItem('PKCI_verifier', verifier);
                        }
                        else {
                            this._storage.setItem('PKCI_verifier', verifier);
                        }
                        url += '&code_challenge=' + challenge;
                        url += '&code_challenge_method=S256';
                        _h.label = 3;
                    case 3:
                        if (loginHint) {
                            url += '&login_hint=' + encodeURIComponent(loginHint);
                        }
                        if (that.resource) {
                            url += '&resource=' + encodeURIComponent(that.resource);
                        }
                        if (that.oidc) {
                            url += '&nonce=' + encodeURIComponent(nonce);
                        }
                        if (noPrompt) {
                            url += '&prompt=none';
                        }
                        try {
                            for (_b = __values(Object.keys(params)), _c = _b.next(); !_c.done; _c = _b.next()) {
                                key = _c.value;
                                url +=
                                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
                            }
                        }
                        catch (e_4_1) { e_4 = { error: e_4_1 }; }
                        finally {
                            try {
                                if (_c && !_c.done && (_f = _b.return)) _f.call(_b);
                            }
                            finally { if (e_4) throw e_4.error; }
                        }
                        if (this.customQueryParams) {
                            try {
                                for (_d = __values(Object.getOwnPropertyNames(this.customQueryParams)), _e = _d.next(); !_e.done; _e = _d.next()) {
                                    key = _e.value;
                                    url +=
                                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                                }
                            }
                            catch (e_5_1) { e_5 = { error: e_5_1 }; }
                            finally {
                                try {
                                    if (_e && !_e.done && (_g = _d.return)) _g.call(_d);
                                }
                                finally { if (e_5) throw e_5.error; }
                            }
                        }
                        return [2 /*return*/, url];
                }
            });
        });
    };
    OAuthService.prototype.initImplicitFlowInternal = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        var addParams = {};
        var loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(function (error) {
            console.error('Error in initImplicitFlow', error);
            _this.inImplicitFlow = false;
        });
    };
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    OAuthService.prototype.initImplicitFlow = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(function (e) { return e.type === 'discovery_document_loaded'; }))
                .subscribe(function (_) { return _this.initImplicitFlowInternal(additionalState, params); });
        }
    };
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    OAuthService.prototype.resetImplicitFlow = function () {
        this.inImplicitFlow = false;
    };
    OAuthService.prototype.callOnTokenReceivedIfExists = function (options) {
        var that = this;
        if (options.onTokenReceived) {
            var tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    };
    OAuthService.prototype.storeAccessTokenResponse = function (accessToken, refreshToken, expiresIn, grantedScopes, customParameters) {
        var _this = this;
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes && !Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        else if (grantedScopes && Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            var expiresInMilliSeconds = expiresIn * 1000;
            var now = new Date();
            var expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
        if (customParameters) {
            customParameters.forEach(function (value, key) {
                _this._storage.setItem(key, value);
            });
        }
    };
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    OAuthService.prototype.tryLogin = function (options) {
        if (options === void 0) { options = null; }
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow(options).then(function (_) { return true; });
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    };
    OAuthService.prototype.parseQueryString = function (queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    };
    OAuthService.prototype.tryLoginCodeFlow = function (options) {
        if (options === void 0) { options = null; }
        options = options || {};
        var querySource = options.customHashFragment
            ? options.customHashFragment.substring(1)
            : window.location.search;
        var parts = this.getCodePartsFromUrl(querySource);
        var code = parts['code'];
        var state = parts['state'];
        var sessionState = parts['session_state'];
        if (!options.preventClearHashAfterLogin) {
            var href = location.href
                .replace(/[&\?]code=[^&\$]*/, '')
                .replace(/[&\?]scope=[^&\$]*/, '')
                .replace(/[&\?]state=[^&\$]*/, '')
                .replace(/[&\?]session_state=[^&\$]*/, '');
            history.replaceState(null, window.name, href);
        }
        var _a = __read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            var err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        var success = this.validateNonce(nonceInState);
        if (!success) {
            var event_1 = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event_1);
            return Promise.reject(event_1);
        }
        this.storeSessionState(sessionState);
        if (code) {
            return this.getTokenFromCode(code, options).then(function (_) { return null; });
        }
        else {
            return Promise.resolve();
        }
    };
    /**
     * Retrieve the returned auth code from the redirect uri that has been called.
     * If required also check hash, as we could use hash location strategy.
     */
    OAuthService.prototype.getCodePartsFromUrl = function (queryString) {
        if (!queryString || queryString.length === 0) {
            return this.urlHelper.getHashFragmentParams();
        }
        // normalize query string
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    };
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    OAuthService.prototype.getTokenFromCode = function (code, options) {
        var params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', options.customRedirectUri || this.redirectUri);
        if (!this.disablePKCE) {
            var pkciVerifier = void 0;
            if (this.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                pkciVerifier = localStorage.getItem('PKCI_verifier');
            }
            else {
                pkciVerifier = this._storage.getItem('PKCI_verifier');
            }
            if (!pkciVerifier) {
                console.warn('No PKCI verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', pkciVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    };
    OAuthService.prototype.fetchAndProcessToken = function (params) {
        var _this = this;
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        var headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            var header = btoa(this.clientId + ":" + this.dummyClientSecret);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise(function (resolve, reject) {
            var e_6, _a;
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_6_1) { e_6 = { error: e_6_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_6) throw e_6.error; }
                }
            }
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .subscribe(function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                if (_this.oidc && tokenResponse.id_token) {
                    _this.processIdToken(tokenResponse.id_token, tokenResponse.access_token)
                        .then(function (result) {
                        _this.storeIdToken(result);
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    })
                        .catch(function (reason) {
                        _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    });
                }
                else {
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }, function (err) {
                console.error('Error getting token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    };
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    OAuthService.prototype.tryLoginImplicitFlow = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        options = options || {};
        var parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        var state = parts['state'];
        var _a = __read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            var err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        var accessToken = parts['access_token'];
        var idToken = parts['id_token'];
        var sessionState = parts['session_state'];
        var grantedScopes = parts['scope'];
        if (!this.requestAccessToken && !this.oidc) {
            return Promise.reject('Either requestAccessToken or oidc (or both) must be true.');
        }
        if (this.requestAccessToken && !accessToken) {
            return Promise.resolve(false);
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck && !state) {
            return Promise.resolve(false);
        }
        if (this.oidc && !idToken) {
            return Promise.resolve(false);
        }
        if (this.sessionChecksEnabled && !sessionState) {
            this.logger.warn('session checks (Session Status Change Notification) ' +
                'were activated in the configuration but the id_token ' +
                'does not contain a session_state claim');
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck) {
            var success = this.validateNonce(nonceInState);
            if (!success) {
                var event_2 = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event_2);
                return Promise.reject(event_2);
            }
        }
        if (this.requestAccessToken) {
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in'] || this.fallbackAccessTokenExpirationTimeInSec, grantedScopes);
        }
        if (!this.oidc) {
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.callOnTokenReceivedIfExists(options);
            return Promise.resolve(true);
        }
        return this.processIdToken(idToken, accessToken)
            .then(function (result) {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then(function (_) { return result; });
            }
            return result;
        })
            .then(function (result) {
            _this.storeIdToken(result);
            _this.storeSessionState(sessionState);
            if (_this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            _this.callOnTokenReceivedIfExists(options);
            _this.inImplicitFlow = false;
            return true;
        })
            .catch(function (reason) {
            _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            _this.logger.error('Error validating tokens');
            _this.logger.error(reason);
            return Promise.reject(reason);
        });
    };
    OAuthService.prototype.parseState = function (state) {
        var nonce = state;
        var userState = '';
        if (state) {
            var idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    };
    OAuthService.prototype.validateNonce = function (nonceInState) {
        var savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (savedNonce !== nonceInState) {
            var err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    };
    OAuthService.prototype.storeIdToken = function (idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    };
    OAuthService.prototype.storeSessionState = function (sessionState) {
        this._storage.setItem('session_state', sessionState);
    };
    OAuthService.prototype.getSessionState = function () {
        return this._storage.getItem('session_state');
    };
    OAuthService.prototype.handleLoginError = function (options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
            location.hash = '';
        }
    };
    /**
     * @ignore
     */
    OAuthService.prototype.processIdToken = function (idToken, accessToken, skipNonceCheck) {
        var _this = this;
        if (skipNonceCheck === void 0) { skipNonceCheck = false; }
        var tokenParts = idToken.split('.');
        var headerBase64 = this.padBase64(tokenParts[0]);
        var headerJson = b64DecodeUnicode(headerBase64);
        var header = JSON.parse(headerJson);
        var claimsBase64 = this.padBase64(tokenParts[1]);
        var claimsJson = b64DecodeUnicode(claimsBase64);
        var claims = JSON.parse(claimsJson);
        var savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(function (v) { return v !== _this.clientId; })) {
                var err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                var err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            var err = 'No sub claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /* For now, we only check whether the sub against
         * silentRefreshSubject when sessionChecksEnabled is on
         * We will reconsider in a later version to do this
         * in every other case too.
         */
        if (this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']) {
            var err = 'After refreshing, we got an id_token for another user (sub). ' +
                ("Expected sub: " + this.silentRefreshSubject + ", received sub: " + claims['sub']);
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            var err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            var err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            var err = 'Wrong nonce: ' + claims.nonce;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        // at_hash is not applicable to authorization code flow
        // addressing https://github.com/manfredsteyer/angular-oauth2-oidc/issues/661
        // i.e. Based on spec the at_hash check is only true for implicit code flow on Ping Federate
        // https://www.pingidentity.com/developer/en/resources/openid-connect-developers-guide.html
        if (this.hasOwnProperty('responseType') && this.responseType === 'code') {
            this.disableAtHashCheck = true;
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            var err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        var now = Date.now();
        var issuedAtMSec = claims.iat * 1000;
        var expiresAtMSec = claims.exp * 1000;
        var clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            var err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        var validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: function () { return _this.loadJwks(); }
        };
        if (this.disableAtHashCheck) {
            return this.checkSignature(validationParams).then(function (_) {
                var result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                return result;
            });
        }
        return this.checkAtHash(validationParams).then(function (atHashValid) {
            if (!_this.disableAtHashCheck && _this.requestAccessToken && !atHashValid) {
                var err = 'Wrong at_hash';
                _this.logger.warn(err);
                return Promise.reject(err);
            }
            return _this.checkSignature(validationParams).then(function (_) {
                var atHashCheckEnabled = !_this.disableAtHashCheck;
                var result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                if (atHashCheckEnabled) {
                    return _this.checkAtHash(validationParams).then(function (atHashValid) {
                        if (_this.requestAccessToken && !atHashValid) {
                            var err = 'Wrong at_hash';
                            _this.logger.warn(err);
                            return Promise.reject(err);
                        }
                        else {
                            return result;
                        }
                    });
                }
                else {
                    return result;
                }
            });
        });
    };
    /**
     * Returns the received claims about the user.
     */
    OAuthService.prototype.getIdentityClaims = function () {
        var claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    };
    /**
     * Returns the granted scopes from the server.
     */
    OAuthService.prototype.getGrantedScopes = function () {
        var scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    };
    /**
     * Returns the current id_token.
     */
    OAuthService.prototype.getIdToken = function () {
        return this._storage ? this._storage.getItem('id_token') : null;
    };
    OAuthService.prototype.padBase64 = function (base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    };
    /**
     * Returns the current access_token.
     */
    OAuthService.prototype.getAccessToken = function () {
        return this._storage ? this._storage.getItem('access_token') : null;
    };
    OAuthService.prototype.getRefreshToken = function () {
        return this._storage ? this._storage.getItem('refresh_token') : null;
    };
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    OAuthService.prototype.getAccessTokenExpiration = function () {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    };
    OAuthService.prototype.getAccessTokenStoredAt = function () {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    };
    OAuthService.prototype.getIdTokenStoredAt = function () {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    };
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    OAuthService.prototype.getIdTokenExpiration = function () {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    };
    /**
     * Checkes, whether there is a valid access_token.
     */
    OAuthService.prototype.hasValidAccessToken = function () {
        if (this.getAccessToken()) {
            var expiresAt = this._storage.getItem('expires_at');
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Checks whether there is a valid id_token.
     */
    OAuthService.prototype.hasValidIdToken = function () {
        if (this.getIdToken()) {
            var expiresAt = this._storage.getItem('id_token_expires_at');
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Retrieve a saved custom property of the TokenReponse object. Only if predefined in authconfig.
     */
    OAuthService.prototype.getCustomTokenResponseProperty = function (requestedProperty) {
        return this._storage &&
            this.config.customTokenParameters &&
            this.config.customTokenParameters.indexOf(requestedProperty) >= 0 &&
            this._storage.getItem(requestedProperty) !== null
            ? JSON.parse(this._storage.getItem(requestedProperty))
            : null;
    };
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    OAuthService.prototype.authorizationHeader = function () {
        return 'Bearer ' + this.getAccessToken();
    };
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it with optional state parameter.
     * @param noRedirectToLogoutUrl
     * @param state
     */
    OAuthService.prototype.logOut = function (noRedirectToLogoutUrl, state) {
        var _this = this;
        if (noRedirectToLogoutUrl === void 0) { noRedirectToLogoutUrl = false; }
        if (state === void 0) { state = ''; }
        var id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        if (this.saveNoncesInLocalStorage) {
            localStorage.removeItem('nonce');
            localStorage.removeItem('PKCI_verifier');
        }
        else {
            this._storage.removeItem('nonce');
            this._storage.removeItem('PKCI_verifier');
        }
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
        this._storage.removeItem('granted_scopes');
        this._storage.removeItem('session_state');
        if (this.config.customTokenParameters) {
            this.config.customTokenParameters.forEach(function (customParam) {
                return _this._storage.removeItem(customParam);
            });
        }
        this.silentRefreshSubject = null;
        this.eventsSubject.next(new OAuthInfoEvent('logout'));
        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token && !this.postLogoutRedirectUri) {
            return;
        }
        var logoutUrl;
        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error("logoutUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        }
        else {
            var params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            var postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
                if (state) {
                    params = params.set('state', state);
                }
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    };
    /**
     * @ignore
     */
    OAuthService.prototype.createAndSaveNonce = function () {
        var that = this;
        return this.createNonce().then(function (nonce) {
            // Use localStorage for nonce if possible
            // localStorage is the only storage who survives a
            // redirect in ALL browsers (also IE)
            // Otherwiese we'd force teams who have to support
            // IE into using localStorage for everything
            if (that.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                localStorage.setItem('nonce', nonce);
            }
            else {
                that._storage.setItem('nonce', nonce);
            }
            return nonce;
        });
    };
    /**
     * @ignore
     */
    OAuthService.prototype.ngOnDestroy = function () {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.removeSilentRefreshEventListener();
        var silentRefreshFrame = this.document.getElementById(this.silentRefreshIFrameName);
        if (silentRefreshFrame) {
            silentRefreshFrame.remove();
        }
        this.stopSessionCheckTimer();
        this.removeSessionCheckEventListener();
        var sessionCheckFrame = this.document.getElementById(this.sessionCheckIFrameName);
        if (sessionCheckFrame) {
            sessionCheckFrame.remove();
        }
    };
    OAuthService.prototype.createNonce = function () {
        var _this = this;
        return new Promise(function (resolve) {
            if (_this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
             * This alphabet is from:
             * https://tools.ietf.org/html/rfc7636#section-4.1
             *
             * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
             */
            var unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            var size = 45;
            var id = '';
            var crypto = typeof self === 'undefined' ? null : self.crypto || self['msCrypto'];
            if (crypto) {
                var bytes = new Uint8Array(size);
                crypto.getRandomValues(bytes);
                // Needed for IE
                if (!bytes.map) {
                    bytes.map = Array.prototype.map;
                }
                bytes = bytes.map(function (x) { return unreserved.charCodeAt(x % unreserved.length); });
                id = String.fromCharCode.apply(null, bytes);
            }
            else {
                while (0 < size--) {
                    id += unreserved[(Math.random() * unreserved.length) | 0];
                }
            }
            resolve(base64UrlEncode(id));
        });
    };
    OAuthService.prototype.checkAtHash = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                if (!this.tokenValidationHandler) {
                    this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                    return [2 /*return*/, true];
                }
                return [2 /*return*/, this.tokenValidationHandler.validateAtHash(params)];
            });
        });
    };
    OAuthService.prototype.checkSignature = function (params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    };
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    OAuthService.prototype.initLoginFlow = function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    };
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    OAuthService.prototype.initCodeFlow = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(function (e) { return e.type === 'discovery_document_loaded'; }))
                .subscribe(function (_) { return _this.initCodeFlowInternal(additionalState, params); });
        }
    };
    OAuthService.prototype.initCodeFlowInternal = function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
            .catch(function (error) {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        });
    };
    OAuthService.prototype.createChallangeVerifierPairForPKCE = function () {
        return __awaiter(this, void 0, void 0, function () {
            var verifier, challengeRaw, challenge;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!this.crypto) {
                            throw new Error('PKCE support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
                        }
                        return [4 /*yield*/, this.createNonce()];
                    case 1:
                        verifier = _a.sent();
                        return [4 /*yield*/, this.crypto.calcHash(verifier, 'sha-256')];
                    case 2:
                        challengeRaw = _a.sent();
                        challenge = base64UrlEncode(challengeRaw);
                        return [2 /*return*/, [challenge, verifier]];
                }
            });
        });
    };
    OAuthService.prototype.extractRecognizedCustomParameters = function (tokenResponse) {
        var foundParameters = new Map();
        if (!this.config.customTokenParameters) {
            return foundParameters;
        }
        this.config.customTokenParameters.forEach(function (recognizedParameter) {
            if (tokenResponse[recognizedParameter]) {
                foundParameters.set(recognizedParameter, JSON.stringify(tokenResponse[recognizedParameter]));
            }
        });
        return foundParameters;
    };
    OAuthService.ctorParameters = function () { return [
        { type: NgZone },
        { type: HttpClient },
        { type: OAuthStorage, decorators: [{ type: Optional }] },
        { type: ValidationHandler, decorators: [{ type: Optional }] },
        { type: AuthConfig, decorators: [{ type: Optional }] },
        { type: UrlHelperService },
        { type: OAuthLogger },
        { type: HashHandler, decorators: [{ type: Optional }] },
        { type: Document, decorators: [{ type: Inject, args: [DOCUMENT,] }] }
    ]; };
    OAuthService = __decorate([
        Injectable(),
        __param(2, Optional()),
        __param(3, Optional()),
        __param(4, Optional()),
        __param(7, Optional()),
        __param(8, Inject(DOCUMENT)),
        __metadata("design:paramtypes", [NgZone,
            HttpClient,
            OAuthStorage,
            ValidationHandler,
            AuthConfig,
            UrlHelperService,
            OAuthLogger,
            HashHandler,
            Document])
    ], OAuthService);
    return OAuthService;
}(AuthConfig));
export { OAuthService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUNoRixPQUFPLEVBQUUsVUFBVSxFQUFFLFdBQVcsRUFBRSxVQUFVLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUMzRSxPQUFPLEVBQWMsT0FBTyxFQUFnQixFQUFFLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxNQUFNLE1BQU0sQ0FBQztBQUN6RSxPQUFPLEVBQ0wsTUFBTSxFQUNOLEtBQUssRUFDTCxLQUFLLEVBQ0wsR0FBRyxFQUNILEdBQUcsRUFDSCxTQUFTLEVBQ1QsWUFBWSxFQUNiLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBRTNDLE9BQU8sRUFDTCxpQkFBaUIsRUFDakIsZ0JBQWdCLEVBQ2pCLE1BQU0sdUNBQXVDLENBQUM7QUFDL0MsT0FBTyxFQUFFLGdCQUFnQixFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFDeEQsT0FBTyxFQUVMLGNBQWMsRUFDZCxlQUFlLEVBQ2YsaUJBQWlCLEVBQ2xCLE1BQU0sVUFBVSxDQUFDO0FBQ2xCLE9BQU8sRUFDTCxXQUFXLEVBQ1gsWUFBWSxFQUNaLFlBQVksRUFDWixhQUFhLEVBQ2IsZ0JBQWdCLEVBQ2hCLGFBQWEsRUFDYixRQUFRLEVBQ1QsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FB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TCxRQUFRO09BN0RuQyxZQUFZLENBdWlGeEI7SUFBRCxtQkFBQztDQUFBLEFBdmlGRCxDQUFrQyxVQUFVLEdBdWlGM0M7U0F2aUZZLFlBQVkiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZ1pvbmUsIE9wdGlvbmFsLCBPbkRlc3Ryb3ksIEluamVjdCB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgSHR0cENsaWVudCwgSHR0cEhlYWRlcnMsIEh0dHBQYXJhbXMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBTdWJqZWN0LCBTdWJzY3JpcHRpb24sIG9mLCByYWNlLCBmcm9tIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQge1xuICBmaWx0ZXIsXG4gIGRlbGF5LFxuICBmaXJzdCxcbiAgdGFwLFxuICBtYXAsXG4gIHN3aXRjaE1hcCxcbiAgZGVib3VuY2VUaW1lXG59IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IERPQ1VNRU5UIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uJztcblxuaW1wb3J0IHtcbiAgVmFsaWRhdGlvbkhhbmRsZXIsXG4gIFZhbGlkYXRpb25QYXJhbXNcbn0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL3ZhbGlkYXRpb24taGFuZGxlcic7XG5pbXBvcnQgeyBVcmxIZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi91cmwtaGVscGVyLnNlcnZpY2UnO1xuaW1wb3J0IHtcbiAgT0F1dGhFdmVudCxcbiAgT0F1dGhJbmZvRXZlbnQsXG4gIE9BdXRoRXJyb3JFdmVudCxcbiAgT0F1dGhTdWNjZXNzRXZlbnRcbn0gZnJvbSAnLi9ldmVudHMnO1xuaW1wb3J0IHtcbiAgT0F1dGhMb2dnZXIsXG4gIE9BdXRoU3RvcmFnZSxcbiAgTG9naW5PcHRpb25zLFxuICBQYXJzZWRJZFRva2VuLFxuICBPaWRjRGlzY292ZXJ5RG9jLFxuICBUb2tlblJlc3BvbnNlLFxuICBVc2VySW5mb1xufSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IGI2NERlY29kZVVuaWNvZGUsIGJhc2U2NFVybEVuY29kZSB9IGZyb20gJy4vYmFzZTY0LWhlbHBlcic7XG5pbXBvcnQgeyBBdXRoQ29uZmlnIH0gZnJvbSAnLi9hdXRoLmNvbmZpZyc7XG5pbXBvcnQgeyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYyB9IGZyb20gJy4vZW5jb2Rlcic7XG5pbXBvcnQgeyBIYXNoSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9oYXNoLWhhbmRsZXInO1xuXG4vKipcbiAqIFNlcnZpY2UgZm9yIGxvZ2dpbmcgaW4gYW5kIGxvZ2dpbmcgb3V0IHdpdGhcbiAqIE9JREMgYW5kIE9BdXRoMi4gU3VwcG9ydHMgaW1wbGljaXQgZmxvdyBhbmRcbiAqIHBhc3N3b3JkIGZsb3cuXG4gKi9cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBPQXV0aFNlcnZpY2UgZXh0ZW5kcyBBdXRoQ29uZmlnIGltcGxlbWVudHMgT25EZXN0cm95IHtcbiAgLy8gRXh0ZW5kaW5nIEF1dGhDb25maWcgaXN0IGp1c3QgZm9yIExFR0FDWSByZWFzb25zXG4gIC8vIHRvIG5vdCBicmVhayBleGlzdGluZyBjb2RlLlxuXG4gIC8qKlxuICAgKiBUaGUgVmFsaWRhdGlvbkhhbmRsZXIgdXNlZCB0byB2YWxpZGF0ZSByZWNlaXZlZFxuICAgKiBpZF90b2tlbnMuXG4gICAqL1xuICBwdWJsaWMgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXI7XG5cbiAgLyoqXG4gICAqIEBpbnRlcm5hbFxuICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXG4gICAqL1xuICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQgPSBmYWxzZTtcblxuICAvKipcbiAgICogQGludGVybmFsXG4gICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcbiAgICovXG4gIHB1YmxpYyBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZCQ6IE9ic2VydmFibGU8T2lkY0Rpc2NvdmVyeURvYz47XG5cbiAgLyoqXG4gICAqIEluZm9ybXMgYWJvdXQgZXZlbnRzLCBsaWtlIHRva2VuX3JlY2VpdmVkIG9yIHRva2VuX2V4cGlyZXMuXG4gICAqIFNlZSB0aGUgc3RyaW5nIGVudW0gRXZlbnRUeXBlIGZvciBhIGZ1bGwgbGlzdCBvZiBldmVudCB0eXBlcy5cbiAgICovXG4gIHB1YmxpYyBldmVudHM6IE9ic2VydmFibGU8T0F1dGhFdmVudD47XG5cbiAgLyoqXG4gICAqIFRoZSByZWNlaXZlZCAocGFzc2VkIGFyb3VuZCkgc3RhdGUsIHdoZW4gbG9nZ2luZ1xuICAgKiBpbiB3aXRoIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgc3RhdGU/ID0gJyc7XG5cbiAgcHJvdGVjdGVkIGV2ZW50c1N1YmplY3Q6IFN1YmplY3Q8T0F1dGhFdmVudD4gPSBuZXcgU3ViamVjdDxPQXV0aEV2ZW50PigpO1xuICBwcm90ZWN0ZWQgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0OiBTdWJqZWN0PFxuICAgIE9pZGNEaXNjb3ZlcnlEb2NcbiAgPiA9IG5ldyBTdWJqZWN0PE9pZGNEaXNjb3ZlcnlEb2M+KCk7XG4gIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyOiBFdmVudExpc3RlbmVyO1xuICBwcm90ZWN0ZWQgZ3JhbnRUeXBlc1N1cHBvcnRlZDogQXJyYXk8c3RyaW5nPiA9IFtdO1xuICBwcm90ZWN0ZWQgX3N0b3JhZ2U6IE9BdXRoU3RvcmFnZTtcbiAgcHJvdGVjdGVkIGFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbjogU3Vic2NyaXB0aW9uO1xuICBwcm90ZWN0ZWQgaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgcHJvdGVjdGVkIHRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgcHJvdGVjdGVkIHNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XG4gIHByb3RlY3RlZCBqd2tzVXJpOiBzdHJpbmc7XG4gIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tUaW1lcjogYW55O1xuICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFN1YmplY3Q6IHN0cmluZztcbiAgcHJvdGVjdGVkIGluSW1wbGljaXRGbG93ID0gZmFsc2U7XG5cbiAgcHJvdGVjdGVkIHNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSA9IGZhbHNlO1xuXG4gIGNvbnN0cnVjdG9yKFxuICAgIHByb3RlY3RlZCBuZ1pvbmU6IE5nWm9uZSxcbiAgICBwcm90ZWN0ZWQgaHR0cDogSHR0cENsaWVudCxcbiAgICBAT3B0aW9uYWwoKSBzdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXG4gICAgQE9wdGlvbmFsKCkgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXIsXG4gICAgQE9wdGlvbmFsKCkgcHJvdGVjdGVkIGNvbmZpZzogQXV0aENvbmZpZyxcbiAgICBwcm90ZWN0ZWQgdXJsSGVscGVyOiBVcmxIZWxwZXJTZXJ2aWNlLFxuICAgIHByb3RlY3RlZCBsb2dnZXI6IE9BdXRoTG9nZ2VyLFxuICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjcnlwdG86IEhhc2hIYW5kbGVyLFxuICAgIEBJbmplY3QoRE9DVU1FTlQpIHByaXZhdGUgZG9jdW1lbnQ6IERvY3VtZW50XG4gICkge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLmRlYnVnKCdhbmd1bGFyLW9hdXRoMi1vaWRjIHY4LWJldGEnKTtcblxuICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkID0gdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QuYXNPYnNlcnZhYmxlKCk7XG4gICAgdGhpcy5ldmVudHMgPSB0aGlzLmV2ZW50c1N1YmplY3QuYXNPYnNlcnZhYmxlKCk7XG5cbiAgICBpZiAodG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyID0gdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjtcbiAgICB9XG5cbiAgICBpZiAoY29uZmlnKSB7XG4gICAgICB0aGlzLmNvbmZpZ3VyZShjb25maWcpO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICBpZiAoc3RvcmFnZSkge1xuICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc3RvcmFnZSk7XG4gICAgICB9IGVsc2UgaWYgKHR5cGVvZiBzZXNzaW9uU3RvcmFnZSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHNlc3Npb25TdG9yYWdlKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKFxuICAgICAgICAnTm8gT0F1dGhTdG9yYWdlIHByb3ZpZGVkIGFuZCBjYW5ub3QgYWNjZXNzIGRlZmF1bHQgKHNlc3Npb25TdG9yYWdlKS4nICtcbiAgICAgICAgICAnQ29uc2lkZXIgcHJvdmlkaW5nIGEgY3VzdG9tIE9BdXRoU3RvcmFnZSBpbXBsZW1lbnRhdGlvbiBpbiB5b3VyIG1vZHVsZS4nLFxuICAgICAgICBlXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIGluIElFLCBzZXNzaW9uU3RvcmFnZSBkb2VzIG5vdCBhbHdheXMgc3Vydml2ZSBhIHJlZGlyZWN0XG4gICAgaWYgKFxuICAgICAgdHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgJiZcbiAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xuICAgICkge1xuICAgICAgY29uc3QgdWEgPSB3aW5kb3c/Lm5hdmlnYXRvcj8udXNlckFnZW50O1xuICAgICAgY29uc3QgbXNpZSA9IHVhPy5pbmNsdWRlcygnTVNJRSAnKSB8fCB1YT8uaW5jbHVkZXMoJ1RyaWRlbnQnKTtcblxuICAgICAgaWYgKG1zaWUpIHtcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgPSB0cnVlO1xuICAgICAgfVxuICAgIH1cblxuICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gY29uZmlndXJlIHRoZSBzZXJ2aWNlXG4gICAqIEBwYXJhbSBjb25maWcgdGhlIGNvbmZpZ3VyYXRpb25cbiAgICovXG4gIHB1YmxpYyBjb25maWd1cmUoY29uZmlnOiBBdXRoQ29uZmlnKTogdm9pZCB7XG4gICAgLy8gRm9yIHRoZSBzYWtlIG9mIGRvd253YXJkIGNvbXBhdGliaWxpdHkgd2l0aFxuICAgIC8vIG9yaWdpbmFsIGNvbmZpZ3VyYXRpb24gQVBJXG4gICAgT2JqZWN0LmFzc2lnbih0aGlzLCBuZXcgQXV0aENvbmZpZygpLCBjb25maWcpO1xuXG4gICAgdGhpcy5jb25maWcgPSBPYmplY3QuYXNzaWduKHt9IGFzIEF1dGhDb25maWcsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XG5cbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgdGhpcy5zZXR1cFNlc3Npb25DaGVjaygpO1xuICAgIH1cblxuICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGNvbmZpZ0NoYW5nZWQoKTogdm9pZCB7XG4gICAgdGhpcy5zZXR1cFJlZnJlc2hUaW1lcigpO1xuICB9XG5cbiAgcHVibGljIHJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgcmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcbiAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICB9XG5cbiAgcHJvdGVjdGVkIHNldHVwU2Vzc2lvbkNoZWNrKCk6IHZvaWQge1xuICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSkuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogV2lsbCBzZXR1cCB1cCBzaWxlbnQgcmVmcmVzaGluZyBmb3Igd2hlbiB0aGUgdG9rZW4gaXNcbiAgICogYWJvdXQgdG8gZXhwaXJlLiBXaGVuIHRoZSB1c2VyIGlzIGxvZ2dlZCBvdXQgdmlhIHRoaXMubG9nT3V0IG1ldGhvZCwgdGhlXG4gICAqIHNpbGVudCByZWZyZXNoaW5nIHdpbGwgcGF1c2UgYW5kIG5vdCByZWZyZXNoIHRoZSB0b2tlbnMgdW50aWwgdGhlIHVzZXIgaXNcbiAgICogbG9nZ2VkIGJhY2sgaW4gdmlhIHJlY2VpdmluZyBhIG5ldyB0b2tlbi5cbiAgICogQHBhcmFtIHBhcmFtcyBBZGRpdGlvbmFsIHBhcmFtZXRlciB0byBwYXNzXG4gICAqIEBwYXJhbSBsaXN0ZW5UbyBTZXR1cCBhdXRvbWF0aWMgcmVmcmVzaCBvZiBhIHNwZWNpZmljIHRva2VuIHR5cGVcbiAgICovXG4gIHB1YmxpYyBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2goXG4gICAgcGFyYW1zOiBvYmplY3QgPSB7fSxcbiAgICBsaXN0ZW5Ubz86ICdhY2Nlc3NfdG9rZW4nIHwgJ2lkX3Rva2VuJyB8ICdhbnknLFxuICAgIG5vUHJvbXB0ID0gdHJ1ZVxuICApOiB2b2lkIHtcbiAgICBsZXQgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XG4gICAgdGhpcy5ldmVudHNcbiAgICAgIC5waXBlKFxuICAgICAgICB0YXAoZSA9PiB7XG4gICAgICAgICAgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xuICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XG4gICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICdsb2dvdXQnKSB7XG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gZmFsc2U7XG4gICAgICAgICAgfVxuICAgICAgICB9KSxcbiAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fZXhwaXJlcycpLFxuICAgICAgICBkZWJvdW5jZVRpbWUoMTAwMClcbiAgICAgIClcbiAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgIGNvbnN0IGV2ZW50ID0gZSBhcyBPQXV0aEluZm9FdmVudDtcbiAgICAgICAgaWYgKFxuICAgICAgICAgIChsaXN0ZW5UbyA9PSBudWxsIHx8IGxpc3RlblRvID09PSAnYW55JyB8fCBldmVudC5pbmZvID09PSBsaXN0ZW5UbykgJiZcbiAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoXG4gICAgICAgICkge1xuICAgICAgICAgIC8vIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KS5jYXRjaChfID0+IHtcbiAgICAgICAgICB0aGlzLnJlZnJlc2hJbnRlcm5hbChwYXJhbXMsIG5vUHJvbXB0KS5jYXRjaChfID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ0F1dG9tYXRpYyBzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsnKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG5cbiAgICB0aGlzLnJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTtcbiAgfVxuXG4gIHByb3RlY3RlZCByZWZyZXNoSW50ZXJuYWwoXG4gICAgcGFyYW1zLFxuICAgIG5vUHJvbXB0XG4gICk6IFByb21pc2U8VG9rZW5SZXNwb25zZSB8IE9BdXRoRXZlbnQ+IHtcbiAgICBpZiAoIXRoaXMudXNlU2lsZW50UmVmcmVzaCAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICByZXR1cm4gdGhpcy5yZWZyZXNoVG9rZW4oKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudCguLi4pYCBhbmRcbiAgICogZGlyZWN0bHkgY2hhaW5zIHVzaW5nIHRoZSBgdGhlbiguLi4pYCBwYXJ0IG9mIHRoZSBwcm9taXNlIHRvIGNhbGxcbiAgICogdGhlIGB0cnlMb2dpbiguLi4pYCBtZXRob2QuXG4gICAqXG4gICAqIEBwYXJhbSBvcHRpb25zIExvZ2luT3B0aW9ucyB0byBwYXNzIHRocm91Z2ggdG8gYHRyeUxvZ2luKC4uLilgXG4gICAqL1xuICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4oXG4gICAgb3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbFxuICApOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICByZXR1cm4gdGhpcy5sb2FkRGlzY292ZXJ5RG9jdW1lbnQoKS50aGVuKGRvYyA9PiB7XG4gICAgICByZXR1cm4gdGhpcy50cnlMb2dpbihvcHRpb25zKTtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDb252ZW5pZW5jZSBtZXRob2QgdGhhdCBmaXJzdCBjYWxscyBgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4oLi4uKWBcbiAgICogYW5kIGlmIHRoZW4gY2hhaW5zIHRvIGBpbml0TG9naW5GbG93KClgLCBidXQgb25seSBpZiB0aGVyZSBpcyBubyB2YWxpZFxuICAgKiBJZFRva2VuIG9yIG5vIHZhbGlkIEFjY2Vzc1Rva2VuLlxuICAgKlxuICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxuICAgKi9cbiAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZExvZ2luKFxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9ucyAmIHsgc3RhdGU/OiBzdHJpbmcgfSA9IG51bGxcbiAgKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKCFvcHRpb25zKSB7XG4gICAgICBvcHRpb25zID0geyBzdGF0ZTogJycgfTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4ob3B0aW9ucykudGhlbihfID0+IHtcbiAgICAgIGlmICghdGhpcy5oYXNWYWxpZElkVG9rZW4oKSB8fCAhdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICB0aGlzLmluaXRDb2RlRmxvdygpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRoaXMuaW5pdEltcGxpY2l0RmxvdygpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGRlYnVnKC4uLmFyZ3MpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zaG93RGVidWdJbmZvcm1hdGlvbikge1xuICAgICAgdGhpcy5sb2dnZXIuZGVidWcuYXBwbHkodGhpcy5sb2dnZXIsIGFyZ3MpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudCh1cmw6IHN0cmluZyk6IHN0cmluZ1tdIHtcbiAgICBjb25zdCBlcnJvcnM6IHN0cmluZ1tdID0gW107XG4gICAgY29uc3QgaHR0cHNDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh1cmwpO1xuICAgIGNvbnN0IGlzc3VlckNoZWNrID0gdGhpcy52YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsKTtcblxuICAgIGlmICghaHR0cHNDaGVjaykge1xuICAgICAgZXJyb3JzLnB1c2goXG4gICAgICAgICdodHRwcyBmb3IgYWxsIHVybHMgcmVxdWlyZWQuIEFsc28gZm9yIHVybHMgcmVjZWl2ZWQgYnkgZGlzY292ZXJ5LidcbiAgICAgICk7XG4gICAgfVxuXG4gICAgaWYgKCFpc3N1ZXJDaGVjaykge1xuICAgICAgZXJyb3JzLnB1c2goXG4gICAgICAgICdFdmVyeSB1cmwgaW4gZGlzY292ZXJ5IGRvY3VtZW50IGhhcyB0byBzdGFydCB3aXRoIHRoZSBpc3N1ZXIgdXJsLicgK1xuICAgICAgICAgICdBbHNvIHNlZSBwcm9wZXJ0eSBzdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24uJ1xuICAgICAgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gZXJyb3JzO1xuICB9XG5cbiAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRm9ySHR0cHModXJsOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgICBpZiAoIXVybCkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgY29uc3QgbGNVcmwgPSB1cmwudG9Mb3dlckNhc2UoKTtcblxuICAgIGlmICh0aGlzLnJlcXVpcmVIdHRwcyA9PT0gZmFsc2UpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIGlmIChcbiAgICAgIChsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pIHx8XG4gICAgICAgIGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykpICYmXG4gICAgICB0aGlzLnJlcXVpcmVIdHRwcyA9PT0gJ3JlbW90ZU9ubHknXG4gICAgKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICByZXR1cm4gbGNVcmwuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBhc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxuICAgIHVybDogc3RyaW5nIHwgdW5kZWZpbmVkLFxuICAgIGRlc2NyaXB0aW9uOiBzdHJpbmdcbiAgKSB7XG4gICAgaWYgKCF1cmwpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgJyR7ZGVzY3JpcHRpb259JyBzaG91bGQgbm90IGJlIG51bGxgKTtcbiAgICB9XG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBgJyR7ZGVzY3JpcHRpb259JyBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5gXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCB2YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsOiBzdHJpbmcpIHtcbiAgICBpZiAoIXRoaXMuc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgaWYgKCF1cmwpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICByZXR1cm4gdXJsLnRvTG93ZXJDYXNlKCkuc3RhcnRzV2l0aCh0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cFJlZnJlc2hUaW1lcigpOiB2b2lkIHtcbiAgICBpZiAodHlwZW9mIHdpbmRvdyA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHRoaXMuZGVidWcoJ3RpbWVyIG5vdCBzdXBwb3J0ZWQgb24gdGhpcyBwbGF0dGZvcm0nKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSB8fCB0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcbiAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbilcbiAgICAgIHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuXG4gICAgdGhpcy50b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uID0gdGhpcy5ldmVudHNcbiAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpXG4gICAgICAuc3Vic2NyaWJlKF8gPT4ge1xuICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XG4gICAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cEV4cGlyYXRpb25UaW1lcnMoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICB0aGlzLnNldHVwQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICB0aGlzLnNldHVwSWRUb2tlblRpbWVyKCk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHNldHVwQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKTtcbiAgICBjb25zdCBzdG9yZWRBdCA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5TdG9yZWRBdCgpO1xuICAgIGNvbnN0IHRpbWVvdXQgPSB0aGlzLmNhbGNUaW1lb3V0KHN0b3JlZEF0LCBleHBpcmF0aW9uKTtcblxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgIHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXG4gICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdhY2Nlc3NfdG9rZW4nKVxuICAgICAgKVxuICAgICAgICAucGlwZShkZWxheSh0aW1lb3V0KSlcbiAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIHNldHVwSWRUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldElkVG9rZW5FeHBpcmF0aW9uKCk7XG4gICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldElkVG9rZW5TdG9yZWRBdCgpO1xuICAgIGNvbnN0IHRpbWVvdXQgPSB0aGlzLmNhbGNUaW1lb3V0KHN0b3JlZEF0LCBleHBpcmF0aW9uKTtcblxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24gPSBvZihcbiAgICAgICAgbmV3IE9BdXRoSW5mb0V2ZW50KCd0b2tlbl9leHBpcmVzJywgJ2lkX3Rva2VuJylcbiAgICAgIClcbiAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBTdG9wcyB0aW1lcnMgZm9yIGF1dG9tYXRpYyByZWZyZXNoLlxuICAgKiBUbyByZXN0YXJ0IGl0LCBjYWxsIHNldHVwQXV0b21hdGljU2lsZW50UmVmcmVzaCBhZ2Fpbi5cbiAgICovXG4gIHB1YmxpYyBzdG9wQXV0b21hdGljUmVmcmVzaCgpIHtcbiAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBjbGVhckFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XG4gICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBjbGVhcklkVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBjYWxjVGltZW91dChzdG9yZWRBdDogbnVtYmVyLCBleHBpcmF0aW9uOiBudW1iZXIpOiBudW1iZXIge1xuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgY29uc3QgZGVsdGEgPVxuICAgICAgKGV4cGlyYXRpb24gLSBzdG9yZWRBdCkgKiB0aGlzLnRpbWVvdXRGYWN0b3IgLSAobm93IC0gc3RvcmVkQXQpO1xuICAgIHJldHVybiBNYXRoLm1heCgwLCBkZWx0YSk7XG4gIH1cblxuICAvKipcbiAgICogREVQUkVDQVRFRC4gVXNlIGEgcHJvdmlkZXIgZm9yIE9BdXRoU3RvcmFnZSBpbnN0ZWFkOlxuICAgKlxuICAgKiB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogb0F1dGhTdG9yYWdlRmFjdG9yeSB9XG4gICAqIGV4cG9ydCBmdW5jdGlvbiBvQXV0aFN0b3JhZ2VGYWN0b3J5KCk6IE9BdXRoU3RvcmFnZSB7IHJldHVybiBsb2NhbFN0b3JhZ2U7IH1cbiAgICogU2V0cyBhIGN1c3RvbSBzdG9yYWdlIHVzZWQgdG8gc3RvcmUgdGhlIHJlY2VpdmVkXG4gICAqIHRva2VucyBvbiBjbGllbnQgc2lkZS4gQnkgZGVmYXVsdCwgdGhlIGJyb3dzZXInc1xuICAgKiBzZXNzaW9uU3RvcmFnZSBpcyB1c2VkLlxuICAgKiBAaWdub3JlXG4gICAqXG4gICAqIEBwYXJhbSBzdG9yYWdlXG4gICAqL1xuICBwdWJsaWMgc2V0U3RvcmFnZShzdG9yYWdlOiBPQXV0aFN0b3JhZ2UpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9yYWdlID0gc3RvcmFnZTtcbiAgICB0aGlzLmNvbmZpZ0NoYW5nZWQoKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBMb2FkcyB0aGUgZGlzY292ZXJ5IGRvY3VtZW50IHRvIGNvbmZpZ3VyZSBtb3N0XG4gICAqIHByb3BlcnRpZXMgb2YgdGhpcyBzZXJ2aWNlLiBUaGUgdXJsIG9mIHRoZSBkaXNjb3ZlcnlcbiAgICogZG9jdW1lbnQgaXMgaW5mZXJlZCBmcm9tIHRoZSBpc3N1ZXIncyB1cmwgYWNjb3JkaW5nXG4gICAqIHRvIHRoZSBPcGVuSWQgQ29ubmVjdCBzcGVjLiBUbyB1c2UgYW5vdGhlciB1cmwgeW91XG4gICAqIGNhbiBwYXNzIGl0IHRvIHRvIG9wdGlvbmFsIHBhcmFtZXRlciBmdWxsVXJsLlxuICAgKlxuICAgKiBAcGFyYW0gZnVsbFVybFxuICAgKi9cbiAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudChcbiAgICBmdWxsVXJsOiBzdHJpbmcgPSBudWxsXG4gICk6IFByb21pc2U8T0F1dGhTdWNjZXNzRXZlbnQ+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgaWYgKCFmdWxsVXJsKSB7XG4gICAgICAgIGZ1bGxVcmwgPSB0aGlzLmlzc3VlciB8fCAnJztcbiAgICAgICAgaWYgKCFmdWxsVXJsLmVuZHNXaXRoKCcvJykpIHtcbiAgICAgICAgICBmdWxsVXJsICs9ICcvJztcbiAgICAgICAgfVxuICAgICAgICBmdWxsVXJsICs9ICcud2VsbC1rbm93bi9vcGVuaWQtY29uZmlndXJhdGlvbic7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKGZ1bGxVcmwpKSB7XG4gICAgICAgIHJlamVjdChcbiAgICAgICAgICBcImlzc3VlciAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcbiAgICAgICAgKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmh0dHAuZ2V0PE9pZGNEaXNjb3ZlcnlEb2M+KGZ1bGxVcmwpLnN1YnNjcmliZShcbiAgICAgICAgZG9jID0+IHtcbiAgICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2MpKSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InLCBudWxsKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlamVjdCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB0aGlzLmxvZ2luVXJsID0gZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQ7XG4gICAgICAgICAgdGhpcy5sb2dvdXRVcmwgPSBkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQgfHwgdGhpcy5sb2dvdXRVcmw7XG4gICAgICAgICAgdGhpcy5ncmFudFR5cGVzU3VwcG9ydGVkID0gZG9jLmdyYW50X3R5cGVzX3N1cHBvcnRlZDtcbiAgICAgICAgICB0aGlzLmlzc3VlciA9IGRvYy5pc3N1ZXI7XG4gICAgICAgICAgdGhpcy50b2tlbkVuZHBvaW50ID0gZG9jLnRva2VuX2VuZHBvaW50O1xuICAgICAgICAgIHRoaXMudXNlcmluZm9FbmRwb2ludCA9XG4gICAgICAgICAgICBkb2MudXNlcmluZm9fZW5kcG9pbnQgfHwgdGhpcy51c2VyaW5mb0VuZHBvaW50O1xuICAgICAgICAgIHRoaXMuandrc1VyaSA9IGRvYy5qd2tzX3VyaTtcbiAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCA9XG4gICAgICAgICAgICBkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUgfHwgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XG5cbiAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gdHJ1ZTtcbiAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdC5uZXh0KGRvYyk7XG5cbiAgICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgdGhpcy5yZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHRoaXMubG9hZEp3a3MoKVxuICAgICAgICAgICAgLnRoZW4oandrcyA9PiB7XG4gICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogb2JqZWN0ID0ge1xuICAgICAgICAgICAgICAgIGRpc2NvdmVyeURvY3VtZW50OiBkb2MsXG4gICAgICAgICAgICAgICAgandrczogandrc1xuICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KFxuICAgICAgICAgICAgICAgICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJyxcbiAgICAgICAgICAgICAgICByZXN1bHRcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgICAgICAgICByZXNvbHZlKGV2ZW50KTtcbiAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC5jYXRjaChlcnIgPT4ge1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGRpc2NvdmVyeSBkb2N1bWVudCcsIGVycik7XG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICApO1xuICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICB9XG4gICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGxvYWRKd2tzKCk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPG9iamVjdD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgaWYgKHRoaXMuandrc1VyaSkge1xuICAgICAgICB0aGlzLmh0dHAuZ2V0KHRoaXMuandrc1VyaSkuc3Vic2NyaWJlKFxuICAgICAgICAgIGp3a3MgPT4ge1xuICAgICAgICAgICAgdGhpcy5qd2tzID0gandrcztcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlc29sdmUoandrcyk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgandrcycsIGVycik7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnandrc19sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJlc29sdmUobnVsbCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2M6IE9pZGNEaXNjb3ZlcnlEb2MpOiBib29sZWFuIHtcbiAgICBsZXQgZXJyb3JzOiBzdHJpbmdbXTtcblxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgZG9jLmlzc3VlciAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAnaW52YWxpZCBpc3N1ZXIgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgJ2V4cGVjdGVkOiAnICsgdGhpcy5pc3N1ZXIsXG4gICAgICAgICdjdXJyZW50OiAnICsgZG9jLmlzc3VlclxuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50KTtcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBhdXRob3JpemF0aW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgIGVycm9yc1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCk7XG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgZW5kX3Nlc3Npb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgZXJyb3JzXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnRva2VuX2VuZHBvaW50KTtcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB0b2tlbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICBlcnJvcnNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MudXNlcmluZm9fZW5kcG9pbnQpO1xuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHVzZXJpbmZvX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgIGVycm9yc1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5qd2tzX3VyaSk7XG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgandrc191cmkgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgZXJyb3JzXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IGRpc2NvdmVyeSBkb2N1bWVudCcgK1xuICAgICAgICAgICcgZG9lcyBub3QgY29udGFpbiBhIGNoZWNrX3Nlc3Npb25faWZyYW1lIGZpZWxkJ1xuICAgICAgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhblxuICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxuICAgKiB1c2VzIGl0IHRvIHF1ZXJ5IHRoZSB1c2VyaW5mbyBlbmRwb2ludCBpbiBvcmRlciB0byBnZXQgaW5mb3JtYXRpb25cbiAgICogYWJvdXQgdGhlIHVzZXIgaW4gcXVlc3Rpb24uXG4gICAqXG4gICAqIFdoZW4gdXNpbmcgdGhpcywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxuICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb25cbiAgICogZmFpbC5cbiAgICpcbiAgICogQHBhcmFtIHVzZXJOYW1lXG4gICAqIEBwYXJhbSBwYXNzd29yZFxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICovXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3dBbmRMb2FkVXNlclByb2ZpbGUoXG4gICAgdXNlck5hbWU6IHN0cmluZyxcbiAgICBwYXNzd29yZDogc3RyaW5nLFxuICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgKTogUHJvbWlzZTxVc2VySW5mbz4ge1xuICAgIHJldHVybiB0aGlzLmZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyhcbiAgICAgIHVzZXJOYW1lLFxuICAgICAgcGFzc3dvcmQsXG4gICAgICBoZWFkZXJzXG4gICAgKS50aGVuKCgpID0+IHRoaXMubG9hZFVzZXJQcm9maWxlKCkpO1xuICB9XG5cbiAgLyoqXG4gICAqIFVzZXMgZXh0ZXJuYWwgdG9rZW4gYW5kIHByb3ZpZGVyIGZvciBhblxuICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxuICAgKiB1c2VzIGl0IHRvIHF1ZXJ5IHRoZSB1c2VyaW5mbyBlbmRwb2ludCBpbiBvcmRlciB0byBnZXQgaW5mb3JtYXRpb25cbiAgICogYWJvdXQgdGhlIHVzZXIgaW4gcXVlc3Rpb24uXG4gICAqXG4gICAqIFdoZW4gdXNpbmcgdGhpcywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxuICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb25cbiAgICogZmFpbC5cbiAgICpcbiAgICogQHBhcmFtIHByb3ZpZGVyXG4gICAqIEBwYXJhbSBleHRlcm5hbF90b2tlblxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICovXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdFeHRlcm5hbFRva2VuQW5kTG9hZFVzZXJQcm9maWxlKFxuICAgIHByb3ZpZGVyOiBzdHJpbmcsXG4gICAgZXh0ZXJuYWxfdG9rZW46IHN0cmluZyxcbiAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgcmV0dXJuIHRoaXMuZmV0Y2hUb2tlblVzaW5nVXNpbmdFeHRlcm5hbFRva2VuKFxuICAgICAgcHJvdmlkZXIsXG4gICAgICBleHRlcm5hbF90b2tlbixcbiAgICAgIGhlYWRlcnNcbiAgICApLnRoZW4oKCkgPT4gdGhpcy5sb2FkVXNlclByb2ZpbGUoKSk7XG4gIH1cblxuICAvKipcbiAgICogTG9hZHMgdGhlIHVzZXIgcHJvZmlsZSBieSBhY2Nlc3NpbmcgdGhlIHVzZXIgaW5mbyBlbmRwb2ludCBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0LlxuICAgKlxuICAgKiBXaGVuIHVzaW5nIHRoaXMgd2l0aCBPQXV0aDIgcGFzc3dvcmQgZmxvdywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxuICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb24gZmFpbC5cbiAgICovXG4gIHB1YmxpYyBsb2FkVXNlclByb2ZpbGUoKTogUHJvbWlzZTxVc2VySW5mbz4ge1xuICAgIGlmICghdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQ2FuIG5vdCBsb2FkIFVzZXIgUHJvZmlsZSB3aXRob3V0IGFjY2Vzc190b2tlbicpO1xuICAgIH1cbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnVzZXJpbmZvRW5kcG9pbnQpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwidXNlcmluZm9FbmRwb2ludCBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxuICAgICAgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgY29uc3QgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxuICAgICAgICAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKClcbiAgICAgICk7XG5cbiAgICAgIHRoaXMuaHR0cFxuICAgICAgICAuZ2V0PFVzZXJJbmZvPih0aGlzLnVzZXJpbmZvRW5kcG9pbnQsIHsgaGVhZGVycyB9KVxuICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgIGluZm8gPT4ge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygndXNlcmluZm8gcmVjZWl2ZWQnLCBpbmZvKTtcblxuICAgICAgICAgICAgY29uc3QgZXhpc3RpbmdDbGFpbXMgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XG5cbiAgICAgICAgICAgIGlmICghdGhpcy5za2lwU3ViamVjdENoZWNrKSB7XG4gICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICB0aGlzLm9pZGMgJiZcbiAgICAgICAgICAgICAgICAoIWV4aXN0aW5nQ2xhaW1zWydzdWInXSB8fCBpbmZvLnN1YiAhPT0gZXhpc3RpbmdDbGFpbXNbJ3N1YiddKVxuICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICBjb25zdCBlcnIgPVxuICAgICAgICAgICAgICAgICAgJ2lmIHByb3BlcnR5IG9pZGMgaXMgdHJ1ZSwgdGhlIHJlY2VpdmVkIHVzZXItaWQgKHN1YikgaGFzIHRvIGJlIHRoZSB1c2VyLWlkICcgK1xuICAgICAgICAgICAgICAgICAgJ29mIHRoZSB1c2VyIHRoYXQgaGFzIGxvZ2dlZCBpbiB3aXRoIG9pZGMuXFxuJyArXG4gICAgICAgICAgICAgICAgICAnaWYgeW91IGFyZSBub3QgdXNpbmcgb2lkYyBidXQganVzdCBvYXV0aDIgcGFzc3dvcmQgZmxvdyBzZXQgb2lkYyB0byBmYWxzZSc7XG5cbiAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaW5mbyA9IE9iamVjdC5hc3NpZ24oe30sIGV4aXN0aW5nQ2xhaW1zLCBpbmZvKTtcblxuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJywgSlNPTi5zdHJpbmdpZnkoaW5mbykpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndXNlcl9wcm9maWxlX2xvYWRlZCcpXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmVzb2x2ZShpbmZvKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyB1c2VyIGluZm8nLCBlcnIpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3VzZXJfcHJvZmlsZV9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBVc2VzIHByb3ZpZGVyIGFuZCBleHRlcm5hbCB0b2tlbiBmb3IgYW4gYWNjZXNzX3Rva2VuLlxuICAgKiBAcGFyYW0gcHJvdmlkZXJcbiAgICogQHBhcmFtIGV4dGVybmFsX3Rva2VuXG4gICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxuICAgKi9cbiAgcHVibGljIGZldGNoVG9rZW5Vc2luZ1VzaW5nRXh0ZXJuYWxUb2tlbihcbiAgICBwcm92aWRlcjogc3RyaW5nLFxuICAgIGV4dGVybmFsX3Rva2VuOiBzdHJpbmcsXG4gICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICApOiBQcm9taXNlPG9iamVjdD4ge1xuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMudG9rZW5FbmRwb2ludCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgJ3Rva2VuRW5kcG9pbnQgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8qKlxuICAgICAgICogQSBgSHR0cFBhcmFtZXRlckNvZGVjYCB0aGF0IHVzZXMgYGVuY29kZVVSSUNvbXBvbmVudGAgYW5kIGBkZWNvZGVVUklDb21wb25lbnRgIHRvXG4gICAgICAgKiBzZXJpYWxpemUgYW5kIHBhcnNlIFVSTCBwYXJhbWV0ZXIga2V5cyBhbmQgdmFsdWVzLlxuICAgICAgICpcbiAgICAgICAqIEBzdGFibGVcbiAgICAgICAqL1xuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHsgZW5jb2RlcjogbmV3IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjKCkgfSlcbiAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdleHRlcm5hbCcpXG4gICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcbiAgICAgICAgLnNldCgncHJvdmlkZXInLCBwcm92aWRlcilcbiAgICAgICAgLnNldCgnZXh0ZXJuYWxfdG9rZW4nLCBleHRlcm5hbF90b2tlbik7XG5cbiAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgICApO1xuXG4gICAgICB0aGlzLmh0dHBcbiAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZVxuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHBlcmZvcm1pbmcgZXh0ZXJuYWwgdG9rZW4gZmxvdycsIGVycik7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIGVycikpO1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgfVxuICAgICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuIGFjY2Vzc190b2tlbi5cbiAgICogQHBhcmFtIHVzZXJOYW1lXG4gICAqIEBwYXJhbSBwYXNzd29yZFxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICovXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3coXG4gICAgdXNlck5hbWU6IHN0cmluZyxcbiAgICBwYXNzd29yZDogc3RyaW5nLFxuICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XG4gICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxuICAgICAgJ3Rva2VuRW5kcG9pbnQnXG4gICAgKTtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvKipcbiAgICAgICAqIEEgYEh0dHBQYXJhbWV0ZXJDb2RlY2AgdGhhdCB1c2VzIGBlbmNvZGVVUklDb21wb25lbnRgIGFuZCBgZGVjb2RlVVJJQ29tcG9uZW50YCB0b1xuICAgICAgICogc2VyaWFsaXplIGFuZCBwYXJzZSBVUkwgcGFyYW1ldGVyIGtleXMgYW5kIHZhbHVlcy5cbiAgICAgICAqXG4gICAgICAgKiBAc3RhYmxlXG4gICAgICAgKi9cbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7IGVuY29kZXI6IG5ldyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYygpIH0pXG4gICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAncGFzc3dvcmQnKVxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgIC5zZXQoJ3VzZXJuYW1lJywgdXNlck5hbWUpXG4gICAgICAgIC5zZXQoJ3Bhc3N3b3JkJywgcGFzc3dvcmQpO1xuXG4gICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgIH1cblxuICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICdDb250ZW50LVR5cGUnLFxuICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xuICAgICAgKTtcblxuICAgICAgdGhpcy5odHRwXG4gICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcbiAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcGVyZm9ybWluZyBwYXNzd29yZCBmbG93JywgZXJyKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX2Vycm9yJywgZXJyKSk7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogUmVmcmVzaGVzIHRoZSB0b2tlbiB1c2luZyBhIHJlZnJlc2hfdG9rZW4uXG4gICAqIFRoaXMgZG9lcyBub3Qgd29yayBmb3IgaW1wbGljaXQgZmxvdywgYi9jXG4gICAqIHRoZXJlIGlzIG5vIHJlZnJlc2hfdG9rZW4gaW4gdGhpcyBmbG93LlxuICAgKiBBIHNvbHV0aW9uIGZvciB0aGlzIGlzIHByb3ZpZGVkIGJ5IHRoZVxuICAgKiBtZXRob2Qgc2lsZW50UmVmcmVzaC5cbiAgICovXG4gIHB1YmxpYyByZWZyZXNoVG9rZW4oKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XG4gICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxuICAgICAgJ3Rva2VuRW5kcG9pbnQnXG4gICAgKTtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxuICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3JlZnJlc2hfdG9rZW4nKVxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgIC5zZXQoJ3JlZnJlc2hfdG9rZW4nLCB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKSk7XG5cbiAgICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxuICAgICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICk7XG5cbiAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHRoaXMuaHR0cFxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgIC5waXBlKFxuICAgICAgICAgIHN3aXRjaE1hcCh0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgIGlmICh0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgIHJldHVybiBmcm9tKFxuICAgICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4oXG4gICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmlkX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgICAgICB0cnVlXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICApLnBpcGUoXG4gICAgICAgICAgICAgICAgdGFwKHJlc3VsdCA9PiB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpKSxcbiAgICAgICAgICAgICAgICBtYXAoXyA9PiB0b2tlblJlc3BvbnNlKVxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgcmV0dXJuIG9mKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pXG4gICAgICAgIClcbiAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3JlZnJlc2ggdG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZSxcbiAgICAgICAgICAgICAgdGhpcy5leHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnModG9rZW5SZXNwb25zZSlcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcbiAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJlZnJlc2hpbmcgdG9rZW4nLCBlcnIpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3JlZnJlc2hfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgfVxuICAgICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIHJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIpIHtcbiAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKFxuICAgICAgICAnbWVzc2FnZScsXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxuICAgICAgKTtcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHNldHVwU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XG5cbiAgICAgIHRoaXMudHJ5TG9naW4oe1xuICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXG4gICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxuICAgICAgICBjdXN0b21SZWRpcmVjdFVyaTogdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaVxuICAgICAgfSkuY2F0Y2goZXJyID0+IHRoaXMuZGVidWcoJ3RyeUxvZ2luIGR1cmluZyBzaWxlbnQgcmVmcmVzaCBmYWlsZWQnLCBlcnIpKTtcbiAgICB9O1xuXG4gICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXG4gICAgICAnbWVzc2FnZScsXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcbiAgICApO1xuICB9XG5cbiAgLyoqXG4gICAqIFBlcmZvcm1zIGEgc2lsZW50IHJlZnJlc2ggZm9yIGltcGxpY2l0IGZsb3cuXG4gICAqIFVzZSB0aGlzIG1ldGhvZCB0byBnZXQgbmV3IHRva2VucyB3aGVuL2JlZm9yZVxuICAgKiB0aGUgZXhpc3RpbmcgdG9rZW5zIGV4cGlyZS5cbiAgICovXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoKFxuICAgIHBhcmFtczogb2JqZWN0ID0ge30sXG4gICAgbm9Qcm9tcHQgPSB0cnVlXG4gICk6IFByb21pc2U8T0F1dGhFdmVudD4ge1xuICAgIGNvbnN0IGNsYWltczogb2JqZWN0ID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xuXG4gICAgaWYgKHRoaXMudXNlSWRUb2tlbkhpbnRGb3JTaWxlbnRSZWZyZXNoICYmIHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcbiAgICAgIHBhcmFtc1snaWRfdG9rZW5faGludCddID0gdGhpcy5nZXRJZFRva2VuKCk7XG4gICAgfVxuXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgXCJsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcbiAgICAgICk7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignc2lsZW50IHJlZnJlc2ggaXMgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXRmb3JtJyk7XG4gICAgfVxuXG4gICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWVcbiAgICApO1xuXG4gICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XG4gICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcbiAgICB9XG5cbiAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gY2xhaW1zWydzdWInXTtcblxuICAgIGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWU7XG5cbiAgICB0aGlzLnNldHVwU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcblxuICAgIGNvbnN0IHJlZGlyZWN0VXJpID0gdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKG51bGwsIG51bGwsIHJlZGlyZWN0VXJpLCBub1Byb21wdCwgcGFyYW1zKS50aGVuKHVybCA9PiB7XG4gICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xuXG4gICAgICBpZiAoIXRoaXMuc2lsZW50UmVmcmVzaFNob3dJRnJhbWUpIHtcbiAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XG4gICAgICB9XG4gICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XG4gICAgfSk7XG5cbiAgICBjb25zdCBlcnJvcnMgPSB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgZmlsdGVyKGUgPT4gZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCksXG4gICAgICBmaXJzdCgpXG4gICAgKTtcbiAgICBjb25zdCBzdWNjZXNzID0gdGhpcy5ldmVudHMucGlwZShcbiAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJyksXG4gICAgICBmaXJzdCgpXG4gICAgKTtcbiAgICBjb25zdCB0aW1lb3V0ID0gb2YoXG4gICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JywgbnVsbClcbiAgICApLnBpcGUoZGVsYXkodGhpcy5zaWxlbnRSZWZyZXNoVGltZW91dCkpO1xuXG4gICAgcmV0dXJuIHJhY2UoW2Vycm9ycywgc3VjY2VzcywgdGltZW91dF0pXG4gICAgICAucGlwZShcbiAgICAgICAgbWFwKGUgPT4ge1xuICAgICAgICAgIGlmIChlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSB7XG4gICAgICAgICAgICBpZiAoZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcpIHtcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBlID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfZXJyb3InLCBlKTtcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0aHJvdyBlO1xuICAgICAgICAgIH0gZWxzZSBpZiAoZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSB7XG4gICAgICAgICAgICBlID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdzaWxlbnRseV9yZWZyZXNoZWQnKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gZTtcbiAgICAgICAgfSlcbiAgICAgIClcbiAgICAgIC50b1Byb21pc2UoKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIG1ldGhvZCBleGlzdHMgZm9yIGJhY2t3YXJkcyBjb21wYXRpYmlsaXR5LlxuICAgKiB7QGxpbmsgT0F1dGhTZXJ2aWNlI2luaXRMb2dpbkZsb3dJblBvcHVwfSBoYW5kbGVzIGJvdGggY29kZVxuICAgKiBhbmQgaW1wbGljaXQgZmxvd3MuXG4gICAqL1xuICBwdWJsaWMgaW5pdEltcGxpY2l0Rmxvd0luUG9wdXAob3B0aW9ucz86IHtcbiAgICBoZWlnaHQ/OiBudW1iZXI7XG4gICAgd2lkdGg/OiBudW1iZXI7XG4gIH0pIHtcbiAgICByZXR1cm4gdGhpcy5pbml0TG9naW5GbG93SW5Qb3B1cChvcHRpb25zKTtcbiAgfVxuXG4gIHB1YmxpYyBpbml0TG9naW5GbG93SW5Qb3B1cChvcHRpb25zPzogeyBoZWlnaHQ/OiBudW1iZXI7IHdpZHRoPzogbnVtYmVyIH0pIHtcbiAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcbiAgICByZXR1cm4gdGhpcy5jcmVhdGVMb2dpblVybChcbiAgICAgIG51bGwsXG4gICAgICBudWxsLFxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmksXG4gICAgICBmYWxzZSxcbiAgICAgIHtcbiAgICAgICAgZGlzcGxheTogJ3BvcHVwJ1xuICAgICAgfVxuICAgICkudGhlbih1cmwgPT4ge1xuICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIEVycm9yIGhhbmRsaW5nIHNlY3Rpb25cbiAgICAgICAgICovXG4gICAgICAgIGNvbnN0IGNoZWNrRm9yUG9wdXBDbG9zZWRJbnRlcnZhbCA9IDUwMDtcbiAgICAgICAgbGV0IHdpbmRvd1JlZiA9IHdpbmRvdy5vcGVuKFxuICAgICAgICAgIHVybCxcbiAgICAgICAgICAnX2JsYW5rJyxcbiAgICAgICAgICB0aGlzLmNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9ucylcbiAgICAgICAgKTtcbiAgICAgICAgbGV0IGNoZWNrRm9yUG9wdXBDbG9zZWRUaW1lcjogYW55O1xuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkID0gKCkgPT4ge1xuICAgICAgICAgIGlmICghd2luZG93UmVmIHx8IHdpbmRvd1JlZi5jbG9zZWQpIHtcbiAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9jbG9zZWQnLCB7fSkpO1xuICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICAgICAgaWYgKCF3aW5kb3dSZWYpIHtcbiAgICAgICAgICByZWplY3QobmV3IE9BdXRoRXJyb3JFdmVudCgncG9wdXBfYmxvY2tlZCcsIHt9KSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyID0gd2luZG93LnNldEludGVydmFsKFxuICAgICAgICAgICAgY2hlY2tGb3JQb3B1cENsb3NlZCxcbiAgICAgICAgICAgIGNoZWNrRm9yUG9wdXBDbG9zZWRJbnRlcnZhbFxuICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBjbGVhbnVwID0gKCkgPT4ge1xuICAgICAgICAgIHdpbmRvdy5jbGVhckludGVydmFsKGNoZWNrRm9yUG9wdXBDbG9zZWRUaW1lcik7XG4gICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XG4gICAgICAgICAgaWYgKHdpbmRvd1JlZiAhPT0gbnVsbCkge1xuICAgICAgICAgICAgd2luZG93UmVmLmNsb3NlKCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHdpbmRvd1JlZiA9IG51bGw7XG4gICAgICAgIH07XG5cbiAgICAgICAgY29uc3QgbGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XG5cbiAgICAgICAgICBpZiAobWVzc2FnZSAmJiBtZXNzYWdlICE9PSBudWxsKSB7XG4gICAgICAgICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxuICAgICAgICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcbiAgICAgICAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmk6IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpXG4gICAgICAgICAgICB9KS50aGVuKFxuICAgICAgICAgICAgICAoKSA9PiB7XG4gICAgICAgICAgICAgICAgY2xlYW51cCgpO1xuICAgICAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XG4gICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCdmYWxzZSBldmVudCBmaXJpbmcnKTtcbiAgICAgICAgICB9XG4gICAgICAgIH07XG5cbiAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBjYWxjdWxhdGVQb3B1cEZlYXR1cmVzKG9wdGlvbnM6IHtcbiAgICBoZWlnaHQ/OiBudW1iZXI7XG4gICAgd2lkdGg/OiBudW1iZXI7XG4gIH0pOiBzdHJpbmcge1xuICAgIC8vIFNwZWNpZnkgYW4gc3RhdGljIGhlaWdodCBhbmQgd2lkdGggYW5kIGNhbGN1bGF0ZSBjZW50ZXJlZCBwb3NpdGlvblxuXG4gICAgY29uc3QgaGVpZ2h0ID0gb3B0aW9ucy5oZWlnaHQgfHwgNDcwO1xuICAgIGNvbnN0IHdpZHRoID0gb3B0aW9ucy53aWR0aCB8fCA1MDA7XG4gICAgY29uc3QgbGVmdCA9IHdpbmRvdy5zY3JlZW5MZWZ0ICsgKHdpbmRvdy5vdXRlcldpZHRoIC0gd2lkdGgpIC8gMjtcbiAgICBjb25zdCB0b3AgPSB3aW5kb3cuc2NyZWVuVG9wICsgKHdpbmRvdy5vdXRlckhlaWdodCAtIGhlaWdodCkgLyAyO1xuICAgIHJldHVybiBgbG9jYXRpb249bm8sdG9vbGJhcj1ubyx3aWR0aD0ke3dpZHRofSxoZWlnaHQ9JHtoZWlnaHR9LHRvcD0ke3RvcH0sbGVmdD0ke2xlZnR9YDtcbiAgfVxuXG4gIHByb3RlY3RlZCBwcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlOiBNZXNzYWdlRXZlbnQpOiBzdHJpbmcge1xuICAgIGxldCBleHBlY3RlZFByZWZpeCA9ICcjJztcblxuICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4KSB7XG4gICAgICBleHBlY3RlZFByZWZpeCArPSB0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4O1xuICAgIH1cblxuICAgIGlmICghZSB8fCAhZS5kYXRhIHx8IHR5cGVvZiBlLmRhdGEgIT09ICdzdHJpbmcnKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgcHJlZml4ZWRNZXNzYWdlOiBzdHJpbmcgPSBlLmRhdGE7XG5cbiAgICBpZiAoIXByZWZpeGVkTWVzc2FnZS5zdGFydHNXaXRoKGV4cGVjdGVkUHJlZml4KSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHJldHVybiAnIycgKyBwcmVmaXhlZE1lc3NhZ2Uuc3Vic3RyKGV4cGVjdGVkUHJlZml4Lmxlbmd0aCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgY2FuUGVyZm9ybVNlc3Npb25DaGVjaygpOiBib29sZWFuIHtcbiAgICBpZiAoIXRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCkge1xuICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uQ2hlY2tJRnJhbWVVcmwnXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xuICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XG4gICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25fc3RhdGUnXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xuICB9XG5cbiAgcHJvdGVjdGVkIHNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICB0aGlzLnJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcblxuICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIGNvbnN0IG9yaWdpbiA9IGUub3JpZ2luLnRvTG93ZXJDYXNlKCk7XG4gICAgICBjb25zdCBpc3N1ZXIgPSB0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpO1xuXG4gICAgICB0aGlzLmRlYnVnKCdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyk7XG5cbiAgICAgIGlmICghaXNzdWVyLnN0YXJ0c1dpdGgob3JpZ2luKSkge1xuICAgICAgICB0aGlzLmRlYnVnKFxuICAgICAgICAgICdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyxcbiAgICAgICAgICAnd3Jvbmcgb3JpZ2luJyxcbiAgICAgICAgICBvcmlnaW4sXG4gICAgICAgICAgJ2V4cGVjdGVkJyxcbiAgICAgICAgICBpc3N1ZXIsXG4gICAgICAgICAgJ2V2ZW50JyxcbiAgICAgICAgICBlXG4gICAgICAgICk7XG5cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBvbmx5IHJ1biBpbiBBbmd1bGFyIHpvbmUgaWYgaXQgaXMgJ2NoYW5nZWQnIG9yICdlcnJvcidcbiAgICAgIHN3aXRjaCAoZS5kYXRhKSB7XG4gICAgICAgIGNhc2UgJ3VuY2hhbmdlZCc6XG4gICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ2NoYW5nZWQnOlxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25DaGFuZ2UoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnZXJyb3InOlxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25FcnJvcigpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmRlYnVnKCdnb3QgaW5mbyBmcm9tIHNlc3Npb24gY2hlY2sgaW5mcmFtZScsIGUpO1xuICAgIH07XG5cbiAgICAvLyBwcmV2ZW50IEFuZ3VsYXIgZnJvbSByZWZyZXNoaW5nIHRoZSB2aWV3IG9uIGV2ZXJ5IG1lc3NhZ2UgKHJ1bnMgaW4gaW50ZXJ2YWxzKVxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk6IHZvaWQge1xuICAgIHRoaXMuZGVidWcoJ3Nlc3Npb24gY2hlY2snLCAnc2Vzc2lvbiB1bmNoYW5nZWQnKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uQ2hhbmdlKCk6IHZvaWQge1xuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9jaGFuZ2VkJykpO1xuICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG5cbiAgICBpZiAoIXRoaXMudXNlU2lsZW50UmVmcmVzaCAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICB0aGlzLnJlZnJlc2hUb2tlbigpXG4gICAgICAgIC50aGVuKF8gPT4ge1xuICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuIHJlZnJlc2ggYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2Ugd29ya2VkJyk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaChfID0+IHtcbiAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlbiByZWZyZXNoIGRpZCBub3Qgd29yayBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKTtcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcbiAgICAgICAgfSk7XG4gICAgfSBlbHNlIGlmICh0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSkge1xuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoKCkuY2F0Y2goXyA9PlxuICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBmYWlsZWQgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJylcbiAgICAgICk7XG4gICAgICB0aGlzLndhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xuICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHdhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCk6IHZvaWQge1xuICAgIHRoaXMuZXZlbnRzXG4gICAgICAucGlwZShcbiAgICAgICAgZmlsdGVyKFxuICAgICAgICAgIChlOiBPQXV0aEV2ZW50KSA9PlxuICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50bHlfcmVmcmVzaGVkJyB8fFxuICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcgfHxcbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX2Vycm9yJ1xuICAgICAgICApLFxuICAgICAgICBmaXJzdCgpXG4gICAgICApXG4gICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICBpZiAoZS50eXBlICE9PSAnc2lsZW50bHlfcmVmcmVzaGVkJykge1xuICAgICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGRpZCBub3Qgd29yayBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKTtcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkVycm9yKCk6IHZvaWQge1xuICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2Vycm9yJykpO1xuICB9XG5cbiAgcHJvdGVjdGVkIHJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcikge1xuICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgaW5pdFNlc3Npb25DaGVjaygpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMuY2FuUGVyZm9ybVNlc3Npb25DaGVjaygpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xuICAgICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XG4gICAgfVxuXG4gICAgY29uc3QgaWZyYW1lID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XG4gICAgaWZyYW1lLmlkID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lO1xuXG4gICAgdGhpcy5zZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcblxuICAgIGNvbnN0IHVybCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xuICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHVybCk7XG4gICAgaWZyYW1lLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7XG4gICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xuXG4gICAgdGhpcy5zdGFydFNlc3Npb25DaGVja1RpbWVyKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpOiB2b2lkIHtcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIgPSBzZXRJbnRlcnZhbChcbiAgICAgICAgdGhpcy5jaGVja1Nlc3Npb24uYmluZCh0aGlzKSxcbiAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJbnRlcnZhbGxcbiAgICAgICk7XG4gICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc3RvcFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja1RpbWVyKSB7XG4gICAgICBjbGVhckludGVydmFsKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpO1xuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHVibGljIGNoZWNrU2Vzc2lvbigpOiB2b2lkIHtcbiAgICBjb25zdCBpZnJhbWU6IGFueSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZSk7XG5cbiAgICBpZiAoIWlmcmFtZSkge1xuICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgJ2NoZWNrU2Vzc2lvbiBkaWQgbm90IGZpbmQgaWZyYW1lJyxcbiAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lXG4gICAgICApO1xuICAgIH1cblxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XG5cbiAgICBpZiAoIXNlc3Npb25TdGF0ZSkge1xuICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICB9XG5cbiAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5jbGllbnRJZCArICcgJyArIHNlc3Npb25TdGF0ZTtcbiAgICBpZnJhbWUuY29udGVudFdpbmRvdy5wb3N0TWVzc2FnZShtZXNzYWdlLCB0aGlzLmlzc3Vlcik7XG4gIH1cblxuICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlTG9naW5VcmwoXG4gICAgc3RhdGUgPSAnJyxcbiAgICBsb2dpbkhpbnQgPSAnJyxcbiAgICBjdXN0b21SZWRpcmVjdFVyaSA9ICcnLFxuICAgIG5vUHJvbXB0ID0gZmFsc2UsXG4gICAgcGFyYW1zOiBvYmplY3QgPSB7fVxuICApOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuXG4gICAgbGV0IHJlZGlyZWN0VXJpOiBzdHJpbmc7XG5cbiAgICBpZiAoY3VzdG9tUmVkaXJlY3RVcmkpIHtcbiAgICAgIHJlZGlyZWN0VXJpID0gY3VzdG9tUmVkaXJlY3RVcmk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlZGlyZWN0VXJpID0gdGhpcy5yZWRpcmVjdFVyaTtcbiAgICB9XG5cbiAgICBjb25zdCBub25jZSA9IGF3YWl0IHRoaXMuY3JlYXRlQW5kU2F2ZU5vbmNlKCk7XG5cbiAgICBpZiAoc3RhdGUpIHtcbiAgICAgIHN0YXRlID1cbiAgICAgICAgbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc3RhdGUgPSBub25jZTtcbiAgICB9XG5cbiAgICBpZiAoIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICF0aGlzLm9pZGMpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIG9yIGJvdGggbXVzdCBiZSB0cnVlJyk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSkge1xuICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSB0aGlzLmNvbmZpZy5yZXNwb25zZVR5cGU7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAnaWRfdG9rZW4gdG9rZW4nO1xuICAgICAgfSBlbHNlIGlmICh0aGlzLm9pZGMgJiYgIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuJztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ3Rva2VuJztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBzZXBlcmF0aW9uQ2hhciA9IHRoYXQubG9naW5VcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPyc7XG5cbiAgICBsZXQgc2NvcGUgPSB0aGF0LnNjb3BlO1xuXG4gICAgaWYgKHRoaXMub2lkYyAmJiAhc2NvcGUubWF0Y2goLyhefFxccylvcGVuaWQoJHxcXHMpLykpIHtcbiAgICAgIHNjb3BlID0gJ29wZW5pZCAnICsgc2NvcGU7XG4gICAgfVxuXG4gICAgbGV0IHVybCA9XG4gICAgICB0aGF0LmxvZ2luVXJsICtcbiAgICAgIHNlcGVyYXRpb25DaGFyICtcbiAgICAgICdyZXNwb25zZV90eXBlPScgK1xuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXG4gICAgICAnJmNsaWVudF9pZD0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LmNsaWVudElkKSArXG4gICAgICAnJnN0YXRlPScgK1xuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKSArXG4gICAgICAnJnJlZGlyZWN0X3VyaT0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xuICAgICAgJyZzY29wZT0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzY29wZSk7XG5cbiAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJyAmJiAhdGhpcy5kaXNhYmxlUEtDRSkge1xuICAgICAgY29uc3QgW1xuICAgICAgICBjaGFsbGVuZ2UsXG4gICAgICAgIHZlcmlmaWVyXG4gICAgICBdID0gYXdhaXQgdGhpcy5jcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk7XG5cbiAgICAgIGlmIChcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgICApIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInLCB2ZXJpZmllcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInLCB2ZXJpZmllcik7XG4gICAgICB9XG5cbiAgICAgIHVybCArPSAnJmNvZGVfY2hhbGxlbmdlPScgKyBjaGFsbGVuZ2U7XG4gICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZV9tZXRob2Q9UzI1Nic7XG4gICAgfVxuXG4gICAgaWYgKGxvZ2luSGludCkge1xuICAgICAgdXJsICs9ICcmbG9naW5faGludD0nICsgZW5jb2RlVVJJQ29tcG9uZW50KGxvZ2luSGludCk7XG4gICAgfVxuXG4gICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcbiAgICAgIHVybCArPSAnJnJlc291cmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQodGhhdC5yZXNvdXJjZSk7XG4gICAgfVxuXG4gICAgaWYgKHRoYXQub2lkYykge1xuICAgICAgdXJsICs9ICcmbm9uY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudChub25jZSk7XG4gICAgfVxuXG4gICAgaWYgKG5vUHJvbXB0KSB7XG4gICAgICB1cmwgKz0gJyZwcm9tcHQ9bm9uZSc7XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xuICAgICAgdXJsICs9XG4gICAgICAgICcmJyArIGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHBhcmFtc1trZXldKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgdXJsICs9XG4gICAgICAgICAgJyYnICsga2V5ICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHVybDtcbiAgfVxuXG4gIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcbiAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXG4gICk6IHZvaWQge1xuICAgIGlmICh0aGlzLmluSW1wbGljaXRGbG93KSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IHRydWU7XG5cbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxuICAgICAgKTtcbiAgICB9XG5cbiAgICBsZXQgYWRkUGFyYW1zOiBvYmplY3QgPSB7fTtcbiAgICBsZXQgbG9naW5IaW50OiBzdHJpbmcgPSBudWxsO1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBsb2dpbkhpbnQgPSBwYXJhbXM7XG4gICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xuICAgICAgYWRkUGFyYW1zID0gcGFyYW1zO1xuICAgIH1cblxuICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCBsb2dpbkhpbnQsIG51bGwsIGZhbHNlLCBhZGRQYXJhbXMpXG4gICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEltcGxpY2l0RmxvdycsIGVycm9yKTtcbiAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICAgICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogU3RhcnRzIHRoZSBpbXBsaWNpdCBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgKiB0aGUgYXV0aCBzZXJ2ZXJzJyBsb2dpbiB1cmwuXG4gICAqXG4gICAqIEBwYXJhbSBhZGRpdGlvbmFsU3RhdGUgT3B0aW9uYWwgc3RhdGUgdGhhdCBpcyBwYXNzZWQgYXJvdW5kLlxuICAgKiAgWW91J2xsIGZpbmQgdGhpcyBzdGF0ZSBpbiB0aGUgcHJvcGVydHkgYHN0YXRlYCBhZnRlciBgdHJ5TG9naW5gIGxvZ2dlZCBpbiB0aGUgdXNlci5cbiAgICogQHBhcmFtIHBhcmFtcyBIYXNoIHdpdGggYWRkaXRpb25hbCBwYXJhbWV0ZXIuIElmIGl0IGlzIGEgc3RyaW5nLCBpdCBpcyB1c2VkIGZvciB0aGVcbiAgICogICAgICAgICAgICAgICBwYXJhbWV0ZXIgbG9naW5IaW50IChmb3IgdGhlIHNha2Ugb2YgY29tcGF0aWJpbGl0eSB3aXRoIGZvcm1lciB2ZXJzaW9ucylcbiAgICovXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93KFxuICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgKTogdm9pZCB7XG4gICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuZXZlbnRzXG4gICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlc2V0IGN1cnJlbnQgaW1wbGljaXQgZmxvd1xuICAgKlxuICAgKiBAZGVzY3JpcHRpb24gVGhpcyBtZXRob2QgYWxsb3dzIHJlc2V0dGluZyB0aGUgY3VycmVudCBpbXBsaWN0IGZsb3cgaW4gb3JkZXIgdG8gYmUgaW5pdGlhbGl6ZWQgYWdhaW4uXG4gICAqL1xuICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XG4gICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICB9XG5cbiAgcHJvdGVjdGVkIGNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zOiBMb2dpbk9wdGlvbnMpOiB2b2lkIHtcbiAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICBpZiAob3B0aW9ucy5vblRva2VuUmVjZWl2ZWQpIHtcbiAgICAgIGNvbnN0IHRva2VuUGFyYW1zID0ge1xuICAgICAgICBpZENsYWltczogdGhhdC5nZXRJZGVudGl0eUNsYWltcygpLFxuICAgICAgICBpZFRva2VuOiB0aGF0LmdldElkVG9rZW4oKSxcbiAgICAgICAgYWNjZXNzVG9rZW46IHRoYXQuZ2V0QWNjZXNzVG9rZW4oKSxcbiAgICAgICAgc3RhdGU6IHRoYXQuc3RhdGVcbiAgICAgIH07XG4gICAgICBvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCh0b2tlblBhcmFtcyk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgIHJlZnJlc2hUb2tlbjogc3RyaW5nLFxuICAgIGV4cGlyZXNJbjogbnVtYmVyLFxuICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZyxcbiAgICBjdXN0b21QYXJhbWV0ZXJzPzogTWFwPHN0cmluZywgc3RyaW5nPlxuICApOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcbiAgICBpZiAoZ3JhbnRlZFNjb3BlcyAmJiAhQXJyYXkuaXNBcnJheShncmFudGVkU2NvcGVzKSkge1xuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKFxuICAgICAgICAnZ3JhbnRlZF9zY29wZXMnLFxuICAgICAgICBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzLnNwbGl0KCcrJykpXG4gICAgICApO1xuICAgIH0gZWxzZSBpZiAoZ3JhbnRlZFNjb3BlcyAmJiBBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XG4gICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJywgSlNPTi5zdHJpbmdpZnkoZ3JhbnRlZFNjb3BlcykpO1xuICAgIH1cblxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcsICcnICsgRGF0ZS5ub3coKSk7XG4gICAgaWYgKGV4cGlyZXNJbikge1xuICAgICAgY29uc3QgZXhwaXJlc0luTWlsbGlTZWNvbmRzID0gZXhwaXJlc0luICogMTAwMDtcbiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICBjb25zdCBleHBpcmVzQXQgPSBub3cuZ2V0VGltZSgpICsgZXhwaXJlc0luTWlsbGlTZWNvbmRzO1xuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdleHBpcmVzX2F0JywgJycgKyBleHBpcmVzQXQpO1xuICAgIH1cblxuICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgncmVmcmVzaF90b2tlbicsIHJlZnJlc2hUb2tlbik7XG4gICAgfVxuICAgIGlmIChjdXN0b21QYXJhbWV0ZXJzKSB7XG4gICAgICBjdXN0b21QYXJhbWV0ZXJzLmZvckVhY2goKHZhbHVlOiBzdHJpbmcsIGtleTogc3RyaW5nKSA9PiB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShrZXksIHZhbHVlKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBEZWxlZ2F0ZXMgdG8gdHJ5TG9naW5JbXBsaWNpdEZsb3cgZm9yIHRoZSBzYWtlIG9mIGNvbXBldGFiaWxpdHlcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICovXG4gIHB1YmxpYyB0cnlMb2dpbihvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkNvZGVGbG93KG9wdGlvbnMpLnRoZW4oXyA9PiB0cnVlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBvYmplY3Qge1xuICAgIGlmICghcXVlcnlTdHJpbmcgfHwgcXVlcnlTdHJpbmcubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm4ge307XG4gICAgfVxuXG4gICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XG4gICAgICBxdWVyeVN0cmluZyA9IHF1ZXJ5U3RyaW5nLnN1YnN0cigxKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XG4gIH1cblxuICBwdWJsaWMgdHJ5TG9naW5Db2RlRmxvdyhvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgICBjb25zdCBxdWVyeVNvdXJjZSA9IG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50XG4gICAgICA/IG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50LnN1YnN0cmluZygxKVxuICAgICAgOiB3aW5kb3cubG9jYXRpb24uc2VhcmNoO1xuXG4gICAgY29uc3QgcGFydHMgPSB0aGlzLmdldENvZGVQYXJ0c0Zyb21VcmwocXVlcnlTb3VyY2UpO1xuXG4gICAgY29uc3QgY29kZSA9IHBhcnRzWydjb2RlJ107XG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XG5cbiAgICBpZiAoIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgIGNvbnN0IGhyZWYgPSBsb2NhdGlvbi5ocmVmXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11jb2RlPVteJlxcJF0qLywgJycpXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAucmVwbGFjZSgvWyZcXD9dc3RhdGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgLnJlcGxhY2UoL1smXFw/XXNlc3Npb25fc3RhdGU9W14mXFwkXSovLCAnJyk7XG5cbiAgICAgIGhpc3RvcnkucmVwbGFjZVN0YXRlKG51bGwsIHdpbmRvdy5uYW1lLCBocmVmKTtcbiAgICB9XG5cbiAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XG4gICAgdGhpcy5zdGF0ZSA9IHVzZXJTdGF0ZTtcblxuICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xuICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XG4gICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcbiAgICAgIGNvbnN0IGVyciA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2NvZGVfZXJyb3InLCB7fSwgcGFydHMpO1xuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cblxuICAgIGlmICghbm9uY2VJblN0YXRlKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgfVxuXG4gICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMudmFsaWRhdGVOb25jZShub25jZUluU3RhdGUpO1xuICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgIH1cblxuICAgIHRoaXMuc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlKTtcblxuICAgIGlmIChjb2RlKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRUb2tlbkZyb21Db2RlKGNvZGUsIG9wdGlvbnMpLnRoZW4oXyA9PiBudWxsKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZSB0aGUgcmV0dXJuZWQgYXV0aCBjb2RlIGZyb20gdGhlIHJlZGlyZWN0IHVyaSB0aGF0IGhhcyBiZWVuIGNhbGxlZC5cbiAgICogSWYgcmVxdWlyZWQgYWxzbyBjaGVjayBoYXNoLCBhcyB3ZSBjb3VsZCB1c2UgaGFzaCBsb2NhdGlvbiBzdHJhdGVneS5cbiAgICovXG4gIHByaXZhdGUgZ2V0Q29kZVBhcnRzRnJvbVVybChxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xuICAgICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xuICAgIH1cblxuICAgIC8vIG5vcm1hbGl6ZSBxdWVyeSBzdHJpbmdcbiAgICBpZiAocXVlcnlTdHJpbmcuY2hhckF0KDApID09PSAnPycpIHtcbiAgICAgIHF1ZXJ5U3RyaW5nID0gcXVlcnlTdHJpbmcuc3Vic3RyKDEpO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdG9rZW4gdXNpbmcgYW4gaW50ZXJtZWRpYXRlIGNvZGUuIFdvcmtzIGZvciB0aGUgQXV0aG9yaXphdGlvbiBDb2RlIGZsb3cuXG4gICAqL1xuICBwcml2YXRlIGdldFRva2VuRnJvbUNvZGUoXG4gICAgY29kZTogc3RyaW5nLFxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9uc1xuICApOiBQcm9taXNlPG9iamVjdD4ge1xuICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXG4gICAgICAuc2V0KCdjb2RlJywgY29kZSlcbiAgICAgIC5zZXQoJ3JlZGlyZWN0X3VyaScsIG9wdGlvbnMuY3VzdG9tUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaSk7XG5cbiAgICBpZiAoIXRoaXMuZGlzYWJsZVBLQ0UpIHtcbiAgICAgIGxldCBwa2NpVmVyaWZpZXI7XG5cbiAgICAgIGlmIChcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgICApIHtcbiAgICAgICAgcGtjaVZlcmlmaWVyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHBrY2lWZXJpZmllciA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnUEtDSV92ZXJpZmllcicpO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXBrY2lWZXJpZmllcikge1xuICAgICAgICBjb25zb2xlLndhcm4oJ05vIFBLQ0kgdmVyaWZpZXIgZm91bmQgaW4gb2F1dGggc3RvcmFnZSEnKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NvZGVfdmVyaWZpZXInLCBwa2NpVmVyaWZpZXIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0aGlzLmZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtcyk7XG4gIH1cblxuICBwcml2YXRlIGZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtczogSHR0cFBhcmFtcyk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcbiAgICAgICd0b2tlbkVuZHBvaW50J1xuICAgICk7XG4gICAgbGV0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgKTtcblxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgIH1cblxuICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcbiAgICB9XG5cbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgIGZvciAobGV0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHRoaXMuaHR0cFxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgdGhpcy5wcm9jZXNzSWRUb2tlbihcbiAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmlkX3Rva2VuLFxuICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuXG4gICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcblxuICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKVxuICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpXG4gICAgICAgICAgICAgICAgICApO1xuXG4gICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbilcbiAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xuICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihyZWFzb24pO1xuXG4gICAgICAgICAgICAgICAgICByZWplY3QocmVhc29uKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuXG4gICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgZ2V0dGluZyB0b2tlbicsIGVycik7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgYXJlIHRva2VucyBpbiB0aGUgaGFzaCBmcmFnbWVudFxuICAgKiBhcyBhIHJlc3VsdCBvZiB0aGUgaW1wbGljaXQgZmxvdy4gVGhlc2UgdG9rZW5zIGFyZVxuICAgKiBwYXJzZWQsIHZhbGlkYXRlZCBhbmQgdXNlZCB0byBzaWduIHRoZSB1c2VyIGluIHRvIHRoZVxuICAgKiBjdXJyZW50IGNsaWVudC5cbiAgICpcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICovXG4gIHB1YmxpYyB0cnlMb2dpbkltcGxpY2l0RmxvdyhvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgICBsZXQgcGFydHM6IG9iamVjdDtcblxuICAgIGlmIChvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCkge1xuICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpO1xuICAgIH0gZWxzZSB7XG4gICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xuICAgIH1cblxuICAgIHRoaXMuZGVidWcoJ3BhcnNlZCB1cmwnLCBwYXJ0cyk7XG5cbiAgICBjb25zdCBzdGF0ZSA9IHBhcnRzWydzdGF0ZSddO1xuXG4gICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xuICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XG5cbiAgICBpZiAocGFydHNbJ2Vycm9yJ10pIHtcbiAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xuICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKG9wdGlvbnMsIHBhcnRzKTtcbiAgICAgIGNvbnN0IGVyciA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX2Vycm9yJywge30sIHBhcnRzKTtcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHBhcnRzWydhY2Nlc3NfdG9rZW4nXTtcbiAgICBjb25zdCBpZFRva2VuID0gcGFydHNbJ2lkX3Rva2VuJ107XG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gcGFydHNbJ3Nlc3Npb25fc3RhdGUnXTtcbiAgICBjb25zdCBncmFudGVkU2NvcGVzID0gcGFydHNbJ3Njb3BlJ107XG5cbiAgICBpZiAoIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICF0aGlzLm9pZGMpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcbiAgICAgICAgJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyAob3IgYm90aCkgbXVzdCBiZSB0cnVlLidcbiAgICAgICk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhY2Nlc3NUb2tlbikge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgfVxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjayAmJiAhc3RhdGUpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgIH1cbiAgICBpZiAodGhpcy5vaWRjICYmICFpZFRva2VuKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhc2Vzc2lvblN0YXRlKSB7XG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAnc2Vzc2lvbiBjaGVja3MgKFNlc3Npb24gU3RhdHVzIENoYW5nZSBOb3RpZmljYXRpb24pICcgK1xuICAgICAgICAgICd3ZXJlIGFjdGl2YXRlZCBpbiB0aGUgY29uZmlndXJhdGlvbiBidXQgdGhlIGlkX3Rva2VuICcgK1xuICAgICAgICAgICdkb2VzIG5vdCBjb250YWluIGEgc2Vzc2lvbl9zdGF0ZSBjbGFpbSdcbiAgICAgICk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFvcHRpb25zLmRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrKSB7XG4gICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XG5cbiAgICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xuICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgIGFjY2Vzc1Rva2VuLFxuICAgICAgICBudWxsLFxuICAgICAgICBwYXJ0c1snZXhwaXJlc19pbiddIHx8IHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXG4gICAgICAgIGdyYW50ZWRTY29wZXNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgaWYgKCF0aGlzLm9pZGMpIHtcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcbiAgICAgIH1cblxuICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRydWUpO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnByb2Nlc3NJZFRva2VuKGlkVG9rZW4sIGFjY2Vzc1Rva2VuKVxuICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgaWYgKG9wdGlvbnMudmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICByZXR1cm4gb3B0aW9uc1xuICAgICAgICAgICAgLnZhbGlkYXRpb25IYW5kbGVyKHtcbiAgICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxuICAgICAgICAgICAgICBpZENsYWltczogcmVzdWx0LmlkVG9rZW5DbGFpbXMsXG4gICAgICAgICAgICAgIGlkVG9rZW46IHJlc3VsdC5pZFRva2VuLFxuICAgICAgICAgICAgICBzdGF0ZTogc3RhdGVcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAudGhlbihfID0+IHJlc3VsdCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0pXG4gICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpO1xuICAgICAgICB0aGlzLnN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZSk7XG4gICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4gJiYgIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9KVxuICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pXG4gICAgICAgICk7XG4gICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xuICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihyZWFzb24pO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QocmVhc29uKTtcbiAgICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZVN0YXRlKHN0YXRlOiBzdHJpbmcpOiBbc3RyaW5nLCBzdHJpbmddIHtcbiAgICBsZXQgbm9uY2UgPSBzdGF0ZTtcbiAgICBsZXQgdXNlclN0YXRlID0gJyc7XG5cbiAgICBpZiAoc3RhdGUpIHtcbiAgICAgIGNvbnN0IGlkeCA9IHN0YXRlLmluZGV4T2YodGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvcik7XG4gICAgICBpZiAoaWR4ID4gLTEpIHtcbiAgICAgICAgbm9uY2UgPSBzdGF0ZS5zdWJzdHIoMCwgaWR4KTtcbiAgICAgICAgdXNlclN0YXRlID0gc3RhdGUuc3Vic3RyKGlkeCArIHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IubGVuZ3RoKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIFtub25jZSwgdXNlclN0YXRlXTtcbiAgfVxuXG4gIHByb3RlY3RlZCB2YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZTogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgbGV0IHNhdmVkTm9uY2U7XG5cbiAgICBpZiAoXG4gICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxuICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgKSB7XG4gICAgICBzYXZlZE5vbmNlID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHNhdmVkTm9uY2UgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG4gICAgfVxuXG4gICAgaWYgKHNhdmVkTm9uY2UgIT09IG5vbmNlSW5TdGF0ZSkge1xuICAgICAgY29uc3QgZXJyID0gJ1ZhbGlkYXRpbmcgYWNjZXNzX3Rva2VuIGZhaWxlZCwgd3Jvbmcgc3RhdGUvbm9uY2UuJztcbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyLCBzYXZlZE5vbmNlLCBub25jZUluU3RhdGUpO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzdG9yZUlkVG9rZW4oaWRUb2tlbjogUGFyc2VkSWRUb2tlbik6IHZvaWQge1xuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW4nLCBpZFRva2VuLmlkVG9rZW4pO1xuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIGlkVG9rZW4uaWRUb2tlbkNsYWltc0pzb24pO1xuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcsICcnICsgaWRUb2tlbi5pZFRva2VuRXhwaXJlc0F0KTtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcsICcnICsgRGF0ZS5ub3coKSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlOiBzdHJpbmcpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnLCBzZXNzaW9uU3RhdGUpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGdldFNlc3Npb25TdGF0ZSgpOiBzdHJpbmcge1xuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBoYW5kbGVMb2dpbkVycm9yKG9wdGlvbnM6IExvZ2luT3B0aW9ucywgcGFydHM6IG9iamVjdCk6IHZvaWQge1xuICAgIGlmIChvcHRpb25zLm9uTG9naW5FcnJvcikge1xuICAgICAgb3B0aW9ucy5vbkxvZ2luRXJyb3IocGFydHMpO1xuICAgIH1cbiAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIEBpZ25vcmVcbiAgICovXG4gIHB1YmxpYyBwcm9jZXNzSWRUb2tlbihcbiAgICBpZFRva2VuOiBzdHJpbmcsXG4gICAgYWNjZXNzVG9rZW46IHN0cmluZyxcbiAgICBza2lwTm9uY2VDaGVjayA9IGZhbHNlXG4gICk6IFByb21pc2U8UGFyc2VkSWRUb2tlbj4ge1xuICAgIGNvbnN0IHRva2VuUGFydHMgPSBpZFRva2VuLnNwbGl0KCcuJyk7XG4gICAgY29uc3QgaGVhZGVyQmFzZTY0ID0gdGhpcy5wYWRCYXNlNjQodG9rZW5QYXJ0c1swXSk7XG4gICAgY29uc3QgaGVhZGVySnNvbiA9IGI2NERlY29kZVVuaWNvZGUoaGVhZGVyQmFzZTY0KTtcbiAgICBjb25zdCBoZWFkZXIgPSBKU09OLnBhcnNlKGhlYWRlckpzb24pO1xuICAgIGNvbnN0IGNsYWltc0Jhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMV0pO1xuICAgIGNvbnN0IGNsYWltc0pzb24gPSBiNjREZWNvZGVVbmljb2RlKGNsYWltc0Jhc2U2NCk7XG4gICAgY29uc3QgY2xhaW1zID0gSlNPTi5wYXJzZShjbGFpbXNKc29uKTtcblxuICAgIGxldCBzYXZlZE5vbmNlO1xuICAgIGlmIChcbiAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcbiAgICApIHtcbiAgICAgIHNhdmVkTm9uY2UgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcbiAgICB9XG5cbiAgICBpZiAoQXJyYXkuaXNBcnJheShjbGFpbXMuYXVkKSkge1xuICAgICAgaWYgKGNsYWltcy5hdWQuZXZlcnkodiA9PiB2ICE9PSB0aGlzLmNsaWVudElkKSkge1xuICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXVkaWVuY2U6ICcgKyBjbGFpbXMuYXVkLmpvaW4oJywnKTtcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKGNsYWltcy5hdWQgIT09IHRoaXMuY2xpZW50SWQpIHtcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZDtcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoIWNsYWltcy5zdWIpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdObyBzdWIgY2xhaW0gaW4gaWRfdG9rZW4nO1xuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgLyogRm9yIG5vdywgd2Ugb25seSBjaGVjayB3aGV0aGVyIHRoZSBzdWIgYWdhaW5zdFxuICAgICAqIHNpbGVudFJlZnJlc2hTdWJqZWN0IHdoZW4gc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgb25cbiAgICAgKiBXZSB3aWxsIHJlY29uc2lkZXIgaW4gYSBsYXRlciB2ZXJzaW9uIHRvIGRvIHRoaXNcbiAgICAgKiBpbiBldmVyeSBvdGhlciBjYXNlIHRvby5cbiAgICAgKi9cbiAgICBpZiAoXG4gICAgICB0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ICYmXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ICE9PSBjbGFpbXNbJ3N1YiddXG4gICAgKSB7XG4gICAgICBjb25zdCBlcnIgPVxuICAgICAgICAnQWZ0ZXIgcmVmcmVzaGluZywgd2UgZ290IGFuIGlkX3Rva2VuIGZvciBhbm90aGVyIHVzZXIgKHN1YikuICcgK1xuICAgICAgICBgRXhwZWN0ZWQgc3ViOiAke3RoaXMuc2lsZW50UmVmcmVzaFN1YmplY3R9LCByZWNlaXZlZCBzdWI6ICR7Y2xhaW1zWydzdWInXX1gO1xuXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBpZiAoIWNsYWltcy5pYXQpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdObyBpYXQgY2xhaW0gaW4gaWRfdG9rZW4nO1xuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgaWYgKCF0aGlzLnNraXBJc3N1ZXJDaGVjayAmJiBjbGFpbXMuaXNzICE9PSB0aGlzLmlzc3Vlcikge1xuICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGlzc3VlcjogJyArIGNsYWltcy5pc3M7XG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBpZiAoIXNraXBOb25jZUNoZWNrICYmIGNsYWltcy5ub25jZSAhPT0gc2F2ZWROb25jZSkge1xuICAgICAgY29uc3QgZXJyID0gJ1dyb25nIG5vbmNlOiAnICsgY2xhaW1zLm5vbmNlO1xuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuICAgIC8vIGF0X2hhc2ggaXMgbm90IGFwcGxpY2FibGUgdG8gYXV0aG9yaXphdGlvbiBjb2RlIGZsb3dcbiAgICAvLyBhZGRyZXNzaW5nIGh0dHBzOi8vZ2l0aHViLmNvbS9tYW5mcmVkc3RleWVyL2FuZ3VsYXItb2F1dGgyLW9pZGMvaXNzdWVzLzY2MVxuICAgIC8vIGkuZS4gQmFzZWQgb24gc3BlYyB0aGUgYXRfaGFzaCBjaGVjayBpcyBvbmx5IHRydWUgZm9yIGltcGxpY2l0IGNvZGUgZmxvdyBvbiBQaW5nIEZlZGVyYXRlXG4gICAgLy8gaHR0cHM6Ly93d3cucGluZ2lkZW50aXR5LmNvbS9kZXZlbG9wZXIvZW4vcmVzb3VyY2VzL29wZW5pZC1jb25uZWN0LWRldmVsb3BlcnMtZ3VpZGUuaHRtbFxuICAgIGlmICh0aGlzLmhhc093blByb3BlcnR5KCdyZXNwb25zZVR5cGUnKSAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICB0aGlzLmRpc2FibGVBdEhhc2hDaGVjayA9IHRydWU7XG4gICAgfVxuICAgIGlmIChcbiAgICAgICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJlxuICAgICAgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiZcbiAgICAgICFjbGFpbXNbJ2F0X2hhc2gnXVxuICAgICkge1xuICAgICAgY29uc3QgZXJyID0gJ0FuIGF0X2hhc2ggaXMgbmVlZGVkISc7XG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgIGNvbnN0IGlzc3VlZEF0TVNlYyA9IGNsYWltcy5pYXQgKiAxMDAwO1xuICAgIGNvbnN0IGV4cGlyZXNBdE1TZWMgPSBjbGFpbXMuZXhwICogMTAwMDtcbiAgICBjb25zdCBjbG9ja1NrZXdJbk1TZWMgPSAodGhpcy5jbG9ja1NrZXdJblNlYyB8fCA2MDApICogMTAwMDtcblxuICAgIGlmIChcbiAgICAgIGlzc3VlZEF0TVNlYyAtIGNsb2NrU2tld0luTVNlYyA+PSBub3cgfHxcbiAgICAgIGV4cGlyZXNBdE1TZWMgKyBjbG9ja1NrZXdJbk1TZWMgPD0gbm93XG4gICAgKSB7XG4gICAgICBjb25zdCBlcnIgPSAnVG9rZW4gaGFzIGV4cGlyZWQnO1xuICAgICAgY29uc29sZS5lcnJvcihlcnIpO1xuICAgICAgY29uc29sZS5lcnJvcih7XG4gICAgICAgIG5vdzogbm93LFxuICAgICAgICBpc3N1ZWRBdE1TZWM6IGlzc3VlZEF0TVNlYyxcbiAgICAgICAgZXhwaXJlc0F0TVNlYzogZXhwaXJlc0F0TVNlY1xuICAgICAgfSk7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBjb25zdCB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zID0ge1xuICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxuICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgIGp3a3M6IHRoaXMuandrcyxcbiAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcbiAgICAgIGxvYWRLZXlzOiAoKSA9PiB0aGlzLmxvYWRKd2tzKClcbiAgICB9O1xuXG4gICAgaWYgKHRoaXMuZGlzYWJsZUF0SGFzaENoZWNrKSB7XG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xuICAgICAgICBjb25zdCByZXN1bHQ6IFBhcnNlZElkVG9rZW4gPSB7XG4gICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgaWRUb2tlbkNsYWltc0pzb246IGNsYWltc0pzb24sXG4gICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxuICAgICAgICAgIGlkVG9rZW5FeHBpcmVzQXQ6IGV4cGlyZXNBdE1TZWNcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLmNoZWNrQXRIYXNoKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oYXRIYXNoVmFsaWQgPT4ge1xuICAgICAgaWYgKCF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJiB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYXRIYXNoVmFsaWQpIHtcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xuICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xuICAgICAgICBjb25zdCBhdEhhc2hDaGVja0VuYWJsZWQgPSAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2s7XG4gICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcbiAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxuICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcbiAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXG4gICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xuICAgICAgICB9O1xuICAgICAgICBpZiAoYXRIYXNoQ2hlY2tFbmFibGVkKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcykudGhlbihhdEhhc2hWYWxpZCA9PiB7XG4gICAgICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWF0SGFzaFZhbGlkKSB7XG4gICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdF9oYXNoJztcbiAgICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgcmVjZWl2ZWQgY2xhaW1zIGFib3V0IHRoZSB1c2VyLlxuICAgKi9cbiAgcHVibGljIGdldElkZW50aXR5Q2xhaW1zKCk6IG9iamVjdCB7XG4gICAgY29uc3QgY2xhaW1zID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgaWYgKCFjbGFpbXMpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gSlNPTi5wYXJzZShjbGFpbXMpO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIGdyYW50ZWQgc2NvcGVzIGZyb20gdGhlIHNlcnZlci5cbiAgICovXG4gIHB1YmxpYyBnZXRHcmFudGVkU2NvcGVzKCk6IG9iamVjdCB7XG4gICAgY29uc3Qgc2NvcGVzID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdncmFudGVkX3Njb3BlcycpO1xuICAgIGlmICghc2NvcGVzKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIEpTT04ucGFyc2Uoc2NvcGVzKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGlkX3Rva2VuLlxuICAgKi9cbiAgcHVibGljIGdldElkVG9rZW4oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW4nKSA6IG51bGw7XG4gIH1cblxuICBwcm90ZWN0ZWQgcGFkQmFzZTY0KGJhc2U2NGRhdGEpOiBzdHJpbmcge1xuICAgIHdoaWxlIChiYXNlNjRkYXRhLmxlbmd0aCAlIDQgIT09IDApIHtcbiAgICAgIGJhc2U2NGRhdGEgKz0gJz0nO1xuICAgIH1cbiAgICByZXR1cm4gYmFzZTY0ZGF0YTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGFjY2Vzc190b2tlbi5cbiAgICovXG4gIHB1YmxpYyBnZXRBY2Nlc3NUb2tlbigpOiBzdHJpbmcge1xuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW4nKSA6IG51bGw7XG4gIH1cblxuICBwdWJsaWMgZ2V0UmVmcmVzaFRva2VuKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKSA6IG51bGw7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBhY2Nlc3NfdG9rZW5cbiAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAqL1xuICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSwgMTApO1xuICB9XG5cbiAgcHJvdGVjdGVkIGdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBnZXRJZFRva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgaWRfdG9rZW5cbiAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAqL1xuICBwdWJsaWMgZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTogbnVtYmVyIHtcbiAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG5cbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JyksIDEwKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDaGVja2VzLCB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgYWNjZXNzX3Rva2VuLlxuICAgKi9cbiAgcHVibGljIGhhc1ZhbGlkQWNjZXNzVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgaWYgKHRoaXMuZ2V0QWNjZXNzVG9rZW4oKSkge1xuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgaXMgYSB2YWxpZCBpZF90b2tlbi5cbiAgICovXG4gIHB1YmxpYyBoYXNWYWxpZElkVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgaWYgKHRoaXMuZ2V0SWRUb2tlbigpKSB7XG4gICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZSBhIHNhdmVkIGN1c3RvbSBwcm9wZXJ0eSBvZiB0aGUgVG9rZW5SZXBvbnNlIG9iamVjdC4gT25seSBpZiBwcmVkZWZpbmVkIGluIGF1dGhjb25maWcuXG4gICAqL1xuICBwdWJsaWMgZ2V0Q3VzdG9tVG9rZW5SZXNwb25zZVByb3BlcnR5KHJlcXVlc3RlZFByb3BlcnR5OiBzdHJpbmcpOiBhbnkge1xuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlICYmXG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMgJiZcbiAgICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5pbmRleE9mKHJlcXVlc3RlZFByb3BlcnR5KSA+PSAwICYmXG4gICAgICB0aGlzLl9zdG9yYWdlLmdldEl0ZW0ocmVxdWVzdGVkUHJvcGVydHkpICE9PSBudWxsXG4gICAgICA/IEpTT04ucGFyc2UodGhpcy5fc3RvcmFnZS5nZXRJdGVtKHJlcXVlc3RlZFByb3BlcnR5KSlcbiAgICAgIDogbnVsbDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBhdXRoLWhlYWRlciB0aGF0IGNhbiBiZSB1c2VkXG4gICAqIHRvIHRyYW5zbWl0IHRoZSBhY2Nlc3NfdG9rZW4gdG8gYSBzZXJ2aWNlXG4gICAqL1xuICBwdWJsaWMgYXV0aG9yaXphdGlvbkhlYWRlcigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlcyBhbGwgdG9rZW5zIGFuZCBsb2dzIHRoZSB1c2VyIG91dC5cbiAgICogSWYgYSBsb2dvdXQgdXJsIGlzIGNvbmZpZ3VyZWQsIHRoZSB1c2VyIGlzXG4gICAqIHJlZGlyZWN0ZWQgdG8gaXQgd2l0aCBvcHRpb25hbCBzdGF0ZSBwYXJhbWV0ZXIuXG4gICAqIEBwYXJhbSBub1JlZGlyZWN0VG9Mb2dvdXRVcmxcbiAgICogQHBhcmFtIHN0YXRlXG4gICAqL1xuICBwdWJsaWMgbG9nT3V0KG5vUmVkaXJlY3RUb0xvZ291dFVybCA9IGZhbHNlLCBzdGF0ZSA9ICcnKTogdm9pZCB7XG4gICAgY29uc3QgaWRfdG9rZW4gPSB0aGlzLmdldElkVG9rZW4oKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbicpO1xuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW4nKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3JlZnJlc2hfdG9rZW4nKTtcblxuICAgIGlmICh0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ25vbmNlJyk7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnUEtDSV92ZXJpZmllcicpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ25vbmNlJyk7XG4gICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcbiAgICB9XG5cbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2V4cGlyZXNfYXQnKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpO1xuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcpO1xuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcbiAgICBpZiAodGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzKSB7XG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMuZm9yRWFjaChjdXN0b21QYXJhbSA9PlxuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oY3VzdG9tUGFyYW0pXG4gICAgICApO1xuICAgIH1cbiAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gbnVsbDtcblxuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnbG9nb3V0JykpO1xuXG4gICAgaWYgKCF0aGlzLmxvZ291dFVybCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAobm9SZWRpcmVjdFRvTG9nb3V0VXJsKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKCFpZF90b2tlbiAmJiAhdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBsZXQgbG9nb3V0VXJsOiBzdHJpbmc7XG5cbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ291dFVybCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgXCJsb2dvdXRVcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIEZvciBiYWNrd2FyZCBjb21wYXRpYmlsaXR5XG4gICAgaWYgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJ3t7JykgPiAtMSkge1xuICAgICAgbG9nb3V0VXJsID0gdGhpcy5sb2dvdXRVcmxcbiAgICAgICAgLnJlcGxhY2UoL1xce1xce2lkX3Rva2VuXFx9XFx9LywgaWRfdG9rZW4pXG4gICAgICAgIC5yZXBsYWNlKC9cXHtcXHtjbGllbnRfaWRcXH1cXH0vLCB0aGlzLmNsaWVudElkKTtcbiAgICB9IGVsc2Uge1xuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKCk7XG5cbiAgICAgIGlmIChpZF90b2tlbikge1xuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdpZF90b2tlbl9oaW50JywgaWRfdG9rZW4pO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBwb3N0TG9nb3V0VXJsID0gdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgIGlmIChwb3N0TG9nb3V0VXJsKSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ3Bvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaScsIHBvc3RMb2dvdXRVcmwpO1xuXG4gICAgICAgIGlmIChzdGF0ZSkge1xuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ3N0YXRlJywgc3RhdGUpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGxvZ291dFVybCA9XG4gICAgICAgIHRoaXMubG9nb3V0VXJsICtcbiAgICAgICAgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nKSArXG4gICAgICAgIHBhcmFtcy50b1N0cmluZygpO1xuICAgIH1cbiAgICB0aGlzLmNvbmZpZy5vcGVuVXJpKGxvZ291dFVybCk7XG4gIH1cblxuICAvKipcbiAgICogQGlnbm9yZVxuICAgKi9cbiAgcHVibGljIGNyZWF0ZUFuZFNhdmVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuICAgIHJldHVybiB0aGlzLmNyZWF0ZU5vbmNlKCkudGhlbihmdW5jdGlvbihub25jZTogYW55KSB7XG4gICAgICAvLyBVc2UgbG9jYWxTdG9yYWdlIGZvciBub25jZSBpZiBwb3NzaWJsZVxuICAgICAgLy8gbG9jYWxTdG9yYWdlIGlzIHRoZSBvbmx5IHN0b3JhZ2Ugd2hvIHN1cnZpdmVzIGFcbiAgICAgIC8vIHJlZGlyZWN0IGluIEFMTCBicm93c2VycyAoYWxzbyBJRSlcbiAgICAgIC8vIE90aGVyd2llc2Ugd2UnZCBmb3JjZSB0ZWFtcyB3aG8gaGF2ZSB0byBzdXBwb3J0XG4gICAgICAvLyBJRSBpbnRvIHVzaW5nIGxvY2FsU3RvcmFnZSBmb3IgZXZlcnl0aGluZ1xuICAgICAgaWYgKFxuICAgICAgICB0aGF0LnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxuICAgICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcbiAgICAgICkge1xuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLCBub25jZSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGF0Ll9zdG9yYWdlLnNldEl0ZW0oJ25vbmNlJywgbm9uY2UpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIG5vbmNlO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIEBpZ25vcmVcbiAgICovXG4gIHB1YmxpYyBuZ09uRGVzdHJveSgpOiB2b2lkIHtcbiAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcblxuICAgIHRoaXMucmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcbiAgICBjb25zdCBzaWxlbnRSZWZyZXNoRnJhbWUgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoSUZyYW1lTmFtZVxuICAgICk7XG4gICAgaWYgKHNpbGVudFJlZnJlc2hGcmFtZSkge1xuICAgICAgc2lsZW50UmVmcmVzaEZyYW1lLnJlbW92ZSgpO1xuICAgIH1cblxuICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG4gICAgY29uc3Qgc2Vzc2lvbkNoZWNrRnJhbWUgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lXG4gICAgKTtcbiAgICBpZiAoc2Vzc2lvbkNoZWNrRnJhbWUpIHtcbiAgICAgIHNlc3Npb25DaGVja0ZyYW1lLnJlbW92ZSgpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBjcmVhdGVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcbiAgICAgIGlmICh0aGlzLnJuZ1VybCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgJ2NyZWF0ZU5vbmNlIHdpdGggcm5nLXdlYi1hcGkgaGFzIG5vdCBiZWVuIGltcGxlbWVudGVkIHNvIGZhcidcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgLypcbiAgICAgICAqIFRoaXMgYWxwaGFiZXQgaXMgZnJvbTpcbiAgICAgICAqIGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM3NjM2I3NlY3Rpb24tNC4xXG4gICAgICAgKlxuICAgICAgICogW0EtWl0gLyBbYS16XSAvIFswLTldIC8gXCItXCIgLyBcIi5cIiAvIFwiX1wiIC8gXCJ+XCJcbiAgICAgICAqL1xuICAgICAgY29uc3QgdW5yZXNlcnZlZCA9XG4gICAgICAgICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OS0uX34nO1xuICAgICAgbGV0IHNpemUgPSA0NTtcbiAgICAgIGxldCBpZCA9ICcnO1xuXG4gICAgICBjb25zdCBjcnlwdG8gPVxuICAgICAgICB0eXBlb2Ygc2VsZiA9PT0gJ3VuZGVmaW5lZCcgPyBudWxsIDogc2VsZi5jcnlwdG8gfHwgc2VsZlsnbXNDcnlwdG8nXTtcbiAgICAgIGlmIChjcnlwdG8pIHtcbiAgICAgICAgbGV0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoc2l6ZSk7XG4gICAgICAgIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMoYnl0ZXMpO1xuXG4gICAgICAgIC8vIE5lZWRlZCBmb3IgSUVcbiAgICAgICAgaWYgKCFieXRlcy5tYXApIHtcbiAgICAgICAgICAoYnl0ZXMgYXMgYW55KS5tYXAgPSBBcnJheS5wcm90b3R5cGUubWFwO1xuICAgICAgICB9XG5cbiAgICAgICAgYnl0ZXMgPSBieXRlcy5tYXAoeCA9PiB1bnJlc2VydmVkLmNoYXJDb2RlQXQoeCAlIHVucmVzZXJ2ZWQubGVuZ3RoKSk7XG4gICAgICAgIGlkID0gU3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShudWxsLCBieXRlcyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xuICAgICAgICAgIGlkICs9IHVucmVzZXJ2ZWRbKE1hdGgucmFuZG9tKCkgKiB1bnJlc2VydmVkLmxlbmd0aCkgfCAwXTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICByZXNvbHZlKGJhc2U2NFVybEVuY29kZShpZCkpO1xuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGFzeW5jIGNoZWNrQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGlmICghdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgYXRfaGFzaC4nXG4gICAgICApO1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVBdEhhc2gocGFyYW1zKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBjaGVja1NpZ25hdHVyZShwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT4ge1xuICAgIGlmICghdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgc2lnbmF0dXJlLidcbiAgICAgICk7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKG51bGwpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyLnZhbGlkYXRlU2lnbmF0dXJlKHBhcmFtcyk7XG4gIH1cblxuICAvKipcbiAgICogU3RhcnQgdGhlIGltcGxpY2l0IGZsb3cgb3IgdGhlIGNvZGUgZmxvdyxcbiAgICogZGVwZW5kaW5nIG9uIHlvdXIgY29uZmlndXJhdGlvbi5cbiAgICovXG4gIHB1YmxpYyBpbml0TG9naW5GbG93KGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xuICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICByZXR1cm4gdGhpcy5pbml0Q29kZUZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdGhpcy5pbml0SW1wbGljaXRGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogU3RhcnRzIHRoZSBhdXRob3JpemF0aW9uIGNvZGUgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cbiAgICogdGhlIGF1dGggc2VydmVycyBsb2dpbiB1cmwuXG4gICAqL1xuICBwdWJsaWMgaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xuICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xuICAgICAgdGhpcy5pbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuZXZlbnRzXG4gICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwibG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXG4gICAgICApO1xuICAgIH1cblxuICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCAnJywgbnVsbCwgZmFsc2UsIHBhcmFtcylcbiAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0QXV0aG9yaXphdGlvbkNvZGVGbG93Jyk7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpOiBQcm9taXNlPFxuICAgIFtzdHJpbmcsIHN0cmluZ11cbiAgPiB7XG4gICAgaWYgKCF0aGlzLmNyeXB0bykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAnUEtDRSBzdXBwb3J0IGZvciBjb2RlIGZsb3cgbmVlZHMgYSBDcnlwdG9IYW5kZXIuIERpZCB5b3UgaW1wb3J0IHRoZSBPQXV0aE1vZHVsZSB1c2luZyBmb3JSb290KCkgPydcbiAgICAgICk7XG4gICAgfVxuXG4gICAgY29uc3QgdmVyaWZpZXIgPSBhd2FpdCB0aGlzLmNyZWF0ZU5vbmNlKCk7XG4gICAgY29uc3QgY2hhbGxlbmdlUmF3ID0gYXdhaXQgdGhpcy5jcnlwdG8uY2FsY0hhc2godmVyaWZpZXIsICdzaGEtMjU2Jyk7XG4gICAgY29uc3QgY2hhbGxlbmdlID0gYmFzZTY0VXJsRW5jb2RlKGNoYWxsZW5nZVJhdyk7XG5cbiAgICByZXR1cm4gW2NoYWxsZW5nZSwgdmVyaWZpZXJdO1xuICB9XG5cbiAgcHJpdmF0ZSBleHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnMoXG4gICAgdG9rZW5SZXNwb25zZTogVG9rZW5SZXNwb25zZVxuICApOiBNYXA8c3RyaW5nLCBzdHJpbmc+IHtcbiAgICBsZXQgZm91bmRQYXJhbWV0ZXJzOiBNYXA8c3RyaW5nLCBzdHJpbmc+ID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcbiAgICBpZiAoIXRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycykge1xuICAgICAgcmV0dXJuIGZvdW5kUGFyYW1ldGVycztcbiAgICB9XG4gICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmZvckVhY2goKHJlY29nbml6ZWRQYXJhbWV0ZXI6IHN0cmluZykgPT4ge1xuICAgICAgaWYgKHRva2VuUmVzcG9uc2VbcmVjb2duaXplZFBhcmFtZXRlcl0pIHtcbiAgICAgICAgZm91bmRQYXJhbWV0ZXJzLnNldChcbiAgICAgICAgICByZWNvZ25pemVkUGFyYW1ldGVyLFxuICAgICAgICAgIEpTT04uc3RyaW5naWZ5KHRva2VuUmVzcG9uc2VbcmVjb2duaXplZFBhcmFtZXRlcl0pXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgcmV0dXJuIGZvdW5kUGFyYW1ldGVycztcbiAgfVxufVxuIl19