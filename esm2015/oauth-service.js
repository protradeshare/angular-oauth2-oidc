import { __awaiter, __decorate, __metadata, __param } from "tslib";
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
let OAuthService = class OAuthService extends AuthConfig {
    constructor(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto, document) {
        var _a, _b, _c, _d;
        super();
        this.ngZone = ngZone;
        this.http = http;
        this.config = config;
        this.urlHelper = urlHelper;
        this.logger = logger;
        this.crypto = crypto;
        this.document = document;
        /**
         * @internal
         * Deprecated:  use property events instead
         */
        this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        this.state = '';
        this.eventsSubject = new Subject();
        this.discoveryDocumentLoadedSubject = new Subject();
        this.grantTypesSupported = [];
        this.inImplicitFlow = false;
        this.saveNoncesInLocalStorage = false;
        this.debug('angular-oauth2-oidc v8-beta');
        this.discoveryDocumentLoaded$ = this.discoveryDocumentLoadedSubject.asObservable();
        this.events = this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            this.configure(config);
        }
        try {
            if (storage) {
                this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).' +
                'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        // in IE, sessionStorage does not always survive a redirect
        if (typeof window !== 'undefined' &&
            typeof window['localStorage'] !== 'undefined') {
            const ua = (_b = (_a = window) === null || _a === void 0 ? void 0 : _a.navigator) === null || _b === void 0 ? void 0 : _b.userAgent;
            const msie = ((_c = ua) === null || _c === void 0 ? void 0 : _c.includes('MSIE ')) || ((_d = ua) === null || _d === void 0 ? void 0 : _d.includes('Trident'));
            if (msie) {
                this.saveNoncesInLocalStorage = true;
            }
        }
        this.setupRefreshTimer();
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    configure(config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign({}, new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    }
    configChanged() {
        this.setupRefreshTimer();
    }
    restartSessionChecksIfStillLoggedIn() {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    }
    restartRefreshTimerIfStillLoggedIn() {
        this.setupExpirationTimers();
    }
    setupSessionCheck() {
        this.events.pipe(filter(e => e.type === 'token_received')).subscribe(e => {
            this.initSessionCheck();
        });
    }
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    setupAutomaticSilentRefresh(params = {}, listenTo, noPrompt = true) {
        let shouldRunSilentRefresh = true;
        this.events
            .pipe(tap(e => {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        }), filter(e => e.type === 'token_expires'), debounceTime(1000))
            .subscribe(e => {
            const event = e;
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) &&
                shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                this.refreshInternal(params, noPrompt).catch(_ => {
                    this.debug('Automatic silent refresh did not work');
                });
            }
        });
        this.restartRefreshTimerIfStillLoggedIn();
    }
    refreshInternal(params, noPrompt) {
        if (!this.useSilentRefresh && this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndTryLogin(options = null) {
        return this.loadDiscoveryDocument().then(doc => {
            return this.tryLogin(options);
        });
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initLoginFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndLogin(options = null) {
        if (!options) {
            options = { state: '' };
        }
        return this.loadDiscoveryDocumentAndTryLogin(options).then(_ => {
            if (!this.hasValidIdToken() || !this.hasValidAccessToken()) {
                if (this.responseType === 'code') {
                    this.initCodeFlow();
                }
                else {
                    this.initImplicitFlow();
                }
                return false;
            }
            else {
                return true;
            }
        });
    }
    debug(...args) {
        if (this.showDebugInformation) {
            this.logger.debug.apply(this.logger, args);
        }
    }
    validateUrlFromDiscoveryDocument(url) {
        const errors = [];
        const httpsCheck = this.validateUrlForHttps(url);
        const issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    }
    validateUrlForHttps(url) {
        if (!url) {
            return true;
        }
        const lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    }
    assertUrlNotNullAndCorrectProtocol(url, description) {
        if (!url) {
            throw new Error(`'${description}' should not be null`);
        }
        if (!this.validateUrlForHttps(url)) {
            throw new Error(`'${description}' must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).`);
        }
    }
    validateUrlAgainstIssuer(url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    }
    setupRefreshTimer() {
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
            .pipe(filter(e => e.type === 'token_received'))
            .subscribe(_ => {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        });
    }
    setupExpirationTimers() {
        if (this.hasValidAccessToken()) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            this.setupIdTokenTimer();
        }
    }
    setupAccessTokenTimer() {
        const expiration = this.getAccessTokenExpiration();
        const storedAt = this.getAccessTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    setupIdTokenTimer() {
        const expiration = this.getIdTokenExpiration();
        const storedAt = this.getIdTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    /**
     * Stops timers for automatic refresh.
     * To restart it, call setupAutomaticSilentRefresh again.
     */
    stopAutomaticRefresh() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    }
    clearAccessTokenTimer() {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    }
    clearIdTokenTimer() {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    }
    calcTimeout(storedAt, expiration) {
        const now = Date.now();
        const delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    }
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
    setStorage(storage) {
        this._storage = storage;
        this.configChanged();
    }
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    loadDiscoveryDocument(fullUrl = null) {
        return new Promise((resolve, reject) => {
            if (!fullUrl) {
                fullUrl = this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!this.validateUrlForHttps(fullUrl)) {
                reject("issuer  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
                return;
            }
            this.http.get(fullUrl).subscribe(doc => {
                if (!this.validateDiscoveryDocument(doc)) {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                this.loginUrl = doc.authorization_endpoint;
                this.logoutUrl = doc.end_session_endpoint || this.logoutUrl;
                this.grantTypesSupported = doc.grant_types_supported;
                this.issuer = doc.issuer;
                this.tokenEndpoint = doc.token_endpoint;
                this.userinfoEndpoint =
                    doc.userinfo_endpoint || this.userinfoEndpoint;
                this.jwksUri = doc.jwks_uri;
                this.sessionCheckIFrameUrl =
                    doc.check_session_iframe || this.sessionCheckIFrameUrl;
                this.discoveryDocumentLoaded = true;
                this.discoveryDocumentLoadedSubject.next(doc);
                if (this.sessionChecksEnabled) {
                    this.restartSessionChecksIfStillLoggedIn();
                }
                this.loadJwks()
                    .then(jwks => {
                    const result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    const event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    this.eventsSubject.next(event);
                    resolve(event);
                    return;
                })
                    .catch(err => {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                });
            }, err => {
                this.logger.error('error loading discovery document', err);
                this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            });
        });
    }
    loadJwks() {
        return new Promise((resolve, reject) => {
            if (this.jwksUri) {
                this.http.get(this.jwksUri).subscribe(jwks => {
                    this.jwks = jwks;
                    this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }, err => {
                    this.logger.error('error loading jwks', err);
                    this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        });
    }
    validateDiscoveryDocument(doc) {
        let errors;
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
    }
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
    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName, password, headers = new HttpHeaders()) {
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then(() => this.loadUserProfile());
    }
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
    fetchTokenUsingExternalTokenAndLoadUserProfile(provider, external_token, headers = new HttpHeaders()) {
        return this.fetchTokenUsingUsingExternalToken(provider, external_token, headers).then(() => this.loadUserProfile());
    }
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    loadUserProfile() {
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error("userinfoEndpoint must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        return new Promise((resolve, reject) => {
            const headers = new HttpHeaders().set('Authorization', 'Bearer ' + this.getAccessToken());
            this.http
                .get(this.userinfoEndpoint, { headers })
                .subscribe(info => {
                this.debug('userinfo received', info);
                const existingClaims = this.getIdentityClaims() || {};
                if (!this.skipSubjectCheck) {
                    if (this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        const err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }, err => {
                this.logger.error('error loading user info', err);
                this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            });
        });
    }
    /**
     * Uses provider and external token for an access_token.
     * @param provider
     * @param external_token
     * @param headers Optional additional http-headers.
     */
    fetchTokenUsingUsingExternalToken(provider, external_token, headers = new HttpHeaders()) {
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((resolve, reject) => {
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'external')
                .set('scope', this.scope)
                .set('provider', provider)
                .set('external_token', external_token);
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error performing external token flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    }
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    fetchTokenUsingPasswordFlow(userName, password, headers = new HttpHeaders()) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', this.scope)
                .set('username', userName)
                .set('password', password);
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    }
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    refreshToken() {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            let params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('scope', this.scope)
                .set('refresh_token', this._storage.getItem('refresh_token'));
            let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .pipe(switchMap(tokenResponse => {
                if (tokenResponse.id_token) {
                    return from(this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true)).pipe(tap(result => this.storeIdToken(result)), map(_ => tokenResponse));
                }
                else {
                    return of(tokenResponse);
                }
            }))
                .subscribe(tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error refreshing token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    removeSilentRefreshEventListener() {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    }
    setupSilentRefreshEventListener() {
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = (e) => {
            const message = this.processMessageEventMessage(e);
            this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                customRedirectUri: this.silentRefreshRedirectUri || this.redirectUri
            }).catch(err => this.debug('tryLogin during silent refresh failed', err));
        };
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    }
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    silentRefresh(params = {}, noPrompt = true) {
        const claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        if (typeof document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        const existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        const iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        const redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then(url => {
            iframe.setAttribute('src', url);
            if (!this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        });
        const errors = this.events.pipe(filter(e => e instanceof OAuthErrorEvent), first());
        const success = this.events.pipe(filter(e => e.type === 'token_received'), first());
        const timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(map(e => {
            if (e instanceof OAuthErrorEvent) {
                if (e.type === 'silent_refresh_timeout') {
                    this.eventsSubject.next(e);
                }
                else {
                    e = new OAuthErrorEvent('silent_refresh_error', e);
                    this.eventsSubject.next(e);
                }
                throw e;
            }
            else if (e.type === 'token_received') {
                e = new OAuthSuccessEvent('silently_refreshed');
                this.eventsSubject.next(e);
            }
            return e;
        }))
            .toPromise();
    }
    /**
     * This method exists for backwards compatibility.
     * {@link OAuthService#initLoginFlowInPopup} handles both code
     * and implicit flows.
     */
    initImplicitFlowInPopup(options) {
        return this.initLoginFlowInPopup(options);
    }
    initLoginFlowInPopup(options) {
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then(url => {
            return new Promise((resolve, reject) => {
                /**
                 * Error handling section
                 */
                const checkForPopupClosedInterval = 500;
                let windowRef = window.open(url, '_blank', this.calculatePopupFeatures(options));
                let checkForPopupClosedTimer;
                const checkForPopupClosed = () => {
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
                const cleanup = () => {
                    window.clearInterval(checkForPopupClosedTimer);
                    window.removeEventListener('message', listener);
                    if (windowRef !== null) {
                        windowRef.close();
                    }
                    windowRef = null;
                };
                const listener = (e) => {
                    const message = this.processMessageEventMessage(e);
                    if (message && message !== null) {
                        this.tryLogin({
                            customHashFragment: message,
                            preventClearHashAfterLogin: true,
                            customRedirectUri: this.silentRefreshRedirectUri
                        }).then(() => {
                            cleanup();
                            resolve();
                        }, err => {
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
    }
    calculatePopupFeatures(options) {
        // Specify an static height and width and calculate centered position
        const height = options.height || 470;
        const width = options.width || 500;
        const left = window.screenLeft + (window.outerWidth - width) / 2;
        const top = window.screenTop + (window.outerHeight - height) / 2;
        return `location=no,toolbar=no,width=${width},height=${height},top=${top},left=${left}`;
    }
    processMessageEventMessage(e) {
        let expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        const prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    }
    canPerformSessionCheck() {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    }
    setupSessionCheckEventListener() {
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = (e) => {
            const origin = e.origin.toLowerCase();
            const issuer = this.issuer.toLowerCase();
            this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer, 'event', e);
                return;
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    this.handleSessionUnchanged();
                    break;
                case 'changed':
                    this.ngZone.run(() => {
                        this.handleSessionChange();
                    });
                    break;
                case 'error':
                    this.ngZone.run(() => {
                        this.handleSessionError();
                    });
                    break;
            }
            this.debug('got info from session check inframe', e);
        };
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular(() => {
            window.addEventListener('message', this.sessionCheckEventListener);
        });
    }
    handleSessionUnchanged() {
        this.debug('session check', 'session unchanged');
    }
    handleSessionChange() {
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (!this.useSilentRefresh && this.responseType === 'code') {
            this.refreshToken()
                .then(_ => {
                this.debug('token refresh after session change worked');
            })
                .catch(_ => {
                this.debug('token refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            });
        }
        else if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch(_ => this.debug('silent refresh failed after session changed'));
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    }
    waitForSilentRefreshAfterSessionChange() {
        this.events
            .pipe(filter((e) => e.type === 'silently_refreshed' ||
            e.type === 'silent_refresh_timeout' ||
            e.type === 'silent_refresh_error'), first())
            .subscribe(e => {
            if (e.type !== 'silently_refreshed') {
                this.debug('silent refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            }
        });
    }
    handleSessionError() {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    }
    removeSessionCheckEventListener() {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    }
    initSessionCheck() {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        const existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        const iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        const url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    }
    startSessionCheckTimer() {
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular(() => {
            this.sessionCheckTimer = setInterval(this.checkSession.bind(this), this.sessionCheckIntervall);
        });
    }
    stopSessionCheckTimer() {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    }
    checkSession() {
        const iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        const message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    }
    createLoginUrl(state = '', loginHint = '', customRedirectUri = '', noPrompt = false, params = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const that = this;
            let redirectUri;
            if (customRedirectUri) {
                redirectUri = customRedirectUri;
            }
            else {
                redirectUri = this.redirectUri;
            }
            const nonce = yield this.createAndSaveNonce();
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
            const seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
            let scope = that.scope;
            if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                scope = 'openid ' + scope;
            }
            let url = that.loginUrl +
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
            if (this.responseType === 'code' && !this.disablePKCE) {
                const [challenge, verifier] = yield this.createChallangeVerifierPairForPKCE();
                if (this.saveNoncesInLocalStorage &&
                    typeof window['localStorage'] !== 'undefined') {
                    localStorage.setItem('PKCI_verifier', verifier);
                }
                else {
                    this._storage.setItem('PKCI_verifier', verifier);
                }
                url += '&code_challenge=' + challenge;
                url += '&code_challenge_method=S256';
            }
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
            for (const key of Object.keys(params)) {
                url +=
                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    url +=
                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                }
            }
            return url;
        });
    }
    initImplicitFlowInternal(additionalState = '', params = '') {
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        let addParams = {};
        let loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initImplicitFlow', error);
            this.inImplicitFlow = false;
        });
    }
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    initImplicitFlow(additionalState = '', params = '') {
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initImplicitFlowInternal(additionalState, params));
        }
    }
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    resetImplicitFlow() {
        this.inImplicitFlow = false;
    }
    callOnTokenReceivedIfExists(options) {
        const that = this;
        if (options.onTokenReceived) {
            const tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    }
    storeAccessTokenResponse(accessToken, refreshToken, expiresIn, grantedScopes, customParameters) {
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes && !Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        else if (grantedScopes && Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            const expiresInMilliSeconds = expiresIn * 1000;
            const now = new Date();
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
        if (customParameters) {
            customParameters.forEach((value, key) => {
                this._storage.setItem(key, value);
            });
        }
    }
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    tryLogin(options = null) {
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow(options).then(_ => true);
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    }
    parseQueryString(queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    tryLoginCodeFlow(options = null) {
        options = options || {};
        const querySource = options.customHashFragment
            ? options.customHashFragment.substring(1)
            : window.location.search;
        const parts = this.getCodePartsFromUrl(querySource);
        const code = parts['code'];
        const state = parts['state'];
        const sessionState = parts['session_state'];
        if (!options.preventClearHashAfterLogin) {
            const href = location.href
                .replace(/[&\?]code=[^&\$]*/, '')
                .replace(/[&\?]scope=[^&\$]*/, '')
                .replace(/[&\?]state=[^&\$]*/, '')
                .replace(/[&\?]session_state=[^&\$]*/, '');
            history.replaceState(null, window.name, href);
        }
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            const err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        const success = this.validateNonce(nonceInState);
        if (!success) {
            const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event);
            return Promise.reject(event);
        }
        this.storeSessionState(sessionState);
        if (code) {
            return this.getTokenFromCode(code, options).then(_ => null);
        }
        else {
            return Promise.resolve();
        }
    }
    /**
     * Retrieve the returned auth code from the redirect uri that has been called.
     * If required also check hash, as we could use hash location strategy.
     */
    getCodePartsFromUrl(queryString) {
        if (!queryString || queryString.length === 0) {
            return this.urlHelper.getHashFragmentParams();
        }
        // normalize query string
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    getTokenFromCode(code, options) {
        let params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', options.customRedirectUri || this.redirectUri);
        if (!this.disablePKCE) {
            let pkciVerifier;
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
    }
    fetchAndProcessToken(params) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise((resolve, reject) => {
            if (this.customQueryParams) {
                for (let key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                if (this.oidc && tokenResponse.id_token) {
                    this.processIdToken(tokenResponse.id_token, tokenResponse.access_token)
                        .then(result => {
                        this.storeIdToken(result);
                        this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    })
                        .catch(reason => {
                        this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    });
                }
                else {
                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }, err => {
                console.error('Error getting token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    tryLoginImplicitFlow(options = null) {
        options = options || {};
        let parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        const state = parts['state'];
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            const err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        const accessToken = parts['access_token'];
        const idToken = parts['id_token'];
        const sessionState = parts['session_state'];
        const grantedScopes = parts['scope'];
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
            const success = this.validateNonce(nonceInState);
            if (!success) {
                const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event);
                return Promise.reject(event);
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
            .then(result => {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then(_ => result);
            }
            return result;
        })
            .then(result => {
            this.storeIdToken(result);
            this.storeSessionState(sessionState);
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            this.callOnTokenReceivedIfExists(options);
            this.inImplicitFlow = false;
            return true;
        })
            .catch(reason => {
            this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            this.logger.error('Error validating tokens');
            this.logger.error(reason);
            return Promise.reject(reason);
        });
    }
    parseState(state) {
        let nonce = state;
        let userState = '';
        if (state) {
            const idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    }
    validateNonce(nonceInState) {
        let savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (savedNonce !== nonceInState) {
            const err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    }
    storeIdToken(idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    }
    storeSessionState(sessionState) {
        this._storage.setItem('session_state', sessionState);
    }
    getSessionState() {
        return this._storage.getItem('session_state');
    }
    handleLoginError(options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
            location.hash = '';
        }
    }
    /**
     * @ignore
     */
    processIdToken(idToken, accessToken, skipNonceCheck = false) {
        const tokenParts = idToken.split('.');
        const headerBase64 = this.padBase64(tokenParts[0]);
        const headerJson = b64DecodeUnicode(headerBase64);
        const header = JSON.parse(headerJson);
        const claimsBase64 = this.padBase64(tokenParts[1]);
        const claimsJson = b64DecodeUnicode(claimsBase64);
        const claims = JSON.parse(claimsJson);
        let savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(v => v !== this.clientId)) {
                const err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                const err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            const err = 'No sub claim in id_token';
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
            const err = 'After refreshing, we got an id_token for another user (sub). ' +
                `Expected sub: ${this.silentRefreshSubject}, received sub: ${claims['sub']}`;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            const err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            const err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            const err = 'Wrong nonce: ' + claims.nonce;
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
            const err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        const now = Date.now();
        const issuedAtMSec = claims.iat * 1000;
        const expiresAtMSec = claims.exp * 1000;
        const clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            const err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        const validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: () => this.loadJwks()
        };
        if (this.disableAtHashCheck) {
            return this.checkSignature(validationParams).then(_ => {
                const result = {
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
        return this.checkAtHash(validationParams).then(atHashValid => {
            if (!this.disableAtHashCheck && this.requestAccessToken && !atHashValid) {
                const err = 'Wrong at_hash';
                this.logger.warn(err);
                return Promise.reject(err);
            }
            return this.checkSignature(validationParams).then(_ => {
                const atHashCheckEnabled = !this.disableAtHashCheck;
                const result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                if (atHashCheckEnabled) {
                    return this.checkAtHash(validationParams).then(atHashValid => {
                        if (this.requestAccessToken && !atHashValid) {
                            const err = 'Wrong at_hash';
                            this.logger.warn(err);
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
    }
    /**
     * Returns the received claims about the user.
     */
    getIdentityClaims() {
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }
    /**
     * Returns the granted scopes from the server.
     */
    getGrantedScopes() {
        const scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    }
    /**
     * Returns the current id_token.
     */
    getIdToken() {
        return this._storage ? this._storage.getItem('id_token') : null;
    }
    padBase64(base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }
    /**
     * Returns the current access_token.
     */
    getAccessToken() {
        return this._storage ? this._storage.getItem('access_token') : null;
    }
    getRefreshToken() {
        return this._storage ? this._storage.getItem('refresh_token') : null;
    }
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    getAccessTokenExpiration() {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    }
    getAccessTokenStoredAt() {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    }
    getIdTokenStoredAt() {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    }
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    getIdTokenExpiration() {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    }
    /**
     * Checkes, whether there is a valid access_token.
     */
    hasValidAccessToken() {
        if (this.getAccessToken()) {
            const expiresAt = this._storage.getItem('expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Checks whether there is a valid id_token.
     */
    hasValidIdToken() {
        if (this.getIdToken()) {
            const expiresAt = this._storage.getItem('id_token_expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Retrieve a saved custom property of the TokenReponse object. Only if predefined in authconfig.
     */
    getCustomTokenResponseProperty(requestedProperty) {
        return this._storage &&
            this.config.customTokenParameters &&
            this.config.customTokenParameters.indexOf(requestedProperty) >= 0 &&
            this._storage.getItem(requestedProperty) !== null
            ? JSON.parse(this._storage.getItem(requestedProperty))
            : null;
    }
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    authorizationHeader() {
        return 'Bearer ' + this.getAccessToken();
    }
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it with optional state parameter.
     * @param noRedirectToLogoutUrl
     * @param state
     */
    logOut(noRedirectToLogoutUrl = false, state = '') {
        const id_token = this.getIdToken();
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
            this.config.customTokenParameters.forEach(customParam => this._storage.removeItem(customParam));
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
        let logoutUrl;
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
            let params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            const postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
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
    }
    /**
     * @ignore
     */
    createAndSaveNonce() {
        const that = this;
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
    }
    /**
     * @ignore
     */
    ngOnDestroy() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.removeSilentRefreshEventListener();
        const silentRefreshFrame = this.document.getElementById(this.silentRefreshIFrameName);
        if (silentRefreshFrame) {
            silentRefreshFrame.remove();
        }
        this.stopSessionCheckTimer();
        this.removeSessionCheckEventListener();
        const sessionCheckFrame = this.document.getElementById(this.sessionCheckIFrameName);
        if (sessionCheckFrame) {
            sessionCheckFrame.remove();
        }
    }
    createNonce() {
        return new Promise(resolve => {
            if (this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
             * This alphabet is from:
             * https://tools.ietf.org/html/rfc7636#section-4.1
             *
             * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
             */
            const unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            let size = 45;
            let id = '';
            const crypto = typeof self === 'undefined' ? null : self.crypto || self['msCrypto'];
            if (crypto) {
                let bytes = new Uint8Array(size);
                crypto.getRandomValues(bytes);
                // Needed for IE
                if (!bytes.map) {
                    bytes.map = Array.prototype.map;
                }
                bytes = bytes.map(x => unreserved.charCodeAt(x % unreserved.length));
                id = String.fromCharCode.apply(null, bytes);
            }
            else {
                while (0 < size--) {
                    id += unreserved[(Math.random() * unreserved.length) | 0];
                }
            }
            resolve(base64UrlEncode(id));
        });
    }
    checkAtHash(params) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.tokenValidationHandler) {
                this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                return true;
            }
            return this.tokenValidationHandler.validateAtHash(params);
        });
    }
    checkSignature(params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    }
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    initLoginFlow(additionalState = '', params = {}) {
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    }
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    initCodeFlow(additionalState = '', params = {}) {
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initCodeFlowInternal(additionalState, params));
        }
    }
    initCodeFlowInternal(additionalState = '', params = {}) {
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        });
    }
    createChallangeVerifierPairForPKCE() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.crypto) {
                throw new Error('PKCE support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
            }
            const verifier = yield this.createNonce();
            const challengeRaw = yield this.crypto.calcHash(verifier, 'sha-256');
            const challenge = base64UrlEncode(challengeRaw);
            return [challenge, verifier];
        });
    }
    extractRecognizedCustomParameters(tokenResponse) {
        let foundParameters = new Map();
        if (!this.config.customTokenParameters) {
            return foundParameters;
        }
        this.config.customTokenParameters.forEach((recognizedParameter) => {
            if (tokenResponse[recognizedParameter]) {
                foundParameters.set(recognizedParameter, JSON.stringify(tokenResponse[recognizedParameter]));
            }
        });
        return foundParameters;
    }
};
OAuthService.ctorParameters = () => [
    { type: NgZone },
    { type: HttpClient },
    { type: OAuthStorage, decorators: [{ type: Optional }] },
    { type: ValidationHandler, decorators: [{ type: Optional }] },
    { type: AuthConfig, decorators: [{ type: Optional }] },
    { type: UrlHelperService },
    { type: OAuthLogger },
    { type: HashHandler, decorators: [{ type: Optional }] },
    { type: Document, decorators: [{ type: Inject, args: [DOCUMENT,] }] }
];
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
export { OAuthService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUNoRixPQUFPLEVBQUUsVUFBVSxFQUFFLFdBQVcsRUFBRSxVQUFVLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUMzRSxPQUFPLEVBQWMsT0FBTyxFQUFnQixFQUFFLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxNQUFNLE1BQU0sQ0FBQztBQUN6RSxPQUFPLEVBQ0wsTUFBTSxFQUNOLEtBQUssRUFDTCxLQUFLLEVBQ0wsR0FBRyxFQUNILEdBQUcsRUFDSCxTQUFTLEVBQ1QsWUFBWSxFQUNiLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBRTNDLE9BQU8sRUFDTCxpQkFBaUIsRUFDakIsZ0JBQWdCLEVBQ2pCLE1BQU0sdUNBQXVDLENBQUM7QUFDL0MsT0FBTyxFQUFFLGdCQUFnQixFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFDeEQsT0FBTyxFQUVMLGNBQWMsRUFDZCxlQUFlLEVBQ2YsaUJBQWlCLEVBQ2xCLE1BQU0sVUFBVSxDQUFDO0FBQ2xCLE9BQU8sRUFDTCxXQUFXLEVBQ1gsWUFBWSxFQUNaLFlBQVksRUFDWixhQUFhLEVBQ2IsZ0JBQWdCLEVBQ2hCLGFBQWEsRUFDYixRQUFRLEVBQ1QsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FB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QUNxQixVQUFVLHVCQUF2QyxRQUFRO1lBQ1ksZ0JBQWdCO1lBQ25CLFdBQVc7WUFDQyxXQUFXLHVCQUF4QyxRQUFRO1lBQzJCLFFBQVEsdUJBQTNDLE1BQU0sU0FBQyxRQUFROztBQTdEUCxZQUFZO0lBRHhCLFVBQVUsRUFBRTtJQXdEUixXQUFBLFFBQVEsRUFBRSxDQUFBO0lBQ1YsV0FBQSxRQUFRLEVBQUUsQ0FBQTtJQUNWLFdBQUEsUUFBUSxFQUFFLENBQUE7SUFHVixXQUFBLFFBQVEsRUFBRSxDQUFBO0lBQ1YsV0FBQSxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUE7cUNBUkMsTUFBTTtRQUNSLFVBQVU7UUFDTCxZQUFZO1FBQ0csaUJBQWlCO1FBQ3ZCLFVBQVU7UUFDbkIsZ0JBQWdCO1FBQ25CLFdBQVc7UUFDQyxXQUFXO1FBQ0wsUUFBUTtHQTdEbkMsWUFBWSxDQXVpRnhCO1NBdmlGWSxZQUFZIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmdab25lLCBPcHRpb25hbCwgT25EZXN0cm95LCBJbmplY3QgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IEh0dHBDbGllbnQsIEh0dHBIZWFkZXJzLCBIdHRwUGFyYW1zIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgU3ViamVjdCwgU3Vic2NyaXB0aW9uLCBvZiwgcmFjZSwgZnJvbSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0IHtcbiAgZmlsdGVyLFxuICBkZWxheSxcbiAgZmlyc3QsXG4gIHRhcCxcbiAgbWFwLFxuICBzd2l0Y2hNYXAsXG4gIGRlYm91bmNlVGltZVxufSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBET0NVTUVOVCB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XG5cbmltcG9ydCB7XG4gIFZhbGlkYXRpb25IYW5kbGVyLFxuICBWYWxpZGF0aW9uUGFyYW1zXG59IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi92YWxpZGF0aW9uLWhhbmRsZXInO1xuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcbmltcG9ydCB7XG4gIE9BdXRoRXZlbnQsXG4gIE9BdXRoSW5mb0V2ZW50LFxuICBPQXV0aEVycm9yRXZlbnQsXG4gIE9BdXRoU3VjY2Vzc0V2ZW50XG59IGZyb20gJy4vZXZlbnRzJztcbmltcG9ydCB7XG4gIE9BdXRoTG9nZ2VyLFxuICBPQXV0aFN0b3JhZ2UsXG4gIExvZ2luT3B0aW9ucyxcbiAgUGFyc2VkSWRUb2tlbixcbiAgT2lkY0Rpc2NvdmVyeURvYyxcbiAgVG9rZW5SZXNwb25zZSxcbiAgVXNlckluZm9cbn0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBiNjREZWNvZGVVbmljb2RlLCBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuL2Jhc2U2NC1oZWxwZXInO1xuaW1wb3J0IHsgQXV0aENvbmZpZyB9IGZyb20gJy4vYXV0aC5jb25maWcnO1xuaW1wb3J0IHsgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgfSBmcm9tICcuL2VuY29kZXInO1xuaW1wb3J0IHsgSGFzaEhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcblxuLyoqXG4gKiBTZXJ2aWNlIGZvciBsb2dnaW5nIGluIGFuZCBsb2dnaW5nIG91dCB3aXRoXG4gKiBPSURDIGFuZCBPQXV0aDIuIFN1cHBvcnRzIGltcGxpY2l0IGZsb3cgYW5kXG4gKiBwYXNzd29yZCBmbG93LlxuICovXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgT0F1dGhTZXJ2aWNlIGV4dGVuZHMgQXV0aENvbmZpZyBpbXBsZW1lbnRzIE9uRGVzdHJveSB7XG4gIC8vIEV4dGVuZGluZyBBdXRoQ29uZmlnIGlzdCBqdXN0IGZvciBMRUdBQ1kgcmVhc29uc1xuICAvLyB0byBub3QgYnJlYWsgZXhpc3RpbmcgY29kZS5cblxuICAvKipcbiAgICogVGhlIFZhbGlkYXRpb25IYW5kbGVyIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWRcbiAgICogaWRfdG9rZW5zLlxuICAgKi9cbiAgcHVibGljIHRva2VuVmFsaWRhdGlvbkhhbmRsZXI6IFZhbGlkYXRpb25IYW5kbGVyO1xuXG4gIC8qKlxuICAgKiBAaW50ZXJuYWxcbiAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxuICAgKi9cbiAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIEBpbnRlcm5hbFxuICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXG4gICAqL1xuICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkOiBPYnNlcnZhYmxlPE9pZGNEaXNjb3ZlcnlEb2M+O1xuXG4gIC8qKlxuICAgKiBJbmZvcm1zIGFib3V0IGV2ZW50cywgbGlrZSB0b2tlbl9yZWNlaXZlZCBvciB0b2tlbl9leHBpcmVzLlxuICAgKiBTZWUgdGhlIHN0cmluZyBlbnVtIEV2ZW50VHlwZSBmb3IgYSBmdWxsIGxpc3Qgb2YgZXZlbnQgdHlwZXMuXG4gICAqL1xuICBwdWJsaWMgZXZlbnRzOiBPYnNlcnZhYmxlPE9BdXRoRXZlbnQ+O1xuXG4gIC8qKlxuICAgKiBUaGUgcmVjZWl2ZWQgKHBhc3NlZCBhcm91bmQpIHN0YXRlLCB3aGVuIGxvZ2dpbmdcbiAgICogaW4gd2l0aCBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIHN0YXRlPyA9ICcnO1xuXG4gIHByb3RlY3RlZCBldmVudHNTdWJqZWN0OiBTdWJqZWN0PE9BdXRoRXZlbnQ+ID0gbmV3IFN1YmplY3Q8T0F1dGhFdmVudD4oKTtcbiAgcHJvdGVjdGVkIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdDogU3ViamVjdDxcbiAgICBPaWRjRGlzY292ZXJ5RG9jXG4gID4gPSBuZXcgU3ViamVjdDxPaWRjRGlzY292ZXJ5RG9jPigpO1xuICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcbiAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcbiAgcHJvdGVjdGVkIF9zdG9yYWdlOiBPQXV0aFN0b3JhZ2U7XG4gIHByb3RlY3RlZCBhY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gIHByb3RlY3RlZCB0b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyOiBFdmVudExpc3RlbmVyO1xuICBwcm90ZWN0ZWQgandrc1VyaTogc3RyaW5nO1xuICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrVGltZXI6IGFueTtcbiAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hTdWJqZWN0OiBzdHJpbmc7XG4gIHByb3RlY3RlZCBpbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuXG4gIHByb3RlY3RlZCBzYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgPSBmYWxzZTtcblxuICBjb25zdHJ1Y3RvcihcbiAgICBwcm90ZWN0ZWQgbmdab25lOiBOZ1pvbmUsXG4gICAgcHJvdGVjdGVkIGh0dHA6IEh0dHBDbGllbnQsXG4gICAgQE9wdGlvbmFsKCkgc3RvcmFnZTogT0F1dGhTdG9yYWdlLFxuICAgIEBPcHRpb25hbCgpIHRva2VuVmFsaWRhdGlvbkhhbmRsZXI6IFZhbGlkYXRpb25IYW5kbGVyLFxuICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjb25maWc6IEF1dGhDb25maWcsXG4gICAgcHJvdGVjdGVkIHVybEhlbHBlcjogVXJsSGVscGVyU2VydmljZSxcbiAgICBwcm90ZWN0ZWQgbG9nZ2VyOiBPQXV0aExvZ2dlcixcbiAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY3J5cHRvOiBIYXNoSGFuZGxlcixcbiAgICBASW5qZWN0KERPQ1VNRU5UKSBwcml2YXRlIGRvY3VtZW50OiBEb2N1bWVudFxuICApIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5kZWJ1ZygnYW5ndWxhci1vYXV0aDItb2lkYyB2OC1iZXRhJyk7XG5cbiAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkJCA9IHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuICAgIHRoaXMuZXZlbnRzID0gdGhpcy5ldmVudHNTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuXG4gICAgaWYgKHRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlciA9IHRva2VuVmFsaWRhdGlvbkhhbmRsZXI7XG4gICAgfVxuXG4gICAgaWYgKGNvbmZpZykge1xuICAgICAgdGhpcy5jb25maWd1cmUoY29uZmlnKTtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgaWYgKHN0b3JhZ2UpIHtcbiAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHN0b3JhZ2UpO1xuICAgICAgfSBlbHNlIGlmICh0eXBlb2Ygc2Vzc2lvblN0b3JhZ2UgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIHRoaXMuc2V0U3RvcmFnZShzZXNzaW9uU3RvcmFnZSk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcihcbiAgICAgICAgJ05vIE9BdXRoU3RvcmFnZSBwcm92aWRlZCBhbmQgY2Fubm90IGFjY2VzcyBkZWZhdWx0IChzZXNzaW9uU3RvcmFnZSkuJyArXG4gICAgICAgICAgJ0NvbnNpZGVyIHByb3ZpZGluZyBhIGN1c3RvbSBPQXV0aFN0b3JhZ2UgaW1wbGVtZW50YXRpb24gaW4geW91ciBtb2R1bGUuJyxcbiAgICAgICAgZVxuICAgICAgKTtcbiAgICB9XG5cbiAgICAvLyBpbiBJRSwgc2Vzc2lvblN0b3JhZ2UgZG9lcyBub3QgYWx3YXlzIHN1cnZpdmUgYSByZWRpcmVjdFxuICAgIGlmIChcbiAgICAgIHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnICYmXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcbiAgICApIHtcbiAgICAgIGNvbnN0IHVhID0gd2luZG93Py5uYXZpZ2F0b3I/LnVzZXJBZ2VudDtcbiAgICAgIGNvbnN0IG1zaWUgPSB1YT8uaW5jbHVkZXMoJ01TSUUgJykgfHwgdWE/LmluY2x1ZGVzKCdUcmlkZW50Jyk7XG5cbiAgICAgIGlmIChtc2llKSB7XG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XG4gIH1cblxuICAvKipcbiAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGNvbmZpZ3VyZSB0aGUgc2VydmljZVxuICAgKiBAcGFyYW0gY29uZmlnIHRoZSBjb25maWd1cmF0aW9uXG4gICAqL1xuICBwdWJsaWMgY29uZmlndXJlKGNvbmZpZzogQXV0aENvbmZpZyk6IHZvaWQge1xuICAgIC8vIEZvciB0aGUgc2FrZSBvZiBkb3dud2FyZCBjb21wYXRpYmlsaXR5IHdpdGhcbiAgICAvLyBvcmlnaW5hbCBjb25maWd1cmF0aW9uIEFQSVxuICAgIE9iamVjdC5hc3NpZ24odGhpcywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcblxuICAgIHRoaXMuY29uZmlnID0gT2JqZWN0LmFzc2lnbih7fSBhcyBBdXRoQ29uZmlnLCBuZXcgQXV0aENvbmZpZygpLCBjb25maWcpO1xuXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2soKTtcbiAgICB9XG5cbiAgICB0aGlzLmNvbmZpZ0NoYW5nZWQoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBjb25maWdDaGFuZ2VkKCk6IHZvaWQge1xuICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcbiAgfVxuXG4gIHB1YmxpYyByZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XG4gICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVjaygpOiB2b2lkIHtcbiAgICB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpLnN1YnNjcmliZShlID0+IHtcbiAgICAgIHRoaXMuaW5pdFNlc3Npb25DaGVjaygpO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFdpbGwgc2V0dXAgdXAgc2lsZW50IHJlZnJlc2hpbmcgZm9yIHdoZW4gdGhlIHRva2VuIGlzXG4gICAqIGFib3V0IHRvIGV4cGlyZS4gV2hlbiB0aGUgdXNlciBpcyBsb2dnZWQgb3V0IHZpYSB0aGlzLmxvZ091dCBtZXRob2QsIHRoZVxuICAgKiBzaWxlbnQgcmVmcmVzaGluZyB3aWxsIHBhdXNlIGFuZCBub3QgcmVmcmVzaCB0aGUgdG9rZW5zIHVudGlsIHRoZSB1c2VyIGlzXG4gICAqIGxvZ2dlZCBiYWNrIGluIHZpYSByZWNlaXZpbmcgYSBuZXcgdG9rZW4uXG4gICAqIEBwYXJhbSBwYXJhbXMgQWRkaXRpb25hbCBwYXJhbWV0ZXIgdG8gcGFzc1xuICAgKiBAcGFyYW0gbGlzdGVuVG8gU2V0dXAgYXV0b21hdGljIHJlZnJlc2ggb2YgYSBzcGVjaWZpYyB0b2tlbiB0eXBlXG4gICAqL1xuICBwdWJsaWMgc2V0dXBBdXRvbWF0aWNTaWxlbnRSZWZyZXNoKFxuICAgIHBhcmFtczogb2JqZWN0ID0ge30sXG4gICAgbGlzdGVuVG8/OiAnYWNjZXNzX3Rva2VuJyB8ICdpZF90b2tlbicgfCAnYW55JyxcbiAgICBub1Byb21wdCA9IHRydWVcbiAgKTogdm9pZCB7XG4gICAgbGV0IHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xuICAgIHRoaXMuZXZlbnRzXG4gICAgICAucGlwZShcbiAgICAgICAgdGFwKGUgPT4ge1xuICAgICAgICAgIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcbiAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xuICAgICAgICAgIH0gZWxzZSBpZiAoZS50eXBlID09PSAnbG9nb3V0Jykge1xuICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IGZhbHNlO1xuICAgICAgICAgIH1cbiAgICAgICAgfSksXG4gICAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX2V4cGlyZXMnKSxcbiAgICAgICAgZGVib3VuY2VUaW1lKDEwMDApXG4gICAgICApXG4gICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICBjb25zdCBldmVudCA9IGUgYXMgT0F1dGhJbmZvRXZlbnQ7XG4gICAgICAgIGlmIChcbiAgICAgICAgICAobGlzdGVuVG8gPT0gbnVsbCB8fCBsaXN0ZW5UbyA9PT0gJ2FueScgfHwgZXZlbnQuaW5mbyA9PT0gbGlzdGVuVG8pICYmXG4gICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaFxuICAgICAgICApIHtcbiAgICAgICAgICAvLyB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgdGhpcy5yZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdBdXRvbWF0aWMgc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrJyk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgdGhpcy5yZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgcmVmcmVzaEludGVybmFsKFxuICAgIHBhcmFtcyxcbiAgICBub1Byb21wdFxuICApOiBQcm9taXNlPFRva2VuUmVzcG9uc2UgfCBPQXV0aEV2ZW50PiB7XG4gICAgaWYgKCF0aGlzLnVzZVNpbGVudFJlZnJlc2ggJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFRva2VuKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoLi4uKWAgYW5kXG4gICAqIGRpcmVjdGx5IGNoYWlucyB1c2luZyB0aGUgYHRoZW4oLi4uKWAgcGFydCBvZiB0aGUgcHJvbWlzZSB0byBjYWxsXG4gICAqIHRoZSBgdHJ5TG9naW4oLi4uKWAgbWV0aG9kLlxuICAgKlxuICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxuICAgKi9cbiAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKFxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGxcbiAgKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50KCkudGhlbihkb2MgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW4ob3B0aW9ucyk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKC4uLilgXG4gICAqIGFuZCBpZiB0aGVuIGNoYWlucyB0byBgaW5pdExvZ2luRmxvdygpYCwgYnV0IG9ubHkgaWYgdGhlcmUgaXMgbm8gdmFsaWRcbiAgICogSWRUb2tlbiBvciBubyB2YWxpZCBBY2Nlc3NUb2tlbi5cbiAgICpcbiAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcbiAgICovXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRMb2dpbihcbiAgICBvcHRpb25zOiBMb2dpbk9wdGlvbnMgJiB7IHN0YXRlPzogc3RyaW5nIH0gPSBudWxsXG4gICk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGlmICghb3B0aW9ucykge1xuICAgICAgb3B0aW9ucyA9IHsgc3RhdGU6ICcnIH07XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnMpLnRoZW4oXyA9PiB7XG4gICAgICBpZiAoIXRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgdGhpcy5pbml0Q29kZUZsb3coKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3coKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBkZWJ1ZyguLi5hcmdzKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc2hvd0RlYnVnSW5mb3JtYXRpb24pIHtcbiAgICAgIHRoaXMubG9nZ2VyLmRlYnVnLmFwcGx5KHRoaXMubG9nZ2VyLCBhcmdzKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQodXJsOiBzdHJpbmcpOiBzdHJpbmdbXSB7XG4gICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xuICAgIGNvbnN0IGh0dHBzQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKTtcbiAgICBjb25zdCBpc3N1ZXJDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybCk7XG5cbiAgICBpZiAoIWh0dHBzQ2hlY2spIHtcbiAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAnaHR0cHMgZm9yIGFsbCB1cmxzIHJlcXVpcmVkLiBBbHNvIGZvciB1cmxzIHJlY2VpdmVkIGJ5IGRpc2NvdmVyeS4nXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICghaXNzdWVyQ2hlY2spIHtcbiAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAnRXZlcnkgdXJsIGluIGRpc2NvdmVyeSBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyIHVybC4nICtcbiAgICAgICAgICAnQWxzbyBzZWUgcHJvcGVydHkgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uLidcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGVycm9ycztcbiAgfVxuXG4gIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZvckh0dHBzKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgaWYgKCF1cmwpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIGNvbnN0IGxjVXJsID0gdXJsLnRvTG93ZXJDYXNlKCk7XG5cbiAgICBpZiAodGhpcy5yZXF1aXJlSHR0cHMgPT09IGZhbHNlKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICBpZiAoXG4gICAgICAobGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSB8fFxuICAgICAgICBsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pKSAmJlxuICAgICAgdGhpcy5yZXF1aXJlSHR0cHMgPT09ICdyZW1vdGVPbmx5J1xuICAgICkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIGxjVXJsLnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJyk7XG4gIH1cblxuICBwcm90ZWN0ZWQgYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcbiAgICB1cmw6IHN0cmluZyB8IHVuZGVmaW5lZCxcbiAgICBkZXNjcmlwdGlvbjogc3RyaW5nXG4gICkge1xuICAgIGlmICghdXJsKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYCcke2Rlc2NyaXB0aW9ufScgc2hvdWxkIG5vdCBiZSBudWxsYCk7XG4gICAgfVxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYCcke2Rlc2NyaXB0aW9ufScgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuYFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybDogc3RyaW5nKSB7XG4gICAgaWYgKCF0aGlzLnN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbikge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGlmICghdXJsKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgcmV0dXJuIHVybC50b0xvd2VyQ2FzZSgpLnN0YXJ0c1dpdGgodGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc2V0dXBSZWZyZXNoVGltZXIoKTogdm9pZCB7XG4gICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICB0aGlzLmRlYnVnKCd0aW1lciBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdHRmb3JtJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24pXG4gICAgICB0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcblxuICAgIHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbiA9IHRoaXMuZXZlbnRzXG4gICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKVxuICAgICAgLnN1YnNjcmliZShfID0+IHtcbiAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgdGhpcy5zZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgdGhpcy5zZXR1cElkVG9rZW5UaW1lcigpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XG4gICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk7XG4gICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTtcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxuICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnYWNjZXNzX3Rva2VuJylcbiAgICAgIClcbiAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cElkVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRJZFRva2VuRXhwaXJhdGlvbigpO1xuICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRJZFRva2VuU3RvcmVkQXQoKTtcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXG4gICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdpZF90b2tlbicpXG4gICAgICApXG4gICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxuICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogU3RvcHMgdGltZXJzIGZvciBhdXRvbWF0aWMgcmVmcmVzaC5cbiAgICogVG8gcmVzdGFydCBpdCwgY2FsbCBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2ggYWdhaW4uXG4gICAqL1xuICBwdWJsaWMgc3RvcEF1dG9tYXRpY1JlZnJlc2goKSB7XG4gICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgY2xlYXJJZFRva2VuVGltZXIoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24pIHtcbiAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgY2FsY1RpbWVvdXQoc3RvcmVkQXQ6IG51bWJlciwgZXhwaXJhdGlvbjogbnVtYmVyKTogbnVtYmVyIHtcbiAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgIGNvbnN0IGRlbHRhID1cbiAgICAgIChleHBpcmF0aW9uIC0gc3RvcmVkQXQpICogdGhpcy50aW1lb3V0RmFjdG9yIC0gKG5vdyAtIHN0b3JlZEF0KTtcbiAgICByZXR1cm4gTWF0aC5tYXgoMCwgZGVsdGEpO1xuICB9XG5cbiAgLyoqXG4gICAqIERFUFJFQ0FURUQuIFVzZSBhIHByb3ZpZGVyIGZvciBPQXV0aFN0b3JhZ2UgaW5zdGVhZDpcbiAgICpcbiAgICogeyBwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IG9BdXRoU3RvcmFnZUZhY3RvcnkgfVxuICAgKiBleHBvcnQgZnVuY3Rpb24gb0F1dGhTdG9yYWdlRmFjdG9yeSgpOiBPQXV0aFN0b3JhZ2UgeyByZXR1cm4gbG9jYWxTdG9yYWdlOyB9XG4gICAqIFNldHMgYSBjdXN0b20gc3RvcmFnZSB1c2VkIHRvIHN0b3JlIHRoZSByZWNlaXZlZFxuICAgKiB0b2tlbnMgb24gY2xpZW50IHNpZGUuIEJ5IGRlZmF1bHQsIHRoZSBicm93c2VyJ3NcbiAgICogc2Vzc2lvblN0b3JhZ2UgaXMgdXNlZC5cbiAgICogQGlnbm9yZVxuICAgKlxuICAgKiBAcGFyYW0gc3RvcmFnZVxuICAgKi9cbiAgcHVibGljIHNldFN0b3JhZ2Uoc3RvcmFnZTogT0F1dGhTdG9yYWdlKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcmFnZSA9IHN0b3JhZ2U7XG4gICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XG4gIH1cblxuICAvKipcbiAgICogTG9hZHMgdGhlIGRpc2NvdmVyeSBkb2N1bWVudCB0byBjb25maWd1cmUgbW9zdFxuICAgKiBwcm9wZXJ0aWVzIG9mIHRoaXMgc2VydmljZS4gVGhlIHVybCBvZiB0aGUgZGlzY292ZXJ5XG4gICAqIGRvY3VtZW50IGlzIGluZmVyZWQgZnJvbSB0aGUgaXNzdWVyJ3MgdXJsIGFjY29yZGluZ1xuICAgKiB0byB0aGUgT3BlbklkIENvbm5lY3Qgc3BlYy4gVG8gdXNlIGFub3RoZXIgdXJsIHlvdVxuICAgKiBjYW4gcGFzcyBpdCB0byB0byBvcHRpb25hbCBwYXJhbWV0ZXIgZnVsbFVybC5cbiAgICpcbiAgICogQHBhcmFtIGZ1bGxVcmxcbiAgICovXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoXG4gICAgZnVsbFVybDogc3RyaW5nID0gbnVsbFxuICApOiBQcm9taXNlPE9BdXRoU3VjY2Vzc0V2ZW50PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghZnVsbFVybCkge1xuICAgICAgICBmdWxsVXJsID0gdGhpcy5pc3N1ZXIgfHwgJyc7XG4gICAgICAgIGlmICghZnVsbFVybC5lbmRzV2l0aCgnLycpKSB7XG4gICAgICAgICAgZnVsbFVybCArPSAnLyc7XG4gICAgICAgIH1cbiAgICAgICAgZnVsbFVybCArPSAnLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24nO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyhmdWxsVXJsKSkge1xuICAgICAgICByZWplY3QoXG4gICAgICAgICAgXCJpc3N1ZXIgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXG4gICAgICAgICk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgdGhpcy5odHRwLmdldDxPaWRjRGlzY292ZXJ5RG9jPihmdWxsVXJsKS5zdWJzY3JpYmUoXG4gICAgICAgIGRvYyA9PiB7XG4gICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jKSkge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJywgbnVsbClcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZWplY3QoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJyk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgdGhpcy5sb2dpblVybCA9IGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50O1xuICAgICAgICAgIHRoaXMubG9nb3V0VXJsID0gZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50IHx8IHRoaXMubG9nb3V0VXJsO1xuICAgICAgICAgIHRoaXMuZ3JhbnRUeXBlc1N1cHBvcnRlZCA9IGRvYy5ncmFudF90eXBlc19zdXBwb3J0ZWQ7XG4gICAgICAgICAgdGhpcy5pc3N1ZXIgPSBkb2MuaXNzdWVyO1xuICAgICAgICAgIHRoaXMudG9rZW5FbmRwb2ludCA9IGRvYy50b2tlbl9lbmRwb2ludDtcbiAgICAgICAgICB0aGlzLnVzZXJpbmZvRW5kcG9pbnQgPVxuICAgICAgICAgICAgZG9jLnVzZXJpbmZvX2VuZHBvaW50IHx8IHRoaXMudXNlcmluZm9FbmRwb2ludDtcbiAgICAgICAgICB0aGlzLmp3a3NVcmkgPSBkb2Muandrc191cmk7XG4gICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwgPVxuICAgICAgICAgICAgZG9jLmNoZWNrX3Nlc3Npb25faWZyYW1lIHx8IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xuXG4gICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IHRydWU7XG4gICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QubmV4dChkb2MpO1xuXG4gICAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgICAgICAgIHRoaXMucmVzdGFydFNlc3Npb25DaGVja3NJZlN0aWxsTG9nZ2VkSW4oKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB0aGlzLmxvYWRKd2tzKClcbiAgICAgICAgICAgIC50aGVuKGp3a3MgPT4ge1xuICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IG9iamVjdCA9IHtcbiAgICAgICAgICAgICAgICBkaXNjb3ZlcnlEb2N1bWVudDogZG9jLFxuICAgICAgICAgICAgICAgIGp3a3M6IGp3a3NcbiAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudChcbiAgICAgICAgICAgICAgICAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcsXG4gICAgICAgICAgICAgICAgcmVzdWx0XG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgICAgcmVzb2x2ZShldmVudCk7XG4gICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSxcbiAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBkaXNjb3ZlcnkgZG9jdW1lbnQnLCBlcnIpO1xuICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgKTtcbiAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgfVxuICAgICAgKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBsb2FkSndrcygpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxvYmplY3Q+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICh0aGlzLmp3a3NVcmkpIHtcbiAgICAgICAgdGhpcy5odHRwLmdldCh0aGlzLmp3a3NVcmkpLnN1YnNjcmliZShcbiAgICAgICAgICBqd2tzID0+IHtcbiAgICAgICAgICAgIHRoaXMuandrcyA9IGp3a3M7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJylcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXNvbHZlKGp3a3MpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGp3a3MnLCBlcnIpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2p3a3NfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXNvbHZlKG51bGwpO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIHZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jOiBPaWRjRGlzY292ZXJ5RG9jKTogYm9vbGVhbiB7XG4gICAgbGV0IGVycm9yczogc3RyaW5nW107XG5cbiAgICBpZiAoIXRoaXMuc2tpcElzc3VlckNoZWNrICYmIGRvYy5pc3N1ZXIgIT09IHRoaXMuaXNzdWVyKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2ludmFsaWQgaXNzdWVyIGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgICdleHBlY3RlZDogJyArIHRoaXMuaXNzdWVyLFxuICAgICAgICAnY3VycmVudDogJyArIGRvYy5pc3N1ZXJcbiAgICAgICk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludCk7XG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgYXV0aG9yaXphdGlvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICBlcnJvcnNcbiAgICAgICk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQpO1xuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGVuZF9zZXNzaW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgIGVycm9yc1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy50b2tlbl9lbmRwb2ludCk7XG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdG9rZW5fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgZXJyb3JzXG4gICAgICApO1xuICAgIH1cblxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnVzZXJpbmZvX2VuZHBvaW50KTtcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB1c2VyaW5mb19lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICBlcnJvcnNcbiAgICAgICk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2Muandrc191cmkpO1xuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGp3a3NfdXJpIGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgIGVycm9yc1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhZG9jLmNoZWNrX3Nlc3Npb25faWZyYW1lKSB7XG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCBkaXNjb3ZlcnkgZG9jdW1lbnQnICtcbiAgICAgICAgICAnIGRvZXMgbm90IGNvbnRhaW4gYSBjaGVja19zZXNzaW9uX2lmcmFtZSBmaWVsZCdcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICAvKipcbiAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW5cbiAgICogYWNjZXNzX3Rva2VuLiBBZnRlciByZWNlaXZpbmcgdGhlIGFjY2Vzc190b2tlbiwgdGhpcyBtZXRob2RcbiAgICogdXNlcyBpdCB0byBxdWVyeSB0aGUgdXNlcmluZm8gZW5kcG9pbnQgaW4gb3JkZXIgdG8gZ2V0IGluZm9ybWF0aW9uXG4gICAqIGFib3V0IHRoZSB1c2VyIGluIHF1ZXN0aW9uLlxuICAgKlxuICAgKiBXaGVuIHVzaW5nIHRoaXMsIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uXG4gICAqIGZhaWwuXG4gICAqXG4gICAqIEBwYXJhbSB1c2VyTmFtZVxuICAgKiBAcGFyYW0gcGFzc3dvcmRcbiAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXG4gICAqL1xuICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93QW5kTG9hZFVzZXJQcm9maWxlKFxuICAgIHVzZXJOYW1lOiBzdHJpbmcsXG4gICAgcGFzc3dvcmQ6IHN0cmluZyxcbiAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICk6IFByb21pc2U8VXNlckluZm8+IHtcbiAgICByZXR1cm4gdGhpcy5mZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3coXG4gICAgICB1c2VyTmFtZSxcbiAgICAgIHBhc3N3b3JkLFxuICAgICAgaGVhZGVyc1xuICAgICkudGhlbigoKSA9PiB0aGlzLmxvYWRVc2VyUHJvZmlsZSgpKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBVc2VzIGV4dGVybmFsIHRva2VuIGFuZCBwcm92aWRlciBmb3IgYW5cbiAgICogYWNjZXNzX3Rva2VuLiBBZnRlciByZWNlaXZpbmcgdGhlIGFjY2Vzc190b2tlbiwgdGhpcyBtZXRob2RcbiAgICogdXNlcyBpdCB0byBxdWVyeSB0aGUgdXNlcmluZm8gZW5kcG9pbnQgaW4gb3JkZXIgdG8gZ2V0IGluZm9ybWF0aW9uXG4gICAqIGFib3V0IHRoZSB1c2VyIGluIHF1ZXN0aW9uLlxuICAgKlxuICAgKiBXaGVuIHVzaW5nIHRoaXMsIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uXG4gICAqIGZhaWwuXG4gICAqXG4gICAqIEBwYXJhbSBwcm92aWRlclxuICAgKiBAcGFyYW0gZXh0ZXJuYWxfdG9rZW5cbiAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXG4gICAqL1xuICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nRXh0ZXJuYWxUb2tlbkFuZExvYWRVc2VyUHJvZmlsZShcbiAgICBwcm92aWRlcjogc3RyaW5nLFxuICAgIGV4dGVybmFsX3Rva2VuOiBzdHJpbmcsXG4gICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICApOiBQcm9taXNlPG9iamVjdD4ge1xuICAgIHJldHVybiB0aGlzLmZldGNoVG9rZW5Vc2luZ1VzaW5nRXh0ZXJuYWxUb2tlbihcbiAgICAgIHByb3ZpZGVyLFxuICAgICAgZXh0ZXJuYWxfdG9rZW4sXG4gICAgICBoZWFkZXJzXG4gICAgKS50aGVuKCgpID0+IHRoaXMubG9hZFVzZXJQcm9maWxlKCkpO1xuICB9XG5cbiAgLyoqXG4gICAqIExvYWRzIHRoZSB1c2VyIHByb2ZpbGUgYnkgYWNjZXNzaW5nIHRoZSB1c2VyIGluZm8gZW5kcG9pbnQgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICpcbiAgICogV2hlbiB1c2luZyB0aGlzIHdpdGggT0F1dGgyIHBhc3N3b3JkIGZsb3csIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uIGZhaWwuXG4gICAqL1xuICBwdWJsaWMgbG9hZFVzZXJQcm9maWxlKCk6IFByb21pc2U8VXNlckluZm8+IHtcbiAgICBpZiAoIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBub3QgbG9hZCBVc2VyIFByb2ZpbGUgd2l0aG91dCBhY2Nlc3NfdG9rZW4nKTtcbiAgICB9XG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy51c2VyaW5mb0VuZHBvaW50KSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcInVzZXJpbmZvRW5kcG9pbnQgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGNvbnN0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpXG4gICAgICApO1xuXG4gICAgICB0aGlzLmh0dHBcbiAgICAgICAgLmdldDxVc2VySW5mbz4odGhpcy51c2VyaW5mb0VuZHBvaW50LCB7IGhlYWRlcnMgfSlcbiAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICBpbmZvID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3VzZXJpbmZvIHJlY2VpdmVkJywgaW5mbyk7XG5cbiAgICAgICAgICAgIGNvbnN0IGV4aXN0aW5nQ2xhaW1zID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xuXG4gICAgICAgICAgICBpZiAoIXRoaXMuc2tpcFN1YmplY3RDaGVjaykge1xuICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjICYmXG4gICAgICAgICAgICAgICAgKCFleGlzdGluZ0NsYWltc1snc3ViJ10gfHwgaW5mby5zdWIgIT09IGV4aXN0aW5nQ2xhaW1zWydzdWInXSlcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgICAgICAgICAgICdpZiBwcm9wZXJ0eSBvaWRjIGlzIHRydWUsIHRoZSByZWNlaXZlZCB1c2VyLWlkIChzdWIpIGhhcyB0byBiZSB0aGUgdXNlci1pZCAnICtcbiAgICAgICAgICAgICAgICAgICdvZiB0aGUgdXNlciB0aGF0IGhhcyBsb2dnZWQgaW4gd2l0aCBvaWRjLlxcbicgK1xuICAgICAgICAgICAgICAgICAgJ2lmIHlvdSBhcmUgbm90IHVzaW5nIG9pZGMgYnV0IGp1c3Qgb2F1dGgyIHBhc3N3b3JkIGZsb3cgc2V0IG9pZGMgdG8gZmFsc2UnO1xuXG4gICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGluZm8gPSBPYmplY3QuYXNzaWduKHt9LCBleGlzdGluZ0NsYWltcywgaW5mbyk7XG5cbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIEpTT04uc3RyaW5naWZ5KGluZm8pKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3VzZXJfcHJvZmlsZV9sb2FkZWQnKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlc29sdmUoaW5mbyk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgdXNlciBpbmZvJywgZXJyKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogVXNlcyBwcm92aWRlciBhbmQgZXh0ZXJuYWwgdG9rZW4gZm9yIGFuIGFjY2Vzc190b2tlbi5cbiAgICogQHBhcmFtIHByb3ZpZGVyXG4gICAqIEBwYXJhbSBleHRlcm5hbF90b2tlblxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICovXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdVc2luZ0V4dGVybmFsVG9rZW4oXG4gICAgcHJvdmlkZXI6IHN0cmluZyxcbiAgICBleHRlcm5hbF90b2tlbjogc3RyaW5nLFxuICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnRva2VuRW5kcG9pbnQpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICd0b2tlbkVuZHBvaW50IG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICApO1xuICAgIH1cblxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvKipcbiAgICAgICAqIEEgYEh0dHBQYXJhbWV0ZXJDb2RlY2AgdGhhdCB1c2VzIGBlbmNvZGVVUklDb21wb25lbnRgIGFuZCBgZGVjb2RlVVJJQ29tcG9uZW50YCB0b1xuICAgICAgICogc2VyaWFsaXplIGFuZCBwYXJzZSBVUkwgcGFyYW1ldGVyIGtleXMgYW5kIHZhbHVlcy5cbiAgICAgICAqXG4gICAgICAgKiBAc3RhYmxlXG4gICAgICAgKi9cbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7IGVuY29kZXI6IG5ldyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYygpIH0pXG4gICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAnZXh0ZXJuYWwnKVxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgIC5zZXQoJ3Byb3ZpZGVyJywgcHJvdmlkZXIpXG4gICAgICAgIC5zZXQoJ2V4dGVybmFsX3Rva2VuJywgZXh0ZXJuYWxfdG9rZW4pO1xuXG4gICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgIH1cblxuICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICdDb250ZW50LVR5cGUnLFxuICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xuICAgICAgKTtcblxuICAgICAgdGhpcy5odHRwXG4gICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcbiAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGVcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciBwZXJmb3JtaW5nIGV4dGVybmFsIHRva2VuIGZsb3cnLCBlcnIpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCBlcnIpKTtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhbiBhY2Nlc3NfdG9rZW4uXG4gICAqIEBwYXJhbSB1c2VyTmFtZVxuICAgKiBAcGFyYW0gcGFzc3dvcmRcbiAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXG4gICAqL1xuICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KFxuICAgIHVzZXJOYW1lOiBzdHJpbmcsXG4gICAgcGFzc3dvcmQ6IHN0cmluZyxcbiAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcbiAgICAgICd0b2tlbkVuZHBvaW50J1xuICAgICk7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLyoqXG4gICAgICAgKiBBIGBIdHRwUGFyYW1ldGVyQ29kZWNgIHRoYXQgdXNlcyBgZW5jb2RlVVJJQ29tcG9uZW50YCBhbmQgYGRlY29kZVVSSUNvbXBvbmVudGAgdG9cbiAgICAgICAqIHNlcmlhbGl6ZSBhbmQgcGFyc2UgVVJMIHBhcmFtZXRlciBrZXlzIGFuZCB2YWx1ZXMuXG4gICAgICAgKlxuICAgICAgICogQHN0YWJsZVxuICAgICAgICovXG4gICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoeyBlbmNvZGVyOiBuZXcgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMoKSB9KVxuICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3Bhc3N3b3JkJylcbiAgICAgICAgLnNldCgnc2NvcGUnLCB0aGlzLnNjb3BlKVxuICAgICAgICAuc2V0KCd1c2VybmFtZScsIHVzZXJOYW1lKVxuICAgICAgICAuc2V0KCdwYXNzd29yZCcsIHBhc3N3b3JkKTtcblxuICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxuICAgICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICk7XG5cbiAgICAgIHRoaXMuaHR0cFxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxuICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKVxuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHBlcmZvcm1pbmcgcGFzc3dvcmQgZmxvdycsIGVycik7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIGVycikpO1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgfVxuICAgICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFJlZnJlc2hlcyB0aGUgdG9rZW4gdXNpbmcgYSByZWZyZXNoX3Rva2VuLlxuICAgKiBUaGlzIGRvZXMgbm90IHdvcmsgZm9yIGltcGxpY2l0IGZsb3csIGIvY1xuICAgKiB0aGVyZSBpcyBubyByZWZyZXNoX3Rva2VuIGluIHRoaXMgZmxvdy5cbiAgICogQSBzb2x1dGlvbiBmb3IgdGhpcyBpcyBwcm92aWRlZCBieSB0aGVcbiAgICogbWV0aG9kIHNpbGVudFJlZnJlc2guXG4gICAqL1xuICBwdWJsaWMgcmVmcmVzaFRva2VuKCk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcbiAgICAgICd0b2tlbkVuZHBvaW50J1xuICAgICk7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKClcbiAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdyZWZyZXNoX3Rva2VuJylcbiAgICAgICAgLnNldCgnc2NvcGUnLCB0aGlzLnNjb3BlKVxuICAgICAgICAuc2V0KCdyZWZyZXNoX3Rva2VuJywgdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJykpO1xuXG4gICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgICApO1xuXG4gICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgIH1cblxuICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICB0aGlzLmh0dHBcbiAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAucGlwZShcbiAgICAgICAgICBzd2l0Y2hNYXAodG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICBpZiAodG9rZW5SZXNwb25zZS5pZF90b2tlbikge1xuICAgICAgICAgICAgICByZXR1cm4gZnJvbShcbiAgICAgICAgICAgICAgICB0aGlzLnByb2Nlc3NJZFRva2VuKFxuICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5pZF90b2tlbixcbiAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgdHJ1ZVxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgKS5waXBlKFxuICAgICAgICAgICAgICAgIHRhcChyZXN1bHQgPT4gdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KSksXG4gICAgICAgICAgICAgICAgbWFwKF8gPT4gdG9rZW5SZXNwb25zZSlcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHJldHVybiBvZih0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KVxuICAgICAgICApXG4gICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XG4gICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciByZWZyZXNoaW5nIHRva2VuJywgZXJyKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCByZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyKSB7XG4gICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgJ21lc3NhZ2UnLFxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcbiAgICAgICk7XG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgIHRoaXMucmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcblxuICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xuXG4gICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxuICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcbiAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmk6IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmlcbiAgICAgIH0pLmNhdGNoKGVyciA9PiB0aGlzLmRlYnVnKCd0cnlMb2dpbiBkdXJpbmcgc2lsZW50IHJlZnJlc2ggZmFpbGVkJywgZXJyKSk7XG4gICAgfTtcblxuICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKFxuICAgICAgJ21lc3NhZ2UnLFxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXG4gICAgKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBQZXJmb3JtcyBhIHNpbGVudCByZWZyZXNoIGZvciBpbXBsaWNpdCBmbG93LlxuICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gZ2V0IG5ldyB0b2tlbnMgd2hlbi9iZWZvcmVcbiAgICogdGhlIGV4aXN0aW5nIHRva2VucyBleHBpcmUuXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaChcbiAgICBwYXJhbXM6IG9iamVjdCA9IHt9LFxuICAgIG5vUHJvbXB0ID0gdHJ1ZVxuICApOiBQcm9taXNlPE9BdXRoRXZlbnQ+IHtcbiAgICBjb25zdCBjbGFpbXM6IG9iamVjdCA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcblxuICAgIGlmICh0aGlzLnVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaCAmJiB0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICBwYXJhbXNbJ2lkX3Rva2VuX2hpbnQnXSA9IHRoaXMuZ2V0SWRUb2tlbigpO1xuICAgIH1cblxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwibG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZG9jdW1lbnQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3NpbGVudCByZWZyZXNoIGlzIG5vdCBzdXBwb3J0ZWQgb24gdGhpcyBwbGF0Zm9ybScpO1xuICAgIH1cblxuICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXG4gICAgKTtcblxuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xuICAgICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XG4gICAgfVxuXG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IGNsYWltc1snc3ViJ107XG5cbiAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcbiAgICBpZnJhbWUuaWQgPSB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lO1xuXG4gICAgdGhpcy5zZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XG5cbiAgICBjb25zdCByZWRpcmVjdFVyaSA9IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCByZWRpcmVjdFVyaSwgbm9Qcm9tcHQsIHBhcmFtcykudGhlbih1cmwgPT4ge1xuICAgICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcblxuICAgICAgaWYgKCF0aGlzLnNpbGVudFJlZnJlc2hTaG93SUZyYW1lKSB7XG4gICAgICAgIGlmcmFtZS5zdHlsZVsnZGlzcGxheSddID0gJ25vbmUnO1xuICAgICAgfVxuICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xuICAgIH0pO1xuXG4gICAgY29uc3QgZXJyb3JzID0gdGhpcy5ldmVudHMucGlwZShcbiAgICAgIGZpbHRlcihlID0+IGUgaW5zdGFuY2VvZiBPQXV0aEVycm9yRXZlbnQpLFxuICAgICAgZmlyc3QoKVxuICAgICk7XG4gICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxuICAgICAgZmlyc3QoKVxuICAgICk7XG4gICAgY29uc3QgdGltZW91dCA9IG9mKFxuICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfdGltZW91dCcsIG51bGwpXG4gICAgKS5waXBlKGRlbGF5KHRoaXMuc2lsZW50UmVmcmVzaFRpbWVvdXQpKTtcblxuICAgIHJldHVybiByYWNlKFtlcnJvcnMsIHN1Y2Nlc3MsIHRpbWVvdXRdKVxuICAgICAgLnBpcGUoXG4gICAgICAgIG1hcChlID0+IHtcbiAgICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCkge1xuICAgICAgICAgICAgaWYgKGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnKSB7XG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgZSA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ3NpbGVudF9yZWZyZXNoX2Vycm9yJywgZSk7XG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhyb3cgZTtcbiAgICAgICAgICB9IGVsc2UgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xuICAgICAgICAgICAgZSA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnc2lsZW50bHlfcmVmcmVzaGVkJyk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIGU7XG4gICAgICAgIH0pXG4gICAgICApXG4gICAgICAudG9Qcm9taXNlKCk7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBtZXRob2QgZXhpc3RzIGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eS5cbiAgICoge0BsaW5rIE9BdXRoU2VydmljZSNpbml0TG9naW5GbG93SW5Qb3B1cH0gaGFuZGxlcyBib3RoIGNvZGVcbiAgICogYW5kIGltcGxpY2l0IGZsb3dzLlxuICAgKi9cbiAgcHVibGljIGluaXRJbXBsaWNpdEZsb3dJblBvcHVwKG9wdGlvbnM/OiB7XG4gICAgaGVpZ2h0PzogbnVtYmVyO1xuICAgIHdpZHRoPzogbnVtYmVyO1xuICB9KSB7XG4gICAgcmV0dXJuIHRoaXMuaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucyk7XG4gIH1cblxuICBwdWJsaWMgaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucz86IHsgaGVpZ2h0PzogbnVtYmVyOyB3aWR0aD86IG51bWJlciB9KSB7XG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG4gICAgcmV0dXJuIHRoaXMuY3JlYXRlTG9naW5VcmwoXG4gICAgICBudWxsLFxuICAgICAgbnVsbCxcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpLFxuICAgICAgZmFsc2UsXG4gICAgICB7XG4gICAgICAgIGRpc3BsYXk6ICdwb3B1cCdcbiAgICAgIH1cbiAgICApLnRoZW4odXJsID0+IHtcbiAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBFcnJvciBoYW5kbGluZyBzZWN0aW9uXG4gICAgICAgICAqL1xuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWwgPSA1MDA7XG4gICAgICAgIGxldCB3aW5kb3dSZWYgPSB3aW5kb3cub3BlbihcbiAgICAgICAgICB1cmwsXG4gICAgICAgICAgJ19ibGFuaycsXG4gICAgICAgICAgdGhpcy5jYWxjdWxhdGVQb3B1cEZlYXR1cmVzKG9wdGlvbnMpXG4gICAgICAgICk7XG4gICAgICAgIGxldCBjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXI6IGFueTtcbiAgICAgICAgY29uc3QgY2hlY2tGb3JQb3B1cENsb3NlZCA9ICgpID0+IHtcbiAgICAgICAgICBpZiAoIXdpbmRvd1JlZiB8fCB3aW5kb3dSZWYuY2xvc2VkKSB7XG4gICAgICAgICAgICBjbGVhbnVwKCk7XG4gICAgICAgICAgICByZWplY3QobmV3IE9BdXRoRXJyb3JFdmVudCgncG9wdXBfY2xvc2VkJywge30pKTtcbiAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgIGlmICghd2luZG93UmVmKSB7XG4gICAgICAgICAgcmVqZWN0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3BvcHVwX2Jsb2NrZWQnLCB7fSkpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGNoZWNrRm9yUG9wdXBDbG9zZWRUaW1lciA9IHdpbmRvdy5zZXRJbnRlcnZhbChcbiAgICAgICAgICAgIGNoZWNrRm9yUG9wdXBDbG9zZWQsXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWxcbiAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgY2xlYW51cCA9ICgpID0+IHtcbiAgICAgICAgICB3aW5kb3cuY2xlYXJJbnRlcnZhbChjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXIpO1xuICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xuICAgICAgICAgIGlmICh3aW5kb3dSZWYgIT09IG51bGwpIHtcbiAgICAgICAgICAgIHdpbmRvd1JlZi5jbG9zZSgpO1xuICAgICAgICAgIH1cbiAgICAgICAgICB3aW5kb3dSZWYgPSBudWxsO1xuICAgICAgICB9O1xuXG4gICAgICAgIGNvbnN0IGxpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xuXG4gICAgICAgICAgaWYgKG1lc3NhZ2UgJiYgbWVzc2FnZSAhPT0gbnVsbCkge1xuICAgICAgICAgICAgdGhpcy50cnlMb2dpbih7XG4gICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcbiAgICAgICAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXG4gICAgICAgICAgICAgIGN1c3RvbVJlZGlyZWN0VXJpOiB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaVxuICAgICAgICAgICAgfSkudGhlbihcbiAgICAgICAgICAgICAgKCkgPT4ge1xuICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgY2xlYW51cCgpO1xuICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZmFsc2UgZXZlbnQgZmlyaW5nJyk7XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zOiB7XG4gICAgaGVpZ2h0PzogbnVtYmVyO1xuICAgIHdpZHRoPzogbnVtYmVyO1xuICB9KTogc3RyaW5nIHtcbiAgICAvLyBTcGVjaWZ5IGFuIHN0YXRpYyBoZWlnaHQgYW5kIHdpZHRoIGFuZCBjYWxjdWxhdGUgY2VudGVyZWQgcG9zaXRpb25cblxuICAgIGNvbnN0IGhlaWdodCA9IG9wdGlvbnMuaGVpZ2h0IHx8IDQ3MDtcbiAgICBjb25zdCB3aWR0aCA9IG9wdGlvbnMud2lkdGggfHwgNTAwO1xuICAgIGNvbnN0IGxlZnQgPSB3aW5kb3cuc2NyZWVuTGVmdCArICh3aW5kb3cub3V0ZXJXaWR0aCAtIHdpZHRoKSAvIDI7XG4gICAgY29uc3QgdG9wID0gd2luZG93LnNjcmVlblRvcCArICh3aW5kb3cub3V0ZXJIZWlnaHQgLSBoZWlnaHQpIC8gMjtcbiAgICByZXR1cm4gYGxvY2F0aW9uPW5vLHRvb2xiYXI9bm8sd2lkdGg9JHt3aWR0aH0saGVpZ2h0PSR7aGVpZ2h0fSx0b3A9JHt0b3B9LGxlZnQ9JHtsZWZ0fWA7XG4gIH1cblxuICBwcm90ZWN0ZWQgcHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZTogTWVzc2FnZUV2ZW50KTogc3RyaW5nIHtcbiAgICBsZXQgZXhwZWN0ZWRQcmVmaXggPSAnIyc7XG5cbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeCkge1xuICAgICAgZXhwZWN0ZWRQcmVmaXggKz0gdGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeDtcbiAgICB9XG5cbiAgICBpZiAoIWUgfHwgIWUuZGF0YSB8fCB0eXBlb2YgZS5kYXRhICE9PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHByZWZpeGVkTWVzc2FnZTogc3RyaW5nID0gZS5kYXRhO1xuXG4gICAgaWYgKCFwcmVmaXhlZE1lc3NhZ2Uuc3RhcnRzV2l0aChleHBlY3RlZFByZWZpeCkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICByZXR1cm4gJyMnICsgcHJlZml4ZWRNZXNzYWdlLnN1YnN0cihleHBlY3RlZFByZWZpeC5sZW5ndGgpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKTogYm9vbGVhbiB7XG4gICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwpIHtcbiAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgdGhlcmUgaXMgbm8gc2Vzc2lvbkNoZWNrSUZyYW1lVXJsJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcbiAgICBpZiAoIXNlc3Npb25TdGF0ZSkge1xuICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uX3N0YXRlJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG5cbiAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICBjb25zdCBvcmlnaW4gPSBlLm9yaWdpbi50b0xvd2VyQ2FzZSgpO1xuICAgICAgY29uc3QgaXNzdWVyID0gdGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKTtcblxuICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicpO1xuXG4gICAgICBpZiAoIWlzc3Vlci5zdGFydHNXaXRoKG9yaWdpbikpIHtcbiAgICAgICAgdGhpcy5kZWJ1ZyhcbiAgICAgICAgICAnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgJ3dyb25nIG9yaWdpbicsXG4gICAgICAgICAgb3JpZ2luLFxuICAgICAgICAgICdleHBlY3RlZCcsXG4gICAgICAgICAgaXNzdWVyLFxuICAgICAgICAgICdldmVudCcsXG4gICAgICAgICAgZVxuICAgICAgICApO1xuXG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gb25seSBydW4gaW4gQW5ndWxhciB6b25lIGlmIGl0IGlzICdjaGFuZ2VkJyBvciAnZXJyb3InXG4gICAgICBzd2l0Y2ggKGUuZGF0YSkge1xuICAgICAgICBjYXNlICd1bmNoYW5nZWQnOlxuICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdjaGFuZ2VkJzpcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uQ2hhbmdlKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ2Vycm9yJzpcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uRXJyb3IoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBicmVhaztcbiAgICAgIH1cblxuICAgICAgdGhpcy5kZWJ1ZygnZ290IGluZm8gZnJvbSBzZXNzaW9uIGNoZWNrIGluZnJhbWUnLCBlKTtcbiAgICB9O1xuXG4gICAgLy8gcHJldmVudCBBbmd1bGFyIGZyb20gcmVmcmVzaGluZyB0aGUgdmlldyBvbiBldmVyeSBtZXNzYWdlIChydW5zIGluIGludGVydmFscylcbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XG4gICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpOiB2b2lkIHtcbiAgICB0aGlzLmRlYnVnKCdzZXNzaW9uIGNoZWNrJywgJ3Nlc3Npb24gdW5jaGFuZ2VkJyk7XG4gIH1cblxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcbiAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fY2hhbmdlZCcpKTtcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuXG4gICAgaWYgKCF0aGlzLnVzZVNpbGVudFJlZnJlc2ggJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgdGhpcy5yZWZyZXNoVG9rZW4oKVxuICAgICAgICAudGhlbihfID0+IHtcbiAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlbiByZWZyZXNoIGFmdGVyIHNlc3Npb24gY2hhbmdlIHdvcmtlZCcpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW4gcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgIH0pO1xuICAgIH0gZWxzZSBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkpIHtcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaCgpLmNhdGNoKF8gPT5cbiAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZmFpbGVkIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpXG4gICAgICApO1xuICAgICAgdGhpcy53YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCB3YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcbiAgICB0aGlzLmV2ZW50c1xuICAgICAgLnBpcGUoXG4gICAgICAgIGZpbHRlcihcbiAgICAgICAgICAoZTogT0F1dGhFdmVudCkgPT5cbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcgfHxcbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnIHx8XG4gICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF9lcnJvcidcbiAgICAgICAgKSxcbiAgICAgICAgZmlyc3QoKVxuICAgICAgKVxuICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgaWYgKGUudHlwZSAhPT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcpIHtcbiAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25FcnJvcigpOiB2b2lkIHtcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9lcnJvcicpKTtcbiAgfVxuXG4gIHByb3RlY3RlZCByZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpIHtcbiAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIGluaXRTZXNzaW9uQ2hlY2soKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLmNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcbiAgICBpZiAoZXhpc3RpbmdJZnJhbWUpIHtcbiAgICAgIGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZXhpc3RpbmdJZnJhbWUpO1xuICAgIH1cblxuICAgIGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZTtcblxuICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG5cbiAgICBjb25zdCB1cmwgPSB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcbiAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xuICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xuICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoaWZyYW1lKTtcblxuICAgIHRoaXMuc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICB9XG5cbiAgcHJvdGVjdGVkIHN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XG4gICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gc2V0SW50ZXJ2YWwoXG4gICAgICAgIHRoaXMuY2hlY2tTZXNzaW9uLmJpbmQodGhpcyksXG4gICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSW50ZXJ2YWxsXG4gICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIHN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLnNlc3Npb25DaGVja1RpbWVyKTtcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHB1YmxpYyBjaGVja1Nlc3Npb24oKTogdm9pZCB7XG4gICAgY29uc3QgaWZyYW1lOiBhbnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xuXG4gICAgaWYgKCFpZnJhbWUpIHtcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICdjaGVja1Nlc3Npb24gZGlkIG5vdCBmaW5kIGlmcmFtZScsXG4gICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxuICAgICAgKTtcbiAgICB9XG5cbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xuXG4gICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcbiAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgfVxuXG4gICAgY29uc3QgbWVzc2FnZSA9IHRoaXMuY2xpZW50SWQgKyAnICcgKyBzZXNzaW9uU3RhdGU7XG4gICAgaWZyYW1lLmNvbnRlbnRXaW5kb3cucG9zdE1lc3NhZ2UobWVzc2FnZSwgdGhpcy5pc3N1ZXIpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUxvZ2luVXJsKFxuICAgIHN0YXRlID0gJycsXG4gICAgbG9naW5IaW50ID0gJycsXG4gICAgY3VzdG9tUmVkaXJlY3RVcmkgPSAnJyxcbiAgICBub1Byb21wdCA9IGZhbHNlLFxuICAgIHBhcmFtczogb2JqZWN0ID0ge31cbiAgKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCB0aGF0ID0gdGhpcztcblxuICAgIGxldCByZWRpcmVjdFVyaTogc3RyaW5nO1xuXG4gICAgaWYgKGN1c3RvbVJlZGlyZWN0VXJpKSB7XG4gICAgICByZWRpcmVjdFVyaSA9IGN1c3RvbVJlZGlyZWN0VXJpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZWRpcmVjdFVyaSA9IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgfVxuXG4gICAgY29uc3Qgbm9uY2UgPSBhd2FpdCB0aGlzLmNyZWF0ZUFuZFNhdmVOb25jZSgpO1xuXG4gICAgaWYgKHN0YXRlKSB7XG4gICAgICBzdGF0ZSA9XG4gICAgICAgIG5vbmNlICsgdGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvciArIGVuY29kZVVSSUNvbXBvbmVudChzdGF0ZSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0YXRlID0gbm9uY2U7XG4gICAgfVxuXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyBvciBib3RoIG11c3QgYmUgdHJ1ZScpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLmNvbmZpZy5yZXNwb25zZVR5cGUpIHtcbiAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gdGhpcy5jb25maWcucmVzcG9uc2VUeXBlO1xuICAgIH0gZWxzZSB7XG4gICAgICBpZiAodGhpcy5vaWRjICYmIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuIHRva2VuJztcbiAgICAgIH0gZWxzZSBpZiAodGhpcy5vaWRjICYmICF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbic7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICd0b2tlbic7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3Qgc2VwZXJhdGlvbkNoYXIgPSB0aGF0LmxvZ2luVXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nO1xuXG4gICAgbGV0IHNjb3BlID0gdGhhdC5zY29wZTtcblxuICAgIGlmICh0aGlzLm9pZGMgJiYgIXNjb3BlLm1hdGNoKC8oXnxcXHMpb3BlbmlkKCR8XFxzKS8pKSB7XG4gICAgICBzY29wZSA9ICdvcGVuaWQgJyArIHNjb3BlO1xuICAgIH1cblxuICAgIGxldCB1cmwgPVxuICAgICAgdGhhdC5sb2dpblVybCArXG4gICAgICBzZXBlcmF0aW9uQ2hhciArXG4gICAgICAncmVzcG9uc2VfdHlwZT0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LnJlc3BvbnNlVHlwZSkgK1xuICAgICAgJyZjbGllbnRfaWQ9JyArXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5jbGllbnRJZCkgK1xuICAgICAgJyZzdGF0ZT0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzdGF0ZSkgK1xuICAgICAgJyZyZWRpcmVjdF91cmk9JyArXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICtcbiAgICAgICcmc2NvcGU9JyArXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQoc2NvcGUpO1xuXG4gICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScgJiYgIXRoaXMuZGlzYWJsZVBLQ0UpIHtcbiAgICAgIGNvbnN0IFtcbiAgICAgICAgY2hhbGxlbmdlLFxuICAgICAgICB2ZXJpZmllclxuICAgICAgXSA9IGF3YWl0IHRoaXMuY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpO1xuXG4gICAgICBpZiAoXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXG4gICAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xuICAgICAgKSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xuICAgICAgfVxuXG4gICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZT0nICsgY2hhbGxlbmdlO1xuICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2VfbWV0aG9kPVMyNTYnO1xuICAgIH1cblxuICAgIGlmIChsb2dpbkhpbnQpIHtcbiAgICAgIHVybCArPSAnJmxvZ2luX2hpbnQ9JyArIGVuY29kZVVSSUNvbXBvbmVudChsb2dpbkhpbnQpO1xuICAgIH1cblxuICAgIGlmICh0aGF0LnJlc291cmNlKSB7XG4gICAgICB1cmwgKz0gJyZyZXNvdXJjZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzb3VyY2UpO1xuICAgIH1cblxuICAgIGlmICh0aGF0Lm9pZGMpIHtcbiAgICAgIHVybCArPSAnJm5vbmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQobm9uY2UpO1xuICAgIH1cblxuICAgIGlmIChub1Byb21wdCkge1xuICAgICAgdXJsICs9ICcmcHJvbXB0PW5vbmUnO1xuICAgIH1cblxuICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKHBhcmFtcykpIHtcbiAgICAgIHVybCArPVxuICAgICAgICAnJicgKyBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudChwYXJhbXNba2V5XSk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgIHVybCArPVxuICAgICAgICAgICcmJyArIGtleSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB1cmw7XG4gIH1cblxuICBpbml0SW1wbGljaXRGbG93SW50ZXJuYWwoXG4gICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgcGFyYW1zOiBzdHJpbmcgfCBvYmplY3QgPSAnJ1xuICApOiB2b2lkIHtcbiAgICBpZiAodGhpcy5pbkltcGxpY2l0Rmxvdykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSB0cnVlO1xuXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgXCJsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcbiAgICAgICk7XG4gICAgfVxuXG4gICAgbGV0IGFkZFBhcmFtczogb2JqZWN0ID0ge307XG4gICAgbGV0IGxvZ2luSGludDogc3RyaW5nID0gbnVsbDtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zID09PSAnc3RyaW5nJykge1xuICAgICAgbG9naW5IaW50ID0gcGFyYW1zO1xuICAgIH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ29iamVjdCcpIHtcbiAgICAgIGFkZFBhcmFtcyA9IHBhcmFtcztcbiAgICB9XG5cbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKGFkZGl0aW9uYWxTdGF0ZSwgbG9naW5IaW50LCBudWxsLCBmYWxzZSwgYWRkUGFyYW1zKVxuICAgICAgLnRoZW4odGhpcy5jb25maWcub3BlblVyaSlcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRJbXBsaWNpdEZsb3cnLCBlcnJvcik7XG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFN0YXJ0cyB0aGUgaW1wbGljaXQgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cbiAgICogdGhlIGF1dGggc2VydmVycycgbG9naW4gdXJsLlxuICAgKlxuICAgKiBAcGFyYW0gYWRkaXRpb25hbFN0YXRlIE9wdGlvbmFsIHN0YXRlIHRoYXQgaXMgcGFzc2VkIGFyb3VuZC5cbiAgICogIFlvdSdsbCBmaW5kIHRoaXMgc3RhdGUgaW4gdGhlIHByb3BlcnR5IGBzdGF0ZWAgYWZ0ZXIgYHRyeUxvZ2luYCBsb2dnZWQgaW4gdGhlIHVzZXIuXG4gICAqIEBwYXJhbSBwYXJhbXMgSGFzaCB3aXRoIGFkZGl0aW9uYWwgcGFyYW1ldGVyLiBJZiBpdCBpcyBhIHN0cmluZywgaXQgaXMgdXNlZCBmb3IgdGhlXG4gICAqICAgICAgICAgICAgICAgcGFyYW1ldGVyIGxvZ2luSGludCAoZm9yIHRoZSBzYWtlIG9mIGNvbXBhdGliaWxpdHkgd2l0aCBmb3JtZXIgdmVyc2lvbnMpXG4gICAqL1xuICBwdWJsaWMgaW5pdEltcGxpY2l0RmxvdyhcbiAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXG4gICk6IHZvaWQge1xuICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xuICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmV2ZW50c1xuICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgIC5zdWJzY3JpYmUoXyA9PiB0aGlzLmluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcykpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXNldCBjdXJyZW50IGltcGxpY2l0IGZsb3dcbiAgICpcbiAgICogQGRlc2NyaXB0aW9uIFRoaXMgbWV0aG9kIGFsbG93cyByZXNldHRpbmcgdGhlIGN1cnJlbnQgaW1wbGljdCBmbG93IGluIG9yZGVyIHRvIGJlIGluaXRpYWxpemVkIGFnYWluLlxuICAgKi9cbiAgcHVibGljIHJlc2V0SW1wbGljaXRGbG93KCk6IHZvaWQge1xuICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgfVxuXG4gIHByb3RlY3RlZCBjYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9uczogTG9naW5PcHRpb25zKTogdm9pZCB7XG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XG4gICAgaWYgKG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKSB7XG4gICAgICBjb25zdCB0b2tlblBhcmFtcyA9IHtcbiAgICAgICAgaWRDbGFpbXM6IHRoYXQuZ2V0SWRlbnRpdHlDbGFpbXMoKSxcbiAgICAgICAgaWRUb2tlbjogdGhhdC5nZXRJZFRva2VuKCksXG4gICAgICAgIGFjY2Vzc1Rva2VuOiB0aGF0LmdldEFjY2Vzc1Rva2VuKCksXG4gICAgICAgIHN0YXRlOiB0aGF0LnN0YXRlXG4gICAgICB9O1xuICAgICAgb3B0aW9ucy5vblRva2VuUmVjZWl2ZWQodG9rZW5QYXJhbXMpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBzdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgYWNjZXNzVG9rZW46IHN0cmluZyxcbiAgICByZWZyZXNoVG9rZW46IHN0cmluZyxcbiAgICBleHBpcmVzSW46IG51bWJlcixcbiAgICBncmFudGVkU2NvcGVzOiBTdHJpbmcsXG4gICAgY3VzdG9tUGFyYW1ldGVycz86IE1hcDxzdHJpbmcsIHN0cmluZz5cbiAgKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW4nLCBhY2Nlc3NUb2tlbik7XG4gICAgaWYgKGdyYW50ZWRTY29wZXMgJiYgIUFycmF5LmlzQXJyYXkoZ3JhbnRlZFNjb3BlcykpIHtcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShcbiAgICAgICAgJ2dyYW50ZWRfc2NvcGVzJyxcbiAgICAgICAgSlNPTi5zdHJpbmdpZnkoZ3JhbnRlZFNjb3Blcy5zcGxpdCgnKycpKVxuICAgICAgKTtcbiAgICB9IGVsc2UgaWYgKGdyYW50ZWRTY29wZXMgJiYgQXJyYXkuaXNBcnJheShncmFudGVkU2NvcGVzKSkge1xuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdncmFudGVkX3Njb3BlcycsIEpTT04uc3RyaW5naWZ5KGdyYW50ZWRTY29wZXMpKTtcbiAgICB9XG5cbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xuICAgIGlmIChleHBpcmVzSW4pIHtcbiAgICAgIGNvbnN0IGV4cGlyZXNJbk1pbGxpU2Vjb25kcyA9IGV4cGlyZXNJbiAqIDEwMDA7XG4gICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gbm93LmdldFRpbWUoKSArIGV4cGlyZXNJbk1pbGxpU2Vjb25kcztcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZXhwaXJlc19hdCcsICcnICsgZXhwaXJlc0F0KTtcbiAgICB9XG5cbiAgICBpZiAocmVmcmVzaFRva2VuKSB7XG4gICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nLCByZWZyZXNoVG9rZW4pO1xuICAgIH1cbiAgICBpZiAoY3VzdG9tUGFyYW1ldGVycykge1xuICAgICAgY3VzdG9tUGFyYW1ldGVycy5mb3JFYWNoKCh2YWx1ZTogc3RyaW5nLCBrZXk6IHN0cmluZykgPT4ge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oa2V5LCB2YWx1ZSk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogRGVsZWdhdGVzIHRvIHRyeUxvZ2luSW1wbGljaXRGbG93IGZvciB0aGUgc2FrZSBvZiBjb21wZXRhYmlsaXR5XG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXG4gICAqL1xuICBwdWJsaWMgdHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGlmICh0aGlzLmNvbmZpZy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5Db2RlRmxvdyhvcHRpb25zKS50aGVuKF8gPT4gdHJ1ZSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luSW1wbGljaXRGbG93KG9wdGlvbnMpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xuICAgICAgcmV0dXJuIHt9O1xuICAgIH1cblxuICAgIGlmIChxdWVyeVN0cmluZy5jaGFyQXQoMCkgPT09ICc/Jykge1xuICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLnBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmcpO1xuICB9XG5cbiAgcHVibGljIHRyeUxvZ2luQ29kZUZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8dm9pZD4ge1xuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gICAgY29uc3QgcXVlcnlTb3VyY2UgPSBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudFxuICAgICAgPyBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudC5zdWJzdHJpbmcoMSlcbiAgICAgIDogd2luZG93LmxvY2F0aW9uLnNlYXJjaDtcblxuICAgIGNvbnN0IHBhcnRzID0gdGhpcy5nZXRDb2RlUGFydHNGcm9tVXJsKHF1ZXJ5U291cmNlKTtcblxuICAgIGNvbnN0IGNvZGUgPSBwYXJ0c1snY29kZSddO1xuICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XG5cbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSBwYXJ0c1snc2Vzc2lvbl9zdGF0ZSddO1xuXG4gICAgaWYgKCFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICBjb25zdCBocmVmID0gbG9jYXRpb24uaHJlZlxuICAgICAgICAucmVwbGFjZSgvWyZcXD9dY29kZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAucmVwbGFjZSgvWyZcXD9dc2NvcGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgLnJlcGxhY2UoL1smXFw/XXN0YXRlPVteJlxcJF0qLywgJycpXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zZXNzaW9uX3N0YXRlPVteJlxcJF0qLywgJycpO1xuXG4gICAgICBoaXN0b3J5LnJlcGxhY2VTdGF0ZShudWxsLCB3aW5kb3cubmFtZSwgaHJlZik7XG4gICAgfVxuXG4gICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xuICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XG5cbiAgICBpZiAocGFydHNbJ2Vycm9yJ10pIHtcbiAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xuICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKHt9LCBwYXJ0cyk7XG4gICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdjb2RlX2Vycm9yJywge30sIHBhcnRzKTtcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBpZiAoIW5vbmNlSW5TdGF0ZSkge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgIH1cblxuICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLnZhbGlkYXRlTm9uY2Uobm9uY2VJblN0YXRlKTtcbiAgICBpZiAoIXN1Y2Nlc3MpIHtcbiAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnaW52YWxpZF9ub25jZV9pbl9zdGF0ZScsIG51bGwpO1xuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcbiAgICB9XG5cbiAgICB0aGlzLnN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZSk7XG5cbiAgICBpZiAoY29kZSkge1xuICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW5Gcm9tQ29kZShjb2RlLCBvcHRpb25zKS50aGVuKF8gPT4gbnVsbCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmV0cmlldmUgdGhlIHJldHVybmVkIGF1dGggY29kZSBmcm9tIHRoZSByZWRpcmVjdCB1cmkgdGhhdCBoYXMgYmVlbiBjYWxsZWQuXG4gICAqIElmIHJlcXVpcmVkIGFsc28gY2hlY2sgaGFzaCwgYXMgd2UgY291bGQgdXNlIGhhc2ggbG9jYXRpb24gc3RyYXRlZ3kuXG4gICAqL1xuICBwcml2YXRlIGdldENvZGVQYXJ0c0Zyb21VcmwocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XG4gICAgaWYgKCFxdWVyeVN0cmluZyB8fCBxdWVyeVN0cmluZy5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcbiAgICB9XG5cbiAgICAvLyBub3JtYWxpemUgcXVlcnkgc3RyaW5nXG4gICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XG4gICAgICBxdWVyeVN0cmluZyA9IHF1ZXJ5U3RyaW5nLnN1YnN0cigxKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRva2VuIHVzaW5nIGFuIGludGVybWVkaWF0ZSBjb2RlLiBXb3JrcyBmb3IgdGhlIEF1dGhvcml6YXRpb24gQ29kZSBmbG93LlxuICAgKi9cbiAgcHJpdmF0ZSBnZXRUb2tlbkZyb21Db2RlKFxuICAgIGNvZGU6IHN0cmluZyxcbiAgICBvcHRpb25zOiBMb2dpbk9wdGlvbnNcbiAgKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxuICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdhdXRob3JpemF0aW9uX2NvZGUnKVxuICAgICAgLnNldCgnY29kZScsIGNvZGUpXG4gICAgICAuc2V0KCdyZWRpcmVjdF91cmknLCBvcHRpb25zLmN1c3RvbVJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmkpO1xuXG4gICAgaWYgKCF0aGlzLmRpc2FibGVQS0NFKSB7XG4gICAgICBsZXQgcGtjaVZlcmlmaWVyO1xuXG4gICAgICBpZiAoXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXG4gICAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xuICAgICAgKSB7XG4gICAgICAgIHBrY2lWZXJpZmllciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBwa2NpVmVyaWZpZXIgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCFwa2NpVmVyaWZpZXIpIHtcbiAgICAgICAgY29uc29sZS53YXJuKCdObyBQS0NJIHZlcmlmaWVyIGZvdW5kIGluIG9hdXRoIHN0b3JhZ2UhJyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjb2RlX3ZlcmlmaWVyJywgcGtjaVZlcmlmaWVyKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5mZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXMpO1xuICB9XG5cbiAgcHJpdmF0ZSBmZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXM6IEh0dHBQYXJhbXMpOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcbiAgICB0aGlzLmFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2woXG4gICAgICB0aGlzLnRva2VuRW5kcG9pbnQsXG4gICAgICAndG9rZW5FbmRwb2ludCdcbiAgICApO1xuICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxuICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xuICAgICk7XG5cbiAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICB9XG5cbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgfVxuXG4gICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgIH1cblxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICBmb3IgKGxldCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICB0aGlzLmh0dHBcbiAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygncmVmcmVzaCB0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxuICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKVxuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgaWYgKHRoaXMub2lkYyAmJiB0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4oXG4gICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5pZF90b2tlbixcbiAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlblxuICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG5cbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJylcbiAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKVxuICAgICAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xuICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pXG4gICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IocmVhc29uKTtcblxuICAgICAgICAgICAgICAgICAgcmVqZWN0KHJlYXNvbik7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcblxuICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGdldHRpbmcgdG9rZW4nLCBlcnIpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3JlZnJlc2hfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgfVxuICAgICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGFyZSB0b2tlbnMgaW4gdGhlIGhhc2ggZnJhZ21lbnRcbiAgICogYXMgYSByZXN1bHQgb2YgdGhlIGltcGxpY2l0IGZsb3cuIFRoZXNlIHRva2VucyBhcmVcbiAgICogcGFyc2VkLCB2YWxpZGF0ZWQgYW5kIHVzZWQgdG8gc2lnbiB0aGUgdXNlciBpbiB0byB0aGVcbiAgICogY3VycmVudCBjbGllbnQuXG4gICAqXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXG4gICAqL1xuICBwdWJsaWMgdHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gICAgbGV0IHBhcnRzOiBvYmplY3Q7XG5cbiAgICBpZiAob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpIHtcbiAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50KTtcbiAgICB9IGVsc2Uge1xuICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcbiAgICB9XG5cbiAgICB0aGlzLmRlYnVnKCdwYXJzZWQgdXJsJywgcGFydHMpO1xuXG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcbiAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xuXG4gICAgaWYgKHBhcnRzWydlcnJvciddKSB7XG4gICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcbiAgICAgIHRoaXMuaGFuZGxlTG9naW5FcnJvcihvcHRpb25zLCBwYXJ0cyk7XG4gICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIHt9LCBwYXJ0cyk7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSBwYXJ0c1snYWNjZXNzX3Rva2VuJ107XG4gICAgY29uc3QgaWRUb2tlbiA9IHBhcnRzWydpZF90b2tlbiddO1xuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XG4gICAgY29uc3QgZ3JhbnRlZFNjb3BlcyA9IHBhcnRzWydzY29wZSddO1xuXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgICdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgKG9yIGJvdGgpIG11c3QgYmUgdHJ1ZS4nXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYWNjZXNzVG9rZW4pIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgIH1cbiAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICB9XG4gICAgaWYgKHRoaXMub2lkYyAmJiAhaWRUb2tlbikge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiYgIXNlc3Npb25TdGF0ZSkge1xuICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcbiAgICAgICAgICAnd2VyZSBhY3RpdmF0ZWQgaW4gdGhlIGNvbmZpZ3VyYXRpb24gYnV0IHRoZSBpZF90b2tlbiAnICtcbiAgICAgICAgICAnZG9lcyBub3QgY29udGFpbiBhIHNlc3Npb25fc3RhdGUgY2xhaW0nXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjaykge1xuICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMudmFsaWRhdGVOb25jZShub25jZUluU3RhdGUpO1xuXG4gICAgICBpZiAoIXN1Y2Nlc3MpIHtcbiAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICBhY2Nlc3NUb2tlbixcbiAgICAgICAgbnVsbCxcbiAgICAgICAgcGFydHNbJ2V4cGlyZXNfaW4nXSB8fCB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxuICAgICAgICBncmFudGVkU2NvcGVzXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICghdGhpcy5vaWRjKSB7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XG4gICAgICB9XG5cbiAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0cnVlKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5wcm9jZXNzSWRUb2tlbihpZFRva2VuLCBhY2Nlc3NUb2tlbilcbiAgICAgIC50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgIGlmIChvcHRpb25zLnZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICAgICAgcmV0dXJuIG9wdGlvbnNcbiAgICAgICAgICAgIC52YWxpZGF0aW9uSGFuZGxlcih7XG4gICAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgICAgaWRDbGFpbXM6IHJlc3VsdC5pZFRva2VuQ2xhaW1zLFxuICAgICAgICAgICAgICBpZFRva2VuOiByZXN1bHQuaWRUb2tlbixcbiAgICAgICAgICAgICAgc3RhdGU6IHN0YXRlXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4oXyA9PiByZXN1bHQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICB9KVxuICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcbiAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xuICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKVxuICAgICAgICApO1xuICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IocmVhc29uKTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XG4gICAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgcGFyc2VTdGF0ZShzdGF0ZTogc3RyaW5nKTogW3N0cmluZywgc3RyaW5nXSB7XG4gICAgbGV0IG5vbmNlID0gc3RhdGU7XG4gICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xuXG4gICAgaWYgKHN0YXRlKSB7XG4gICAgICBjb25zdCBpZHggPSBzdGF0ZS5pbmRleE9mKHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IpO1xuICAgICAgaWYgKGlkeCA+IC0xKSB7XG4gICAgICAgIG5vbmNlID0gc3RhdGUuc3Vic3RyKDAsIGlkeCk7XG4gICAgICAgIHVzZXJTdGF0ZSA9IHN0YXRlLnN1YnN0cihpZHggKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yLmxlbmd0aCk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBbbm9uY2UsIHVzZXJTdGF0ZV07XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVOb25jZShub25jZUluU3RhdGU6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIGxldCBzYXZlZE5vbmNlO1xuXG4gICAgaWYgKFxuICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcbiAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xuICAgICkge1xuICAgICAgc2F2ZWROb25jZSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuICAgIH0gZWxzZSB7XG4gICAgICBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuICAgIH1cblxuICAgIGlmIChzYXZlZE5vbmNlICE9PSBub25jZUluU3RhdGUpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdWYWxpZGF0aW5nIGFjY2Vzc190b2tlbiBmYWlsZWQsIHdyb25nIHN0YXRlL25vbmNlLic7XG4gICAgICBjb25zb2xlLmVycm9yKGVyciwgc2F2ZWROb25jZSwgbm9uY2VJblN0YXRlKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBwcm90ZWN0ZWQgc3RvcmVJZFRva2VuKGlkVG9rZW46IFBhcnNlZElkVG9rZW4pOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuJywgaWRUb2tlbi5pZFRva2VuKTtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBpZFRva2VuLmlkVG9rZW5DbGFpbXNKc29uKTtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnLCAnJyArIGlkVG9rZW4uaWRUb2tlbkV4cGlyZXNBdCk7XG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xuICB9XG5cbiAgcHJvdGVjdGVkIHN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZTogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdzZXNzaW9uX3N0YXRlJywgc2Vzc2lvblN0YXRlKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBnZXRTZXNzaW9uU3RhdGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG4gIH1cblxuICBwcm90ZWN0ZWQgaGFuZGxlTG9naW5FcnJvcihvcHRpb25zOiBMb2dpbk9wdGlvbnMsIHBhcnRzOiBvYmplY3QpOiB2b2lkIHtcbiAgICBpZiAob3B0aW9ucy5vbkxvZ2luRXJyb3IpIHtcbiAgICAgIG9wdGlvbnMub25Mb2dpbkVycm9yKHBhcnRzKTtcbiAgICB9XG4gICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBAaWdub3JlXG4gICAqL1xuICBwdWJsaWMgcHJvY2Vzc0lkVG9rZW4oXG4gICAgaWRUb2tlbjogc3RyaW5nLFxuICAgIGFjY2Vzc1Rva2VuOiBzdHJpbmcsXG4gICAgc2tpcE5vbmNlQ2hlY2sgPSBmYWxzZVxuICApOiBQcm9taXNlPFBhcnNlZElkVG9rZW4+IHtcbiAgICBjb25zdCB0b2tlblBhcnRzID0gaWRUb2tlbi5zcGxpdCgnLicpO1xuICAgIGNvbnN0IGhlYWRlckJhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMF0pO1xuICAgIGNvbnN0IGhlYWRlckpzb24gPSBiNjREZWNvZGVVbmljb2RlKGhlYWRlckJhc2U2NCk7XG4gICAgY29uc3QgaGVhZGVyID0gSlNPTi5wYXJzZShoZWFkZXJKc29uKTtcbiAgICBjb25zdCBjbGFpbXNCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzFdKTtcbiAgICBjb25zdCBjbGFpbXNKc29uID0gYjY0RGVjb2RlVW5pY29kZShjbGFpbXNCYXNlNjQpO1xuICAgIGNvbnN0IGNsYWltcyA9IEpTT04ucGFyc2UoY2xhaW1zSnNvbik7XG5cbiAgICBsZXQgc2F2ZWROb25jZTtcbiAgICBpZiAoXG4gICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxuICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgKSB7XG4gICAgICBzYXZlZE5vbmNlID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHNhdmVkTm9uY2UgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG4gICAgfVxuXG4gICAgaWYgKEFycmF5LmlzQXJyYXkoY2xhaW1zLmF1ZCkpIHtcbiAgICAgIGlmIChjbGFpbXMuYXVkLmV2ZXJ5KHYgPT4gdiAhPT0gdGhpcy5jbGllbnRJZCkpIHtcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZC5qb2luKCcsJyk7XG4gICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChjbGFpbXMuYXVkICE9PSB0aGlzLmNsaWVudElkKSB7XG4gICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQ7XG4gICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCFjbGFpbXMuc3ViKSB7XG4gICAgICBjb25zdCBlcnIgPSAnTm8gc3ViIGNsYWltIGluIGlkX3Rva2VuJztcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cblxuICAgIC8qIEZvciBub3csIHdlIG9ubHkgY2hlY2sgd2hldGhlciB0aGUgc3ViIGFnYWluc3RcbiAgICAgKiBzaWxlbnRSZWZyZXNoU3ViamVjdCB3aGVuIHNlc3Npb25DaGVja3NFbmFibGVkIGlzIG9uXG4gICAgICogV2Ugd2lsbCByZWNvbnNpZGVyIGluIGEgbGF0ZXIgdmVyc2lvbiB0byBkbyB0aGlzXG4gICAgICogaW4gZXZlcnkgb3RoZXIgY2FzZSB0b28uXG4gICAgICovXG4gICAgaWYgKFxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAmJlxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAhPT0gY2xhaW1zWydzdWInXVxuICAgICkge1xuICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgJ0FmdGVyIHJlZnJlc2hpbmcsIHdlIGdvdCBhbiBpZF90b2tlbiBmb3IgYW5vdGhlciB1c2VyIChzdWIpLiAnICtcbiAgICAgICAgYEV4cGVjdGVkIHN1YjogJHt0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0fSwgcmVjZWl2ZWQgc3ViOiAke2NsYWltc1snc3ViJ119YDtcblxuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgaWYgKCFjbGFpbXMuaWF0KSB7XG4gICAgICBjb25zdCBlcnIgPSAnTm8gaWF0IGNsYWltIGluIGlkX3Rva2VuJztcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cblxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBpc3N1ZXI6ICcgKyBjbGFpbXMuaXNzO1xuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgaWYgKCFza2lwTm9uY2VDaGVjayAmJiBjbGFpbXMubm9uY2UgIT09IHNhdmVkTm9uY2UpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBub25jZTogJyArIGNsYWltcy5ub25jZTtcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cbiAgICAvLyBhdF9oYXNoIGlzIG5vdCBhcHBsaWNhYmxlIHRvIGF1dGhvcml6YXRpb24gY29kZSBmbG93XG4gICAgLy8gYWRkcmVzc2luZyBodHRwczovL2dpdGh1Yi5jb20vbWFuZnJlZHN0ZXllci9hbmd1bGFyLW9hdXRoMi1vaWRjL2lzc3Vlcy82NjFcbiAgICAvLyBpLmUuIEJhc2VkIG9uIHNwZWMgdGhlIGF0X2hhc2ggY2hlY2sgaXMgb25seSB0cnVlIGZvciBpbXBsaWNpdCBjb2RlIGZsb3cgb24gUGluZyBGZWRlcmF0ZVxuICAgIC8vIGh0dHBzOi8vd3d3LnBpbmdpZGVudGl0eS5jb20vZGV2ZWxvcGVyL2VuL3Jlc291cmNlcy9vcGVuaWQtY29ubmVjdC1kZXZlbG9wZXJzLWd1aWRlLmh0bWxcbiAgICBpZiAodGhpcy5oYXNPd25Qcm9wZXJ0eSgncmVzcG9uc2VUeXBlJykgJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgPSB0cnVlO1xuICAgIH1cbiAgICBpZiAoXG4gICAgICAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiZcbiAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXG4gICAgICAhY2xhaW1zWydhdF9oYXNoJ11cbiAgICApIHtcbiAgICAgIGNvbnN0IGVyciA9ICdBbiBhdF9oYXNoIGlzIG5lZWRlZCEnO1xuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICBjb25zdCBpc3N1ZWRBdE1TZWMgPSBjbGFpbXMuaWF0ICogMTAwMDtcbiAgICBjb25zdCBleHBpcmVzQXRNU2VjID0gY2xhaW1zLmV4cCAqIDEwMDA7XG4gICAgY29uc3QgY2xvY2tTa2V3SW5NU2VjID0gKHRoaXMuY2xvY2tTa2V3SW5TZWMgfHwgNjAwKSAqIDEwMDA7XG5cbiAgICBpZiAoXG4gICAgICBpc3N1ZWRBdE1TZWMgLSBjbG9ja1NrZXdJbk1TZWMgPj0gbm93IHx8XG4gICAgICBleHBpcmVzQXRNU2VjICsgY2xvY2tTa2V3SW5NU2VjIDw9IG5vd1xuICAgICkge1xuICAgICAgY29uc3QgZXJyID0gJ1Rva2VuIGhhcyBleHBpcmVkJztcbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyKTtcbiAgICAgIGNvbnNvbGUuZXJyb3Ioe1xuICAgICAgICBub3c6IG5vdyxcbiAgICAgICAgaXNzdWVkQXRNU2VjOiBpc3N1ZWRBdE1TZWMsXG4gICAgICAgIGV4cGlyZXNBdE1TZWM6IGV4cGlyZXNBdE1TZWNcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgY29uc3QgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyA9IHtcbiAgICAgIGFjY2Vzc1Rva2VuOiBhY2Nlc3NUb2tlbixcbiAgICAgIGlkVG9rZW46IGlkVG9rZW4sXG4gICAgICBqd2tzOiB0aGlzLmp3a3MsXG4gICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICBsb2FkS2V5czogKCkgPT4gdGhpcy5sb2FkSndrcygpXG4gICAgfTtcblxuICAgIGlmICh0aGlzLmRpc2FibGVBdEhhc2hDaGVjaykge1xuICAgICAgcmV0dXJuIHRoaXMuY2hlY2tTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtcykudGhlbihfID0+IHtcbiAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xuICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXG4gICAgICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxuICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxuICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcbiAgICAgICAgICBpZFRva2VuSGVhZGVySnNvbjogaGVhZGVySnNvbixcbiAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5jaGVja0F0SGFzaCh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKGF0SGFzaFZhbGlkID0+IHtcbiAgICAgIGlmICghdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWF0SGFzaFZhbGlkKSB7XG4gICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdF9oYXNoJztcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHRoaXMuY2hlY2tTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtcykudGhlbihfID0+IHtcbiAgICAgICAgY29uc3QgYXRIYXNoQ2hlY2tFbmFibGVkID0gIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrO1xuICAgICAgICBjb25zdCByZXN1bHQ6IFBhcnNlZElkVG9rZW4gPSB7XG4gICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgaWRUb2tlbkNsYWltc0pzb246IGNsYWltc0pzb24sXG4gICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxuICAgICAgICAgIGlkVG9rZW5FeHBpcmVzQXQ6IGV4cGlyZXNBdE1TZWNcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKGF0SGFzaENoZWNrRW5hYmxlZCkge1xuICAgICAgICAgIHJldHVybiB0aGlzLmNoZWNrQXRIYXNoKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oYXRIYXNoVmFsaWQgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhdEhhc2hWYWxpZCkge1xuICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXRfaGFzaCc7XG4gICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIHJlY2VpdmVkIGNsYWltcyBhYm91dCB0aGUgdXNlci5cbiAgICovXG4gIHB1YmxpYyBnZXRJZGVudGl0eUNsYWltcygpOiBvYmplY3Qge1xuICAgIGNvbnN0IGNsYWltcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicpO1xuICAgIGlmICghY2xhaW1zKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIEpTT04ucGFyc2UoY2xhaW1zKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBncmFudGVkIHNjb3BlcyBmcm9tIHRoZSBzZXJ2ZXIuXG4gICAqL1xuICBwdWJsaWMgZ2V0R3JhbnRlZFNjb3BlcygpOiBvYmplY3Qge1xuICAgIGNvbnN0IHNjb3BlcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcbiAgICBpZiAoIXNjb3Blcykge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBKU09OLnBhcnNlKHNjb3Blcyk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgY3VycmVudCBpZF90b2tlbi5cbiAgICovXG4gIHB1YmxpYyBnZXRJZFRva2VuKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuJykgOiBudWxsO1xuICB9XG5cbiAgcHJvdGVjdGVkIHBhZEJhc2U2NChiYXNlNjRkYXRhKTogc3RyaW5nIHtcbiAgICB3aGlsZSAoYmFzZTY0ZGF0YS5sZW5ndGggJSA0ICE9PSAwKSB7XG4gICAgICBiYXNlNjRkYXRhICs9ICc9JztcbiAgICB9XG4gICAgcmV0dXJuIGJhc2U2NGRhdGE7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgY3VycmVudCBhY2Nlc3NfdG9rZW4uXG4gICAqL1xuICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW4oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuJykgOiBudWxsO1xuICB9XG5cbiAgcHVibGljIGdldFJlZnJlc2hUb2tlbigpOiBzdHJpbmcge1xuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJykgOiBudWxsO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgYWNjZXNzX3Rva2VuXG4gICAqIGFzIG1pbGxpc2Vjb25kcyBzaW5jZSAxOTcwLlxuICAgKi9cbiAgcHVibGljIGdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xuICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JykpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JyksIDEwKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBnZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcpLCAxMCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgZ2V0SWRUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBleHBpcmF0aW9uIGRhdGUgb2YgdGhlIGlkX3Rva2VuXG4gICAqIGFzIG1pbGxpc2Vjb25kcyBzaW5jZSAxOTcwLlxuICAgKi9cbiAgcHVibGljIGdldElkVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKSkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuXG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpLCAxMCk7XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2tlcywgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGFjY2Vzc190b2tlbi5cbiAgICovXG4gIHB1YmxpYyBoYXNWYWxpZEFjY2Vzc1Rva2VuKCk6IGJvb2xlYW4ge1xuICAgIGlmICh0aGlzLmdldEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpO1xuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICAgIGlmIChleHBpcmVzQXQgJiYgcGFyc2VJbnQoZXhwaXJlc0F0LCAxMCkgPCBub3cuZ2V0VGltZSgpKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgaWRfdG9rZW4uXG4gICAqL1xuICBwdWJsaWMgaGFzVmFsaWRJZFRva2VuKCk6IGJvb2xlYW4ge1xuICAgIGlmICh0aGlzLmdldElkVG9rZW4oKSkge1xuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XG4gICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgICogUmV0cmlldmUgYSBzYXZlZCBjdXN0b20gcHJvcGVydHkgb2YgdGhlIFRva2VuUmVwb25zZSBvYmplY3QuIE9ubHkgaWYgcHJlZGVmaW5lZCBpbiBhdXRoY29uZmlnLlxuICAgKi9cbiAgcHVibGljIGdldEN1c3RvbVRva2VuUmVzcG9uc2VQcm9wZXJ0eShyZXF1ZXN0ZWRQcm9wZXJ0eTogc3RyaW5nKTogYW55IHtcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSAmJlxuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzICYmXG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMuaW5kZXhPZihyZXF1ZXN0ZWRQcm9wZXJ0eSkgPj0gMCAmJlxuICAgICAgdGhpcy5fc3RvcmFnZS5nZXRJdGVtKHJlcXVlc3RlZFByb3BlcnR5KSAhPT0gbnVsbFxuICAgICAgPyBKU09OLnBhcnNlKHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbShyZXF1ZXN0ZWRQcm9wZXJ0eSkpXG4gICAgICA6IG51bGw7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgYXV0aC1oZWFkZXIgdGhhdCBjYW4gYmUgdXNlZFxuICAgKiB0byB0cmFuc21pdCB0aGUgYWNjZXNzX3Rva2VuIHRvIGEgc2VydmljZVxuICAgKi9cbiAgcHVibGljIGF1dGhvcml6YXRpb25IZWFkZXIoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpO1xuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZXMgYWxsIHRva2VucyBhbmQgbG9ncyB0aGUgdXNlciBvdXQuXG4gICAqIElmIGEgbG9nb3V0IHVybCBpcyBjb25maWd1cmVkLCB0aGUgdXNlciBpc1xuICAgKiByZWRpcmVjdGVkIHRvIGl0IHdpdGggb3B0aW9uYWwgc3RhdGUgcGFyYW1ldGVyLlxuICAgKiBAcGFyYW0gbm9SZWRpcmVjdFRvTG9nb3V0VXJsXG4gICAqIEBwYXJhbSBzdGF0ZVxuICAgKi9cbiAgcHVibGljIGxvZ091dChub1JlZGlyZWN0VG9Mb2dvdXRVcmwgPSBmYWxzZSwgc3RhdGUgPSAnJyk6IHZvaWQge1xuICAgIGNvbnN0IGlkX3Rva2VuID0gdGhpcy5nZXRJZFRva2VuKCk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW4nKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuJyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdyZWZyZXNoX3Rva2VuJyk7XG5cbiAgICBpZiAodGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xuICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XG4gICAgfVxuXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG4gICAgaWYgKHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycykge1xuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmZvckVhY2goY3VzdG9tUGFyYW0gPT5cbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKGN1c3RvbVBhcmFtKVxuICAgICAgKTtcbiAgICB9XG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IG51bGw7XG5cbiAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ2xvZ291dCcpKTtcblxuICAgIGlmICghdGhpcy5sb2dvdXRVcmwpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKG5vUmVkaXJlY3RUb0xvZ291dFVybCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmICghaWRfdG9rZW4gJiYgIXRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgbGV0IGxvZ291dFVybDogc3RyaW5nO1xuXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dvdXRVcmwpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwibG9nb3V0VXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxuICAgICAgKTtcbiAgICB9XG5cbiAgICAvLyBGb3IgYmFja3dhcmQgY29tcGF0aWJpbGl0eVxuICAgIGlmICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCd7eycpID4gLTEpIHtcbiAgICAgIGxvZ291dFVybCA9IHRoaXMubG9nb3V0VXJsXG4gICAgICAgIC5yZXBsYWNlKC9cXHtcXHtpZF90b2tlblxcfVxcfS8sIGlkX3Rva2VuKVxuICAgICAgICAucmVwbGFjZSgvXFx7XFx7Y2xpZW50X2lkXFx9XFx9LywgdGhpcy5jbGllbnRJZCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpO1xuXG4gICAgICBpZiAoaWRfdG9rZW4pIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnaWRfdG9rZW5faGludCcsIGlkX3Rva2VuKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgcG9zdExvZ291dFVybCA9IHRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgICBpZiAocG9zdExvZ291dFVybCkge1xuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdwb3N0X2xvZ291dF9yZWRpcmVjdF91cmknLCBwb3N0TG9nb3V0VXJsKTtcblxuICAgICAgICBpZiAoc3RhdGUpIHtcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdzdGF0ZScsIHN0YXRlKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBsb2dvdXRVcmwgPVxuICAgICAgICB0aGlzLmxvZ291dFVybCArXG4gICAgICAgICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgK1xuICAgICAgICBwYXJhbXMudG9TdHJpbmcoKTtcbiAgICB9XG4gICAgdGhpcy5jb25maWcub3BlblVyaShsb2dvdXRVcmwpO1xuICB9XG5cbiAgLyoqXG4gICAqIEBpZ25vcmVcbiAgICovXG4gIHB1YmxpYyBjcmVhdGVBbmRTYXZlTm9uY2UoKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICByZXR1cm4gdGhpcy5jcmVhdGVOb25jZSgpLnRoZW4oZnVuY3Rpb24obm9uY2U6IGFueSkge1xuICAgICAgLy8gVXNlIGxvY2FsU3RvcmFnZSBmb3Igbm9uY2UgaWYgcG9zc2libGVcbiAgICAgIC8vIGxvY2FsU3RvcmFnZSBpcyB0aGUgb25seSBzdG9yYWdlIHdobyBzdXJ2aXZlcyBhXG4gICAgICAvLyByZWRpcmVjdCBpbiBBTEwgYnJvd3NlcnMgKGFsc28gSUUpXG4gICAgICAvLyBPdGhlcndpZXNlIHdlJ2QgZm9yY2UgdGVhbXMgd2hvIGhhdmUgdG8gc3VwcG9ydFxuICAgICAgLy8gSUUgaW50byB1c2luZyBsb2NhbFN0b3JhZ2UgZm9yIGV2ZXJ5dGhpbmdcbiAgICAgIGlmIChcbiAgICAgICAgdGhhdC5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgICApIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ25vbmNlJywgbm9uY2UpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhhdC5fc3RvcmFnZS5zZXRJdGVtKCdub25jZScsIG5vbmNlKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBub25jZTtcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBAaWdub3JlXG4gICAqL1xuICBwdWJsaWMgbmdPbkRlc3Ryb3koKTogdm9pZCB7XG4gICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG5cbiAgICB0aGlzLnJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XG4gICAgY29uc3Qgc2lsZW50UmVmcmVzaEZyYW1lID0gdGhpcy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWVcbiAgICApO1xuICAgIGlmIChzaWxlbnRSZWZyZXNoRnJhbWUpIHtcbiAgICAgIHNpbGVudFJlZnJlc2hGcmFtZS5yZW1vdmUoKTtcbiAgICB9XG5cbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgIHRoaXMucmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xuICAgIGNvbnN0IHNlc3Npb25DaGVja0ZyYW1lID0gdGhpcy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxuICAgICk7XG4gICAgaWYgKHNlc3Npb25DaGVja0ZyYW1lKSB7XG4gICAgICBzZXNzaW9uQ2hlY2tGcmFtZS5yZW1vdmUoKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgY3JlYXRlTm9uY2UoKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICBpZiAodGhpcy5ybmdVcmwpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICdjcmVhdGVOb25jZSB3aXRoIHJuZy13ZWItYXBpIGhhcyBub3QgYmVlbiBpbXBsZW1lbnRlZCBzbyBmYXInXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIC8qXG4gICAgICAgKiBUaGlzIGFscGhhYmV0IGlzIGZyb206XG4gICAgICAgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzYzNiNzZWN0aW9uLTQuMVxuICAgICAgICpcbiAgICAgICAqIFtBLVpdIC8gW2Etel0gLyBbMC05XSAvIFwiLVwiIC8gXCIuXCIgLyBcIl9cIiAvIFwiflwiXG4gICAgICAgKi9cbiAgICAgIGNvbnN0IHVucmVzZXJ2ZWQgPVxuICAgICAgICAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODktLl9+JztcbiAgICAgIGxldCBzaXplID0gNDU7XG4gICAgICBsZXQgaWQgPSAnJztcblxuICAgICAgY29uc3QgY3J5cHRvID1cbiAgICAgICAgdHlwZW9mIHNlbGYgPT09ICd1bmRlZmluZWQnID8gbnVsbCA6IHNlbGYuY3J5cHRvIHx8IHNlbGZbJ21zQ3J5cHRvJ107XG4gICAgICBpZiAoY3J5cHRvKSB7XG4gICAgICAgIGxldCBieXRlcyA9IG5ldyBVaW50OEFycmF5KHNpemUpO1xuICAgICAgICBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGJ5dGVzKTtcblxuICAgICAgICAvLyBOZWVkZWQgZm9yIElFXG4gICAgICAgIGlmICghYnl0ZXMubWFwKSB7XG4gICAgICAgICAgKGJ5dGVzIGFzIGFueSkubWFwID0gQXJyYXkucHJvdG90eXBlLm1hcDtcbiAgICAgICAgfVxuXG4gICAgICAgIGJ5dGVzID0gYnl0ZXMubWFwKHggPT4gdW5yZXNlcnZlZC5jaGFyQ29kZUF0KHggJSB1bnJlc2VydmVkLmxlbmd0aCkpO1xuICAgICAgICBpZCA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgYnl0ZXMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd2hpbGUgKDAgPCBzaXplLS0pIHtcbiAgICAgICAgICBpZCArPSB1bnJlc2VydmVkWyhNYXRoLnJhbmRvbSgpICogdW5yZXNlcnZlZC5sZW5ndGgpIHwgMF07XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmVzb2x2ZShiYXNlNjRVcmxFbmNvZGUoaWQpKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBhc3luYyBjaGVja0F0SGFzaChwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIGF0X2hhc2guJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyLnZhbGlkYXRlQXRIYXNoKHBhcmFtcyk7XG4gIH1cblxuICBwcm90ZWN0ZWQgY2hlY2tTaWduYXR1cmUocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxhbnk+IHtcbiAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIHNpZ25hdHVyZS4nXG4gICAgICApO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShudWxsKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXMpO1xuICB9XG5cbiAgLyoqXG4gICAqIFN0YXJ0IHRoZSBpbXBsaWNpdCBmbG93IG9yIHRoZSBjb2RlIGZsb3csXG4gICAqIGRlcGVuZGluZyBvbiB5b3VyIGNvbmZpZ3VyYXRpb24uXG4gICAqL1xuICBwdWJsaWMgaW5pdExvZ2luRmxvdyhhZGRpdGlvbmFsU3RhdGUgPSAnJywgcGFyYW1zID0ge30pOiB2b2lkIHtcbiAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgcmV0dXJuIHRoaXMuaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHRoaXMuaW5pdEltcGxpY2l0RmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFN0YXJ0cyB0aGUgYXV0aG9yaXphdGlvbiBjb2RlIGZsb3cgYW5kIHJlZGlyZWN0cyB0byB1c2VyIHRvXG4gICAqIHRoZSBhdXRoIHNlcnZlcnMgbG9naW4gdXJsLlxuICAgKi9cbiAgcHVibGljIGluaXRDb2RlRmxvdyhhZGRpdGlvbmFsU3RhdGUgPSAnJywgcGFyYW1zID0ge30pOiB2b2lkIHtcbiAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcbiAgICAgIHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmV2ZW50c1xuICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgIC5zdWJzY3JpYmUoXyA9PiB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBpbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUgPSAnJywgcGFyYW1zID0ge30pOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxuICAgICAgKTtcbiAgICB9XG5cbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKGFkZGl0aW9uYWxTdGF0ZSwgJycsIG51bGwsIGZhbHNlLCBwYXJhbXMpXG4gICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEF1dGhvcml6YXRpb25Db2RlRmxvdycpO1xuICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUNoYWxsYW5nZVZlcmlmaWVyUGFpckZvclBLQ0UoKTogUHJvbWlzZTxcbiAgICBbc3RyaW5nLCBzdHJpbmddXG4gID4ge1xuICAgIGlmICghdGhpcy5jcnlwdG8pIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgJ1BLQ0Ugc3VwcG9ydCBmb3IgY29kZSBmbG93IG5lZWRzIGEgQ3J5cHRvSGFuZGVyLiBEaWQgeW91IGltcG9ydCB0aGUgT0F1dGhNb2R1bGUgdXNpbmcgZm9yUm9vdCgpID8nXG4gICAgICApO1xuICAgIH1cblxuICAgIGNvbnN0IHZlcmlmaWVyID0gYXdhaXQgdGhpcy5jcmVhdGVOb25jZSgpO1xuICAgIGNvbnN0IGNoYWxsZW5nZVJhdyA9IGF3YWl0IHRoaXMuY3J5cHRvLmNhbGNIYXNoKHZlcmlmaWVyLCAnc2hhLTI1NicpO1xuICAgIGNvbnN0IGNoYWxsZW5nZSA9IGJhc2U2NFVybEVuY29kZShjaGFsbGVuZ2VSYXcpO1xuXG4gICAgcmV0dXJuIFtjaGFsbGVuZ2UsIHZlcmlmaWVyXTtcbiAgfVxuXG4gIHByaXZhdGUgZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKFxuICAgIHRva2VuUmVzcG9uc2U6IFRva2VuUmVzcG9uc2VcbiAgKTogTWFwPHN0cmluZywgc3RyaW5nPiB7XG4gICAgbGV0IGZvdW5kUGFyYW1ldGVyczogTWFwPHN0cmluZywgc3RyaW5nPiA9IG5ldyBNYXA8c3RyaW5nLCBzdHJpbmc+KCk7XG4gICAgaWYgKCF0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMpIHtcbiAgICAgIHJldHVybiBmb3VuZFBhcmFtZXRlcnM7XG4gICAgfVxuICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5mb3JFYWNoKChyZWNvZ25pemVkUGFyYW1ldGVyOiBzdHJpbmcpID0+IHtcbiAgICAgIGlmICh0b2tlblJlc3BvbnNlW3JlY29nbml6ZWRQYXJhbWV0ZXJdKSB7XG4gICAgICAgIGZvdW5kUGFyYW1ldGVycy5zZXQoXG4gICAgICAgICAgcmVjb2duaXplZFBhcmFtZXRlcixcbiAgICAgICAgICBKU09OLnN0cmluZ2lmeSh0b2tlblJlc3BvbnNlW3JlY29nbml6ZWRQYXJhbWV0ZXJdKVxuICAgICAgICApO1xuICAgICAgfVxuICAgIH0pO1xuICAgIHJldHVybiBmb3VuZFBhcmFtZXRlcnM7XG4gIH1cbn1cbiJdfQ==