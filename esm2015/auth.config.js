export class AuthConfig {
    constructor(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Names of known parameters sent out in the TokenResponse. https://tools.ietf.org/html/rfc6749#section-5.1
         */
        this.customTokenParameters = [];
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * @internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks the we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for AJAX calls
         */
        this.useHttpBasicAuth = false;
        /**
         * The interceptors waits this time span if there is no token
         */
        this.waitForTokenInMsec = 0;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = uri => {
            location.href = uri;
        };
        if (json) {
            Object.assign(this, json);
        }
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiYXV0aC5jb25maWcudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsTUFBTSxPQUFPLFVBQVU7SUF3UHJCLFlBQVksSUFBMEI7UUF2UHRDOztXQUVHO1FBQ0ksYUFBUSxHQUFJLEVBQUUsQ0FBQztRQUV0Qjs7V0FFRztRQUNJLGdCQUFXLEdBQUksRUFBRSxDQUFDO1FBRXpCOzs7V0FHRztRQUNJLDBCQUFxQixHQUFJLEVBQUUsQ0FBQztRQUVuQzs7O1dBR0c7UUFDSSxhQUFRLEdBQUksRUFBRSxDQUFDO1FBRXRCOztXQUVHO1FBQ0ksVUFBSyxHQUFJLGdCQUFnQixDQUFDO1FBRTFCLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFZixXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOzs7V0FHRztRQUNJLFNBQUksR0FBSSxJQUFJLENBQUM7UUFFcEI7OztXQUdHO1FBQ0ksdUJBQWtCLEdBQUksSUFBSSxDQUFDO1FBRTNCLFlBQU8sR0FBUyxJQUFJLENBQUM7UUFFNUI7O1dBRUc7UUFDSSxXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOztXQUVHO1FBQ0ksY0FBUyxHQUFJLEVBQUUsQ0FBQztRQUV2Qjs7V0FFRztRQUNJLHdCQUFtQixHQUFJLElBQUksQ0FBQztRQUVuQzs7V0FFRztRQUNJLGtCQUFhLEdBQVksSUFBSSxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQWMsRUFBRSxDQUFDO1FBRTdDOztXQUVHO1FBQ0kscUJBQWdCLEdBQVksSUFBSSxDQUFDO1FBRWpDLGlCQUFZLEdBQUksRUFBRSxDQUFDO1FBRTFCOzs7OztXQUtHO1FBQ0kseUJBQW9CLEdBQUksS0FBSyxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksNkJBQXdCLEdBQUksRUFBRSxDQUFDO1FBRS9CLCtCQUEwQixHQUFJLEVBQUUsQ0FBQztRQUV4Qzs7O1dBR0c7UUFDSSw0QkFBdUIsR0FBSSxLQUFLLENBQUM7UUFFeEM7Ozs7V0FJRztRQUNJLHdCQUFtQixHQUFZLElBQUksR0FBRyxFQUFFLENBQUM7UUFFaEQ7O1dBRUc7UUFDSSx5QkFBb0IsR0FBWSxJQUFJLEdBQUcsRUFBRSxDQUFDO1FBRWpEOzs7Ozs7O1dBT0c7UUFDSSxzQkFBaUIsR0FBWSxJQUFJLENBQUM7UUFFekM7Ozs7O1dBS0c7UUFDSSxpQkFBWSxHQUE0QixZQUFZLENBQUM7UUFFNUQ7OztXQUdHO1FBQ0ksc0NBQWlDLEdBQUksSUFBSSxDQUFDO1FBRWpEOzs7O1dBSUc7UUFDSSxTQUFJLEdBQVksSUFBSSxDQUFDO1FBRTVCOzs7V0FHRztRQUNJLHNCQUFpQixHQUFZLElBQUksQ0FBQztRQUVsQyw0QkFBdUIsR0FBSSwwQ0FBMEMsQ0FBQztRQUU3RTs7OztXQUlHO1FBQ0ksa0JBQWEsR0FBSSxJQUFJLENBQUM7UUFFN0I7Ozs7V0FJRztRQUNJLHlCQUFvQixHQUFJLEtBQUssQ0FBQztRQUVyQzs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxDQUFDLEdBQUcsSUFBSSxDQUFDO1FBRXpDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQVksSUFBSSxDQUFDO1FBRTdDOztXQUVHO1FBQ0ksMkJBQXNCLEdBQUkseUNBQXlDLENBQUM7UUFFM0U7Ozs7OztXQU1HO1FBQ0ksdUJBQWtCLEdBQUksS0FBSyxDQUFDO1FBRW5DOzs7V0FHRztRQUNJLHFCQUFnQixHQUFJLEtBQUssQ0FBQztRQUUxQixtQ0FBOEIsR0FBSSxLQUFLLENBQUM7UUFFL0M7OztXQUdHO1FBQ0ksb0JBQWUsR0FBSSxLQUFLLENBQUM7UUFTaEM7Ozs7O1dBS0c7UUFDSSx3QkFBbUIsR0FBSSxHQUFHLENBQUM7UUFFbEM7O1dBRUc7UUFDSSxxQkFBZ0IsR0FBSSxLQUFLLENBQUM7UUFPakM7O1dBRUc7UUFDSSx1QkFBa0IsR0FBSSxDQUFDLENBQUM7UUFVL0I7Ozs7V0FJRztRQUNJLGdCQUFXLEdBQUksS0FBSyxDQUFDO1FBUTVCOzs7O1dBSUc7UUFDSSxZQUFPLEdBQTJCLEdBQUcsQ0FBQyxFQUFFO1lBQzdDLFFBQVEsQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDO1FBQ3RCLENBQUMsQ0FBQztRQVpBLElBQUksSUFBSSxFQUFFO1lBQ1IsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7U0FDM0I7SUFDSCxDQUFDO0NBVUYiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgY2xhc3MgQXV0aENvbmZpZyB7XG4gIC8qKlxuICAgKiBUaGUgY2xpZW50J3MgaWQgYXMgcmVnaXN0ZXJlZCB3aXRoIHRoZSBhdXRoIHNlcnZlclxuICAgKi9cbiAgcHVibGljIGNsaWVudElkPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgY2xpZW50J3MgcmVkaXJlY3RVcmkgYXMgcmVnaXN0ZXJlZCB3aXRoIHRoZSBhdXRoIHNlcnZlclxuICAgKi9cbiAgcHVibGljIHJlZGlyZWN0VXJpPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBBbiBvcHRpb25hbCBzZWNvbmQgcmVkaXJlY3RVcmkgd2hlcmUgdGhlIGF1dGggc2VydmVyXG4gICAqIHJlZGlyZWN0cyB0aGUgdXNlciB0byBhZnRlciBsb2dnaW5nIG91dC5cbiAgICovXG4gIHB1YmxpYyBwb3N0TG9nb3V0UmVkaXJlY3RVcmk/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSBhdXRoIHNlcnZlcidzIGVuZHBvaW50IHRoYXQgYWxsb3dzIHRvIGxvZ1xuICAgKiB0aGUgdXNlciBpbiB3aGVuIHVzaW5nIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgbG9naW5Vcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSByZXF1ZXN0ZWQgc2NvcGVzXG4gICAqL1xuICBwdWJsaWMgc2NvcGU/ID0gJ29wZW5pZCBwcm9maWxlJztcblxuICBwdWJsaWMgcmVzb3VyY2U/ID0gJyc7XG5cbiAgcHVibGljIHJuZ1VybD8gPSAnJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIHVzZSBPcGVuSWQgQ29ubmVjdCBkdXJpbmdcbiAgICogaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyBvaWRjPyA9IHRydWU7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byByZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiBkdXJpbmdcbiAgICogaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyByZXF1ZXN0QWNjZXNzVG9rZW4/ID0gdHJ1ZTtcblxuICBwdWJsaWMgb3B0aW9ucz86IGFueSA9IG51bGw7XG5cbiAgLyoqXG4gICAqIFRoZSBpc3N1ZXIncyB1cmkuXG4gICAqL1xuICBwdWJsaWMgaXNzdWVyPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgbG9nb3V0IHVybC5cbiAgICovXG4gIHB1YmxpYyBsb2dvdXRVcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byBjbGVhciB0aGUgaGFzaCBmcmFnbWVudCBhZnRlciBsb2dnaW5nIGluLlxuICAgKi9cbiAgcHVibGljIGNsZWFySGFzaEFmdGVyTG9naW4/ID0gdHJ1ZTtcblxuICAvKipcbiAgICogVXJsIG9mIHRoZSB0b2tlbiBlbmRwb2ludCBhcyBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0IGFuZCBPQXV0aCAyLlxuICAgKi9cbiAgcHVibGljIHRva2VuRW5kcG9pbnQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBOYW1lcyBvZiBrbm93biBwYXJhbWV0ZXJzIHNlbnQgb3V0IGluIHRoZSBUb2tlblJlc3BvbnNlLiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTUuMVxuICAgKi9cbiAgcHVibGljIGN1c3RvbVRva2VuUGFyYW1ldGVycz86IHN0cmluZ1tdID0gW107XG5cbiAgLyoqXG4gICAqIFVybCBvZiB0aGUgdXNlcmluZm8gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICovXG4gIHB1YmxpYyB1c2VyaW5mb0VuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICBwdWJsaWMgcmVzcG9uc2VUeXBlPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgYWRkaXRpb25hbCBkZWJ1ZyBpbmZvcm1hdGlvbiBzaG91bGRcbiAgICogYmUgc2hvd24gYXQgdGhlIGNvbnNvbGUuIE5vdGUgdGhhdCBpbiBjZXJ0YWluIGJyb3dzZXJzXG4gICAqIHRoZSB2ZXJib3NpdHkgb2YgdGhlIGNvbnNvbGUgbmVlZHMgdG8gYmUgZXhwbGljaXRseSBzZXRcbiAgICogdG8gaW5jbHVkZSBEZWJ1ZyBsZXZlbCBtZXNzYWdlcy5cbiAgICovXG4gIHB1YmxpYyBzaG93RGVidWdJbmZvcm1hdGlvbj8gPSBmYWxzZTtcblxuICAvKipcbiAgICogVGhlIHJlZGlyZWN0IHVyaSB1c2VkIHdoZW4gZG9pbmcgc2lsZW50IHJlZnJlc2guXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpPyA9ICcnO1xuXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeD8gPSAnJztcblxuICAvKipcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSB0byBkaXNwbGF5IHRoZSBpZnJhbWUgdXNlZCBmb3JcbiAgICogc2lsZW50IHJlZnJlc2ggZm9yIGRlYnVnZ2luZy5cbiAgICovXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoU2hvd0lGcmFtZT8gPSBmYWxzZTtcblxuICAvKipcbiAgICogVGltZW91dCBmb3Igc2lsZW50IHJlZnJlc2guXG4gICAqIEBpbnRlcm5hbFxuICAgKiBkZXByZWFjdGVkIGIvYyBvZiB0eXBvLCBzZWUgc2lsZW50UmVmcmVzaFRpbWVvdXRcbiAgICovXG4gIHB1YmxpYyBzaWxldFJlZnJlc2hUaW1lb3V0PzogbnVtYmVyID0gMTAwMCAqIDIwO1xuXG4gIC8qKlxuICAgKiBUaW1lb3V0IGZvciBzaWxlbnQgcmVmcmVzaC5cbiAgICovXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoVGltZW91dD86IG51bWJlciA9IDEwMDAgKiAyMDtcblxuICAvKipcbiAgICogU29tZSBhdXRoIHNlcnZlcnMgZG9uJ3QgYWxsb3cgdXNpbmcgcGFzc3dvcmQgZmxvd1xuICAgKiB3L28gYSBjbGllbnQgc2VjcmV0IHdoaWxlIHRoZSBzdGFuZGFyZHMgZG8gbm90XG4gICAqIGRlbWFuZCBmb3IgaXQuIEluIHRoaXMgY2FzZSwgeW91IGNhbiBzZXQgYSBwYXNzd29yZFxuICAgKiBoZXJlLiBBcyB0aGlzIHBhc3N3b3JkIGlzIGV4cG9zZWQgdG8gdGhlIHB1YmxpY1xuICAgKiBpdCBkb2VzIG5vdCBicmluZyBhZGRpdGlvbmFsIHNlY3VyaXR5IGFuZCBpcyB0aGVyZWZvcmVcbiAgICogYXMgZ29vZCBhcyB1c2luZyBubyBwYXNzd29yZC5cbiAgICovXG4gIHB1YmxpYyBkdW1teUNsaWVudFNlY3JldD86IHN0cmluZyA9IG51bGw7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciBodHRwcyBpcyByZXF1aXJlZC5cbiAgICogVGhlIGRlZmF1bHQgdmFsdWUgaXMgcmVtb3RlT25seSB3aGljaCBvbmx5IGFsbG93c1xuICAgKiBodHRwIGZvciBsb2NhbGhvc3QsIHdoaWxlIGV2ZXJ5IG90aGVyIGRvbWFpbnMgbmVlZFxuICAgKiB0byBiZSB1c2VkIHdpdGggaHR0cHMuXG4gICAqL1xuICBwdWJsaWMgcmVxdWlyZUh0dHBzPzogYm9vbGVhbiB8ICdyZW1vdGVPbmx5JyA9ICdyZW1vdGVPbmx5JztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIGV2ZXJ5IHVybCBwcm92aWRlZCBieSB0aGUgZGlzY292ZXJ5XG4gICAqIGRvY3VtZW50IGhhcyB0byBzdGFydCB3aXRoIHRoZSBpc3N1ZXIncyB1cmwuXG4gICAqL1xuICBwdWJsaWMgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uPyA9IHRydWU7XG5cbiAgLyoqXG4gICAqIEpTT04gV2ViIEtleSBTZXQgKGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM3NTE3KVxuICAgKiB3aXRoIGtleXMgdXNlZCB0byB2YWxpZGF0ZSByZWNlaXZlZCBpZF90b2tlbnMuXG4gICAqIFRoaXMgaXMgdGFrZW4gb3V0IG9mIHRoZSBkaXNvdmVyeSBkb2N1bWVudC4gQ2FuIGJlIHNldCBtYW51YWxseSB0b28uXG4gICAqL1xuICBwdWJsaWMgandrcz86IG9iamVjdCA9IG51bGw7XG5cbiAgLyoqXG4gICAqIE1hcCB3aXRoIGFkZGl0aW9uYWwgcXVlcnkgcGFyYW1ldGVyIHRoYXQgYXJlIGFwcGVuZGVkIHRvXG4gICAqIHRoZSByZXF1ZXN0IHdoZW4gaW5pdGlhbGl6aW5nIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgY3VzdG9tUXVlcnlQYXJhbXM/OiBvYmplY3QgPSBudWxsO1xuXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoSUZyYW1lTmFtZT8gPSAnYW5ndWxhci1vYXV0aC1vaWRjLXNpbGVudC1yZWZyZXNoLWlmcmFtZSc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hlbiB0aGUgdG9rZW5fdGltZW91dCBldmVudCBzaG91bGQgYmUgcmFpc2VkLlxuICAgKiBJZiB5b3Ugc2V0IHRoaXMgdG8gdGhlIGRlZmF1bHQgdmFsdWUgMC43NSwgdGhlIGV2ZW50XG4gICAqIGlzIHRyaWdnZXJlZCBhZnRlciA3NSUgb2YgdGhlIHRva2VuJ3MgbGlmZSB0aW1lLlxuICAgKi9cbiAgcHVibGljIHRpbWVvdXRGYWN0b3I/ID0gMC43NTtcblxuICAvKipcbiAgICogSWYgdHJ1ZSwgdGhlIGxpYiB3aWxsIHRyeSB0byBjaGVjayB3aGV0aGVyIHRoZSB1c2VyXG4gICAqIGlzIHN0aWxsIGxvZ2dlZCBpbiBvbiBhIHJlZ3VsYXIgYmFzaXMgYXMgZGVzY3JpYmVkXG4gICAqIGluIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LXNlc3Npb24tMV8wLmh0bWwjQ2hhbmdlTm90aWZpY2F0aW9uXG4gICAqL1xuICBwdWJsaWMgc2Vzc2lvbkNoZWNrc0VuYWJsZWQ/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIEludGVydmFsIGluIG1zZWMgZm9yIGNoZWNraW5nIHRoZSBzZXNzaW9uXG4gICAqIGFjY29yZGluZyB0byBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1zZXNzaW9uLTFfMC5odG1sI0NoYW5nZU5vdGlmaWNhdGlvblxuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja0ludGVydmFsbD8gPSAzICogMTAwMDtcblxuICAvKipcbiAgICogVXJsIGZvciB0aGUgaWZyYW1lIHVzZWQgZm9yIHNlc3Npb24gY2hlY2tzXG4gICAqL1xuICBwdWJsaWMgc2Vzc2lvbkNoZWNrSUZyYW1lVXJsPzogc3RyaW5nID0gbnVsbDtcblxuICAvKipcbiAgICogTmFtZSBvZiB0aGUgaWZyYW1lIHRvIHVzZSBmb3Igc2Vzc2lvbiBjaGVja3NcbiAgICovXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJRnJhbWVOYW1lPyA9ICdhbmd1bGFyLW9hdXRoLW9pZGMtY2hlY2stc2Vzc2lvbi1pZnJhbWUnO1xuXG4gIC8qKlxuICAgKiBUaGlzIHByb3BlcnR5IGhhcyBiZWVuIGludHJvZHVjZWQgdG8gZGlzYWJsZSBhdF9oYXNoIGNoZWNrc1xuICAgKiBhbmQgaXMgaW5kZW50ZWQgZm9yIElkZW50aXR5IFByb3ZpZGVyIHRoYXQgZG9lcyBub3QgZGVsaXZlclxuICAgKiBhbiBhdF9oYXNoIEVWRU4gVEhPVUdIIGl0cyByZWNvbW1lbmRlZCBieSB0aGUgT0lEQyBzcGVjcy5cbiAgICogT2YgY291cnNlLCB3aGVuIGRpc2FibGluZyB0aGVzZSBjaGVja3MgdGhlIHdlIGFyZSBieXBhc3NpbmdcbiAgICogYSBzZWN1cml0eSBjaGVjayB3aGljaCBtZWFucyB3ZSBhcmUgbW9yZSB2dWxuZXJhYmxlLlxuICAgKi9cbiAgcHVibGljIGRpc2FibGVBdEhhc2hDaGVjaz8gPSBmYWxzZTtcblxuICAvKipcbiAgICogRGVmaW5lcyB3ZXRoZXIgdG8gY2hlY2sgdGhlIHN1YmplY3Qgb2YgYSByZWZyZXNoZWQgdG9rZW4gYWZ0ZXIgc2lsZW50IHJlZnJlc2guXG4gICAqIE5vcm1hbGx5LCBpdCBzaG91bGQgYmUgdGhlIHNhbWUgYXMgYmVmb3JlLlxuICAgKi9cbiAgcHVibGljIHNraXBTdWJqZWN0Q2hlY2s/ID0gZmFsc2U7XG5cbiAgcHVibGljIHVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaD8gPSBmYWxzZTtcblxuICAvKipcbiAgICogRGVmaW5lZCB3aGV0aGVyIHRvIHNraXAgdGhlIHZhbGlkYXRpb24gb2YgdGhlIGlzc3VlciBpbiB0aGUgZGlzY292ZXJ5IGRvY3VtZW50LlxuICAgKiBOb3JtYWxseSwgdGhlIGRpc2NvdmV5IGRvY3VtZW50J3MgdXJsIHN0YXJ0cyB3aXRoIHRoZSB1cmwgb2YgdGhlIGlzc3Vlci5cbiAgICovXG4gIHB1YmxpYyBza2lwSXNzdWVyQ2hlY2s/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIEFjY29yZGluZyB0byByZmM2NzQ5IGl0IGlzIHJlY29tbWVuZGVkIChidXQgbm90IHJlcXVpcmVkKSB0aGF0IHRoZSBhdXRoXG4gICAqIHNlcnZlciBleHBvc2VzIHRoZSBhY2Nlc3NfdG9rZW4ncyBsaWZlIHRpbWUgaW4gc2Vjb25kcy5cbiAgICogVGhpcyBpcyBhIGZhbGxiYWNrIHZhbHVlIGZvciB0aGUgY2FzZSB0aGlzIHZhbHVlIGlzIG5vdCBleHBvc2VkLlxuICAgKi9cbiAgcHVibGljIGZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjPzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBmaW5hbCBzdGF0ZSBzZW50IHRvIGlzc3VlciBpcyBidWlsdCBhcyBmb2xsb3dzOlxuICAgKiBzdGF0ZSA9IG5vbmNlICsgbm9uY2VTdGF0ZVNlcGFyYXRvciArIGFkZGl0aW9uYWwgc3RhdGVcbiAgICogRGVmYXVsdCBzZXBhcmF0b3IgaXMgJzsnIChlbmNvZGVkICUzQikuXG4gICAqIEluIHJhcmUgY2FzZXMsIHRoaXMgY2hhcmFjdGVyIG1pZ2h0IGJlIGZvcmJpZGRlbiBvciBpbmNvbnZlbmllbnQgdG8gdXNlIGJ5IHRoZSBpc3N1ZXIgc28gaXQgY2FuIGJlIGN1c3RvbWl6ZWQuXG4gICAqL1xuICBwdWJsaWMgbm9uY2VTdGF0ZVNlcGFyYXRvcj8gPSAnOyc7XG5cbiAgLyoqXG4gICAqIFNldCB0aGlzIHRvIHRydWUgdG8gdXNlIEhUVFAgQkFTSUMgYXV0aCBmb3IgQUpBWCBjYWxsc1xuICAgKi9cbiAgcHVibGljIHVzZUh0dHBCYXNpY0F1dGg/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRoZSB3aW5kb3cgb2YgdGltZSAoaW4gc2Vjb25kcykgdG8gYWxsb3cgdGhlIGN1cnJlbnQgdGltZSB0byBkZXZpYXRlIHdoZW4gdmFsaWRhdGluZyBpZF90b2tlbidzIGlhdCBhbmQgZXhwIHZhbHVlcy5cbiAgICovXG4gIHB1YmxpYyBjbG9ja1NrZXdJblNlYz86IG51bWJlcjtcblxuICAvKipcbiAgICogVGhlIGludGVyY2VwdG9ycyB3YWl0cyB0aGlzIHRpbWUgc3BhbiBpZiB0aGVyZSBpcyBubyB0b2tlblxuICAgKi9cbiAgcHVibGljIHdhaXRGb3JUb2tlbkluTXNlYz8gPSAwO1xuXG4gIC8qKlxuICAgKiBTZXQgdGhpcyB0byB0cnVlIGlmIHlvdSB3YW50IHRvIHVzZSBzaWxlbnQgcmVmcmVzaCB0b2dldGhlciB3aXRoXG4gICAqIGNvZGUgZmxvdy4gQXMgc2lsZW50IHJlZnJlc2ggaXMgdGhlIG9ubHkgb3B0aW9uIGZvciByZWZyZXNoaW5nXG4gICAqIHdpdGggaW1wbGljaXQgZmxvdywgeW91IGRvbid0IG5lZWQgdG8gZXhwbGljaXRseSB0dXJuIGl0IG9uIGluXG4gICAqIHRoaXMgY2FzZS5cbiAgICovXG4gIHB1YmxpYyB1c2VTaWxlbnRSZWZyZXNoPztcblxuICAvKipcbiAgICogQ29kZSBGbG93IGlzIGJ5IGRlZmF1bGQgdXNlZCB0b2dldGhlciB3aXRoIFBLQ0kgd2hpY2ggaXMgYWxzbyBoaWdseSByZWNvbW1lbnRlZC5cbiAgICogWW91IGNhbiBkaXNiYWxlIGl0IGhlcmUgYnkgc2V0dGluZyB0aGlzIGZsYWcgdG8gdHJ1ZS5cbiAgICogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc2MzYjc2VjdGlvbi0xLjFcbiAgICovXG4gIHB1YmxpYyBkaXNhYmxlUEtDRT8gPSBmYWxzZTtcblxuICBjb25zdHJ1Y3Rvcihqc29uPzogUGFydGlhbDxBdXRoQ29uZmlnPikge1xuICAgIGlmIChqc29uKSB7XG4gICAgICBPYmplY3QuYXNzaWduKHRoaXMsIGpzb24pO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHByb3BlcnR5IGFsbG93cyB5b3UgdG8gb3ZlcnJpZGUgdGhlIG1ldGhvZCB0aGF0IGlzIHVzZWQgdG8gb3BlbiB0aGUgbG9naW4gdXJsLFxuICAgKiBhbGxvd2luZyBhIHdheSBmb3IgaW1wbGVtZW50YXRpb25zIHRvIHNwZWNpZnkgdGhlaXIgb3duIG1ldGhvZCBvZiByb3V0aW5nIHRvIG5ld1xuICAgKiB1cmxzLlxuICAgKi9cbiAgcHVibGljIG9wZW5Vcmk/OiAodXJpOiBzdHJpbmcpID0+IHZvaWQgPSB1cmkgPT4ge1xuICAgIGxvY2F0aW9uLmhyZWYgPSB1cmk7XG4gIH07XG59XG4iXX0=