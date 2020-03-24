import { __awaiter, __generator } from "tslib";
import { base64UrlEncode } from '../base64-helper';
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 */
var ValidationHandler = /** @class */ (function () {
    function ValidationHandler() {
    }
    return ValidationHandler;
}());
export { ValidationHandler };
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 */
var AbstractValidationHandler = /** @class */ (function () {
    function AbstractValidationHandler() {
    }
    /**
     * Validates the at_hash in an id_token against the received access_token.
     */
    AbstractValidationHandler.prototype.validateAtHash = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var hashAlg, tokenHash, leftMostHalf, atHash, claimsAtHash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        hashAlg = this.inferHashAlgorithm(params.idTokenHeader);
                        return [4 /*yield*/, this.calcHash(params.accessToken, hashAlg)];
                    case 1:
                        tokenHash = _a.sent();
                        leftMostHalf = tokenHash.substr(0, tokenHash.length / 2);
                        atHash = base64UrlEncode(leftMostHalf);
                        claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, '');
                        if (atHash !== claimsAtHash) {
                            console.error('exptected at_hash: ' + atHash);
                            console.error('actual at_hash: ' + claimsAtHash);
                        }
                        return [2 /*return*/, atHash === claimsAtHash];
                }
            });
        });
    };
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @param jwtHeader the id_token's parsed header
     */
    AbstractValidationHandler.prototype.inferHashAlgorithm = function (jwtHeader) {
        var alg = jwtHeader['alg'];
        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }
        return 'sha-' + alg.substr(2);
    };
    return AbstractValidationHandler;
}());
export { AbstractValidationHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGlvbi1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsZUFBZSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFXbkQ7OztHQUdHO0FBQ0g7SUFBQTtJQWNBLENBQUM7SUFBRCx3QkFBQztBQUFELENBQUMsQUFkRCxJQWNDOztBQUVEOzs7O0dBSUc7QUFDSDtJQUFBO0lBdURBLENBQUM7SUFqREM7O09BRUc7SUFDRyxrREFBYyxHQUFwQixVQUFxQixNQUF3Qjs7Ozs7O3dCQUN2QyxPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUMsQ0FBQzt3QkFFNUMscUJBQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFLE9BQU8sQ0FBQyxFQUFBOzt3QkFBNUQsU0FBUyxHQUFHLFNBQWdEO3dCQUU1RCxZQUFZLEdBQUcsU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQzt3QkFFekQsTUFBTSxHQUFHLGVBQWUsQ0FBQyxZQUFZLENBQUMsQ0FBQzt3QkFFdkMsWUFBWSxHQUFHLE1BQU0sQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQzt3QkFFckUsSUFBSSxNQUFNLEtBQUssWUFBWSxFQUFFOzRCQUMzQixPQUFPLENBQUMsS0FBSyxDQUFDLHFCQUFxQixHQUFHLE1BQU0sQ0FBQyxDQUFDOzRCQUM5QyxPQUFPLENBQUMsS0FBSyxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQyxDQUFDO3lCQUNsRDt3QkFFRCxzQkFBTyxNQUFNLEtBQUssWUFBWSxFQUFDOzs7O0tBQ2hDO0lBRUQ7Ozs7O09BS0c7SUFDTyxzREFBa0IsR0FBNUIsVUFBNkIsU0FBaUI7UUFDNUMsSUFBSSxHQUFHLEdBQVcsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBRW5DLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLGNBQWMsQ0FBQyxFQUFFO1lBQzlCLE1BQU0sSUFBSSxLQUFLLENBQUMsMkJBQTJCLEdBQUcsR0FBRyxDQUFDLENBQUM7U0FDcEQ7UUFFRCxPQUFPLE1BQU0sR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2hDLENBQUM7SUFhSCxnQ0FBQztBQUFELENBQUMsQUF2REQsSUF1REMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuLi9iYXNlNjQtaGVscGVyJztcblxuZXhwb3J0IGludGVyZmFjZSBWYWxpZGF0aW9uUGFyYW1zIHtcbiAgaWRUb2tlbjogc3RyaW5nO1xuICBhY2Nlc3NUb2tlbjogc3RyaW5nO1xuICBpZFRva2VuSGVhZGVyOiBvYmplY3Q7XG4gIGlkVG9rZW5DbGFpbXM6IG9iamVjdDtcbiAgandrczogb2JqZWN0O1xuICBsb2FkS2V5czogKCkgPT4gUHJvbWlzZTxvYmplY3Q+O1xufVxuXG4vKipcbiAqIEludGVyZmFjZSBmb3IgSGFuZGxlcnMgdGhhdCBhcmUgaG9va2VkIGluIHRvXG4gKiB2YWxpZGF0ZSB0b2tlbnMuXG4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBWYWxpZGF0aW9uSGFuZGxlciB7XG4gIC8qKlxuICAgKiBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZSBvZiBhbiBpZF90b2tlbi5cbiAgICovXG4gIHB1YmxpYyBhYnN0cmFjdCB2YWxpZGF0ZVNpZ25hdHVyZShcbiAgICB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zXG4gICk6IFByb21pc2U8YW55PjtcblxuICAvKipcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cbiAgICovXG4gIHB1YmxpYyBhYnN0cmFjdCB2YWxpZGF0ZUF0SGFzaChcbiAgICB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zXG4gICk6IFByb21pc2U8Ym9vbGVhbj47XG59XG5cbi8qKlxuICogVGhpcyBhYnN0cmFjdCBpbXBsZW1lbnRhdGlvbiBvZiBWYWxpZGF0aW9uSGFuZGxlciBhbHJlYWR5IGltcGxlbWVudHNcbiAqIHRoZSBtZXRob2QgdmFsaWRhdGVBdEhhc2guIEhvd2V2ZXIsIHRvIG1ha2UgdXNlIG9mIGl0LFxuICogeW91IGhhdmUgdG8gb3ZlcnJpZGUgdGhlIG1ldGhvZCBjYWxjSGFzaC5cbiAqL1xuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEFic3RyYWN0VmFsaWRhdGlvbkhhbmRsZXIgaW1wbGVtZW50cyBWYWxpZGF0aW9uSGFuZGxlciB7XG4gIC8qKlxuICAgKiBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZSBvZiBhbiBpZF90b2tlbi5cbiAgICovXG4gIGFic3RyYWN0IHZhbGlkYXRlU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT47XG5cbiAgLyoqXG4gICAqIFZhbGlkYXRlcyB0aGUgYXRfaGFzaCBpbiBhbiBpZF90b2tlbiBhZ2FpbnN0IHRoZSByZWNlaXZlZCBhY2Nlc3NfdG9rZW4uXG4gICAqL1xuICBhc3luYyB2YWxpZGF0ZUF0SGFzaChwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBsZXQgaGFzaEFsZyA9IHRoaXMuaW5mZXJIYXNoQWxnb3JpdGhtKHBhcmFtcy5pZFRva2VuSGVhZGVyKTtcblxuICAgIGxldCB0b2tlbkhhc2ggPSBhd2FpdCB0aGlzLmNhbGNIYXNoKHBhcmFtcy5hY2Nlc3NUb2tlbiwgaGFzaEFsZyk7IC8vIHNoYTI1NihhY2Nlc3NUb2tlbiwgeyBhc1N0cmluZzogdHJ1ZSB9KTtcblxuICAgIGxldCBsZWZ0TW9zdEhhbGYgPSB0b2tlbkhhc2guc3Vic3RyKDAsIHRva2VuSGFzaC5sZW5ndGggLyAyKTtcblxuICAgIGxldCBhdEhhc2ggPSBiYXNlNjRVcmxFbmNvZGUobGVmdE1vc3RIYWxmKTtcblxuICAgIGxldCBjbGFpbXNBdEhhc2ggPSBwYXJhbXMuaWRUb2tlbkNsYWltc1snYXRfaGFzaCddLnJlcGxhY2UoLz0vZywgJycpO1xuXG4gICAgaWYgKGF0SGFzaCAhPT0gY2xhaW1zQXRIYXNoKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdleHB0ZWN0ZWQgYXRfaGFzaDogJyArIGF0SGFzaCk7XG4gICAgICBjb25zb2xlLmVycm9yKCdhY3R1YWwgYXRfaGFzaDogJyArIGNsYWltc0F0SGFzaCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF0SGFzaCA9PT0gY2xhaW1zQXRIYXNoO1xuICB9XG5cbiAgLyoqXG4gICAqIEluZmVycyB0aGUgbmFtZSBvZiB0aGUgaGFzaCBhbGdvcml0aG0gdG8gdXNlXG4gICAqIGZyb20gdGhlIGFsZyBmaWVsZCBvZiBhbiBpZF90b2tlbi5cbiAgICpcbiAgICogQHBhcmFtIGp3dEhlYWRlciB0aGUgaWRfdG9rZW4ncyBwYXJzZWQgaGVhZGVyXG4gICAqL1xuICBwcm90ZWN0ZWQgaW5mZXJIYXNoQWxnb3JpdGhtKGp3dEhlYWRlcjogb2JqZWN0KTogc3RyaW5nIHtcbiAgICBsZXQgYWxnOiBzdHJpbmcgPSBqd3RIZWFkZXJbJ2FsZyddO1xuXG4gICAgaWYgKCFhbGcubWF0Y2goL14uU1swLTldezN9JC8pKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0FsZ29yaXRobSBub3Qgc3VwcG9ydGVkOiAnICsgYWxnKTtcbiAgICB9XG5cbiAgICByZXR1cm4gJ3NoYS0nICsgYWxnLnN1YnN0cigyKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDYWxjdWxhdGVzIHRoZSBoYXNoIGZvciB0aGUgcGFzc2VkIHZhbHVlIGJ5IHVzaW5nXG4gICAqIHRoZSBwYXNzZWQgaGFzaCBhbGdvcml0aG0uXG4gICAqXG4gICAqIEBwYXJhbSB2YWx1ZVRvSGFzaFxuICAgKiBAcGFyYW0gYWxnb3JpdGhtXG4gICAqL1xuICBwcm90ZWN0ZWQgYWJzdHJhY3QgY2FsY0hhc2goXG4gICAgdmFsdWVUb0hhc2g6IHN0cmluZyxcbiAgICBhbGdvcml0aG06IHN0cmluZ1xuICApOiBQcm9taXNlPHN0cmluZz47XG59XG4iXX0=