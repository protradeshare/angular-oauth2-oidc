import { throwError } from 'rxjs';
var OAuthResourceServerErrorHandler = /** @class */ (function () {
    function OAuthResourceServerErrorHandler() {
    }
    return OAuthResourceServerErrorHandler;
}());
export { OAuthResourceServerErrorHandler };
var OAuthNoopResourceServerErrorHandler = /** @class */ (function () {
    function OAuthNoopResourceServerErrorHandler() {
    }
    OAuthNoopResourceServerErrorHandler.prototype.handleError = function (err) {
        return throwError(err);
    };
    return OAuthNoopResourceServerErrorHandler;
}());
export { OAuthNoopResourceServerErrorHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiaW50ZXJjZXB0b3JzL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUNBLE9BQU8sRUFBYyxVQUFVLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFFOUM7SUFBQTtJQUVBLENBQUM7SUFBRCxzQ0FBQztBQUFELENBQUMsQUFGRCxJQUVDOztBQUVEO0lBQUE7SUFLQSxDQUFDO0lBSEMseURBQVcsR0FBWCxVQUFZLEdBQXNCO1FBQ2hDLE9BQU8sVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3pCLENBQUM7SUFDSCwwQ0FBQztBQUFELENBQUMsQUFMRCxJQUtDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cFJlc3BvbnNlIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgdGhyb3dFcnJvciB9IGZyb20gJ3J4anMnO1xuXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciB7XG4gIGFic3RyYWN0IGhhbmRsZUVycm9yKGVycjogSHR0cFJlc3BvbnNlPGFueT4pOiBPYnNlcnZhYmxlPGFueT47XG59XG5cbmV4cG9ydCBjbGFzcyBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxuICBpbXBsZW1lbnRzIE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIge1xuICBoYW5kbGVFcnJvcihlcnI6IEh0dHBSZXNwb25zZTxhbnk+KTogT2JzZXJ2YWJsZTxhbnk+IHtcbiAgICByZXR1cm4gdGhyb3dFcnJvcihlcnIpO1xuICB9XG59XG4iXX0=