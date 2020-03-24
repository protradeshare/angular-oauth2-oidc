import { __decorate, __metadata, __param } from "tslib";
import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout } from 'rxjs/operators';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';
import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthStorage } from '../types';
import { OAuthService } from '../oauth-service';
let DefaultOAuthInterceptor = class DefaultOAuthInterceptor {
    constructor(authStorage, oAuthService, errorHandler, moduleConfig) {
        this.authStorage = authStorage;
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    checkUrl(url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find(u => url.startsWith(u));
        }
        return true;
    }
    intercept(req, next) {
        const url = req.url.toLowerCase();
        if (!this.moduleConfig ||
            !this.moduleConfig.resourceServer ||
            !this.checkUrl(url)) {
            return next.handle(req);
        }
        const sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError(err => this.errorHandler.handleError(err)));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter(token => (token ? true : false))), this.oAuthService.events.pipe(filter(e => e.type === 'token_received'), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError(_ => of(null)), // timeout is not an error
        map(_ => this.oAuthService.getAccessToken()))).pipe(take(1), mergeMap(token => {
            if (token) {
                const header = 'Bearer ' + token;
                const headers = req.headers.set('Authorization', header);
                req = req.clone({ headers });
            }
            return next
                .handle(req)
                .pipe(catchError(err => this.errorHandler.handleError(err)));
        }));
    }
};
DefaultOAuthInterceptor.ctorParameters = () => [
    { type: OAuthStorage },
    { type: OAuthService },
    { type: OAuthResourceServerErrorHandler },
    { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
];
DefaultOAuthInterceptor = __decorate([
    Injectable(),
    __param(3, Optional()),
    __metadata("design:paramtypes", [OAuthStorage,
        OAuthService,
        OAuthResourceServerErrorHandler,
        OAuthModuleConfig])
], DefaultOAuthInterceptor);
export { DefaultOAuthInterceptor };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUNMLFVBQVUsRUFDVixNQUFNLEVBQ04sR0FBRyxFQUNILElBQUksRUFDSixRQUFRLEVBQ1IsT0FBTyxFQUNSLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLCtCQUErQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDbEYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFDM0QsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLFVBQVUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFHaEQsSUFBYSx1QkFBdUIsR0FBcEMsTUFBYSx1QkFBdUI7SUFDbEMsWUFDVSxXQUF5QixFQUN6QixZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUgzQyxnQkFBVyxHQUFYLFdBQVcsQ0FBYztRQUN6QixpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ2xELENBQUM7SUFFSSxRQUFRLENBQUMsR0FBVztRQUMxQixJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLG1CQUFtQixFQUFFO1lBQ3hELE9BQU8sSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDbEU7UUFF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LCtCQUErQjtRQUNuQixpQkFBaUI7R0FMMUMsdUJBQXVCLENBcUVuQztTQXJFWSx1QkFBdUIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBPcHRpb25hbCB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuXG5pbXBvcnQge1xuICBIdHRwRXZlbnQsXG4gIEh0dHBIYW5kbGVyLFxuICBIdHRwSW50ZXJjZXB0b3IsXG4gIEh0dHBSZXF1ZXN0XG59IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcbmltcG9ydCB7IE9ic2VydmFibGUsIG9mLCBtZXJnZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0IHtcbiAgY2F0Y2hFcnJvcixcbiAgZmlsdGVyLFxuICBtYXAsXG4gIHRha2UsXG4gIG1lcmdlTWFwLFxuICB0aW1lb3V0XG59IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIgfSBmcm9tICcuL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyJztcbmltcG9ydCB7IE9BdXRoTW9kdWxlQ29uZmlnIH0gZnJvbSAnLi4vb2F1dGgtbW9kdWxlLmNvbmZpZyc7XG5pbXBvcnQgeyBPQXV0aFN0b3JhZ2UgfSBmcm9tICcuLi90eXBlcyc7XG5pbXBvcnQgeyBPQXV0aFNlcnZpY2UgfSBmcm9tICcuLi9vYXV0aC1zZXJ2aWNlJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIERlZmF1bHRPQXV0aEludGVyY2VwdG9yIGltcGxlbWVudHMgSHR0cEludGVyY2VwdG9yIHtcbiAgY29uc3RydWN0b3IoXG4gICAgcHJpdmF0ZSBhdXRoU3RvcmFnZTogT0F1dGhTdG9yYWdlLFxuICAgIHByaXZhdGUgb0F1dGhTZXJ2aWNlOiBPQXV0aFNlcnZpY2UsXG4gICAgcHJpdmF0ZSBlcnJvckhhbmRsZXI6IE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIsXG4gICAgQE9wdGlvbmFsKCkgcHJpdmF0ZSBtb2R1bGVDb25maWc6IE9BdXRoTW9kdWxlQ29uZmlnXG4gICkge31cblxuICBwcml2YXRlIGNoZWNrVXJsKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgaWYgKHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24pIHtcbiAgICAgIHJldHVybiB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5jdXN0b21VcmxWYWxpZGF0aW9uKHVybCk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmFsbG93ZWRVcmxzKSB7XG4gICAgICByZXR1cm4gISF0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscy5maW5kKHUgPT5cbiAgICAgICAgdXJsLnN0YXJ0c1dpdGgodSlcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBwdWJsaWMgaW50ZXJjZXB0KFxuICAgIHJlcTogSHR0cFJlcXVlc3Q8YW55PixcbiAgICBuZXh0OiBIdHRwSGFuZGxlclxuICApOiBPYnNlcnZhYmxlPEh0dHBFdmVudDxhbnk+PiB7XG4gICAgY29uc3QgdXJsID0gcmVxLnVybC50b0xvd2VyQ2FzZSgpO1xuXG4gICAgaWYgKFxuICAgICAgIXRoaXMubW9kdWxlQ29uZmlnIHx8XG4gICAgICAhdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIgfHxcbiAgICAgICF0aGlzLmNoZWNrVXJsKHVybClcbiAgICApIHtcbiAgICAgIHJldHVybiBuZXh0LmhhbmRsZShyZXEpO1xuICAgIH1cblxuICAgIGNvbnN0IHNlbmRBY2Nlc3NUb2tlbiA9IHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLnNlbmRBY2Nlc3NUb2tlbjtcblxuICAgIGlmICghc2VuZEFjY2Vzc1Rva2VuKSB7XG4gICAgICByZXR1cm4gbmV4dFxuICAgICAgICAuaGFuZGxlKHJlcSlcbiAgICAgICAgLnBpcGUoY2F0Y2hFcnJvcihlcnIgPT4gdGhpcy5lcnJvckhhbmRsZXIuaGFuZGxlRXJyb3IoZXJyKSkpO1xuICAgIH1cblxuICAgIHJldHVybiBtZXJnZShcbiAgICAgIG9mKHRoaXMub0F1dGhTZXJ2aWNlLmdldEFjY2Vzc1Rva2VuKCkpLnBpcGUoXG4gICAgICAgIGZpbHRlcih0b2tlbiA9PiAodG9rZW4gPyB0cnVlIDogZmFsc2UpKVxuICAgICAgKSxcbiAgICAgIHRoaXMub0F1dGhTZXJ2aWNlLmV2ZW50cy5waXBlKFxuICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxuICAgICAgICB0aW1lb3V0KHRoaXMub0F1dGhTZXJ2aWNlLndhaXRGb3JUb2tlbkluTXNlYyB8fCAwKSxcbiAgICAgICAgY2F0Y2hFcnJvcihfID0+IG9mKG51bGwpKSwgLy8gdGltZW91dCBpcyBub3QgYW4gZXJyb3JcbiAgICAgICAgbWFwKF8gPT4gdGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSlcbiAgICAgIClcbiAgICApLnBpcGUoXG4gICAgICB0YWtlKDEpLFxuICAgICAgbWVyZ2VNYXAodG9rZW4gPT4ge1xuICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICBjb25zdCBoZWFkZXIgPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICBjb25zdCBoZWFkZXJzID0gcmVxLmhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgaGVhZGVyKTtcbiAgICAgICAgICByZXEgPSByZXEuY2xvbmUoeyBoZWFkZXJzIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5leHRcbiAgICAgICAgICAuaGFuZGxlKHJlcSlcbiAgICAgICAgICAucGlwZShjYXRjaEVycm9yKGVyciA9PiB0aGlzLmVycm9ySGFuZGxlci5oYW5kbGVFcnJvcihlcnIpKSk7XG4gICAgICB9KVxuICAgICk7XG4gIH1cbn1cbiJdfQ==