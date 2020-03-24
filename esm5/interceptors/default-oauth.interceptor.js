import { __decorate, __metadata, __param } from "tslib";
import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout } from 'rxjs/operators';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';
import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthStorage } from '../types';
import { OAuthService } from '../oauth-service';
var DefaultOAuthInterceptor = /** @class */ (function () {
    function DefaultOAuthInterceptor(authStorage, oAuthService, errorHandler, moduleConfig) {
        this.authStorage = authStorage;
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    DefaultOAuthInterceptor.prototype.checkUrl = function (url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find(function (u) {
                return url.startsWith(u);
            });
        }
        return true;
    };
    DefaultOAuthInterceptor.prototype.intercept = function (req, next) {
        var _this = this;
        var url = req.url.toLowerCase();
        if (!this.moduleConfig ||
            !this.moduleConfig.resourceServer ||
            !this.checkUrl(url)) {
            return next.handle(req);
        }
        var sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError(function (err) { return _this.errorHandler.handleError(err); }));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter(function (token) { return (token ? true : false); })), this.oAuthService.events.pipe(filter(function (e) { return e.type === 'token_received'; }), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError(function (_) { return of(null); }), // timeout is not an error
        map(function (_) { return _this.oAuthService.getAccessToken(); }))).pipe(take(1), mergeMap(function (token) {
            if (token) {
                var header = 'Bearer ' + token;
                var headers = req.headers.set('Authorization', header);
                req = req.clone({ headers: headers });
            }
            return next
                .handle(req)
                .pipe(catchError(function (err) { return _this.errorHandler.handleError(err); }));
        }));
    };
    DefaultOAuthInterceptor.ctorParameters = function () { return [
        { type: OAuthStorage },
        { type: OAuthService },
        { type: OAuthResourceServerErrorHandler },
        { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
    ]; };
    DefaultOAuthInterceptor = __decorate([
        Injectable(),
        __param(3, Optional()),
        __metadata("design:paramtypes", [OAuthStorage,
            OAuthService,
            OAuthResourceServerErrorHandler,
            OAuthModuleConfig])
    ], DefaultOAuthInterceptor);
    return DefaultOAuthInterceptor;
}());
export { DefaultOAuthInterceptor };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUNMLFVBQVUsRUFDVixNQUFNLEVBQ04sR0FBRyxFQUNILElBQUksRUFDSixRQUFRLEVBQ1IsT0FBTyxFQUNSLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLCtCQUErQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDbEYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFDM0QsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLFVBQVUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFHaEQ7SUFDRSxpQ0FDVSxXQUF5QixFQUN6QixZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUgzQyxnQkFBVyxHQUFYLFdBQVcsQ0FBYztRQUN6QixpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ2xELENBQUM7SUFFSSwwQ0FBUSxHQUFoQixVQUFpQixHQUFXO1FBQzFCLElBQUksSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLEVBQUU7WUFDeEQsT0FBTyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUNsRTtRQUVELElBQUksSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsV0FBVyxFQUFFO1lBQ2hELE9BQU8sQ0FBQyxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLFdBQVcsQ0FBQyxJQUFJLENBQUMsVUFBQSxDQUFDO2dCQUMxRCxPQUFBLEdBQUcsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDO1lBQWpCLENBQWlCLENBQ2xCLENBQUM7U0FDSDtRQUVELE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQztJQUVNLDJDQUFTLEdBQWhCLFVBQ0UsR0FBcUIsRUFDckIsSUFBaUI7UUFGbkIsaUJBOENDO1FBMUNDLElBQU0sR0FBRyxHQUFHLEdBQUcsQ0FBQyxHQUFHLENBQUMsV0FBVyxFQUFFLENBQUM7UUFFbEMsSUFDRSxDQUFDLElBQUksQ0FBQyxZQUFZO1lBQ2xCLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjO1lBQ2pDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFDbkI7WUFDQSxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDekI7UUFFRCxJQUFNLGVBQWUsR0FBRyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxlQUFlLENBQUM7UUFFekUsSUFBSSxDQUFDLGVBQWUsRUFBRTtZQUNwQixPQUFPLElBQUk7aUJBQ1IsTUFBTSxDQUFDLEdBQUcsQ0FBQztpQkFDWCxJQUFJLENBQUMsVUFBVSxDQUFDLFVBQUEsR0FBRyxJQUFJLE9BQUEsS0FBSSxDQUFDLFlBQVksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQWxDLENBQWtDLENBQUMsQ0FBQyxDQUFDO1NBQ2hFO1FBRUQsT0FBTyxLQUFLLENBQ1YsRUFBRSxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQ3pDLE1BQU0sQ0FBQyxVQUFBLEtBQUssSUFBSSxPQUFBLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxFQUF0QixDQUFzQixDQUFDLENBQ3hDLEVBQ0QsSUFBSSxDQUFDLFlBQVksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUMzQixNQUFNLENBQUMsVUFBQSxDQUFDLElBQUksT0FBQSxDQUFDLENBQUMsSUFBSSxLQUFLLGdCQUFnQixFQUEzQixDQUEyQixDQUFDLEVBQ3hDLE9BQU8sQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLGtCQUFrQixJQUFJLENBQUMsQ0FBQyxFQUNsRCxVQUFVLENBQUMsVUFBQSxDQUFDLElBQUksT0FBQSxFQUFFLENBQUMsSUFBSSxDQUFDLEVBQVIsQ0FBUSxDQUFDLEVBQUUsMEJBQTBCO1FBQ3JELEdBQUcsQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLEtBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxFQUFFLEVBQWxDLENBQWtDLENBQUMsQ0FDN0MsQ0FDRixDQUFDLElBQUksQ0FDSixJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQ1AsUUFBUSxDQUFDLFVBQUEsS0FBSztZQUNaLElBQUksS0FBSyxFQUFFO2dCQUNULElBQU0sTUFBTSxHQUFHLFNBQVMsR0FBRyxLQUFLLENBQUM7Z0JBQ2pDLElBQU0sT0FBTyxHQUFHLEdBQUcsQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLGVBQWUsRUFBRSxNQUFNLENBQUMsQ0FBQztnQkFDekQsR0FBRyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRSxPQUFPLFNBQUEsRUFBRSxDQUFDLENBQUM7YUFDOUI7WUFFRCxPQUFPLElBQUk7aUJBQ1IsTUFBTSxDQUFDLEdBQUcsQ0FBQztpQkFDWCxJQUFJLENBQUMsVUFBVSxDQUFDLFVBQUEsR0FBRyxJQUFJLE9BQUEsS0FBSSxDQUFDLFlBQVksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQWxDLENBQWtDLENBQUMsQ0FBQyxDQUFDO1FBQ2pFLENBQUMsQ0FBQyxDQUNILENBQUM7SUFDSixDQUFDOztnQkFsRXNCLFlBQVk7Z0JBQ1gsWUFBWTtnQkFDWiwrQkFBK0I7Z0JBQ25CLGlCQUFpQix1QkFBbEQsUUFBUTs7SUFMQSx1QkFBdUI7UUFEbkMsVUFBVSxFQUFFO1FBTVIsV0FBQSxRQUFRLEVBQUUsQ0FBQTt5Q0FIVSxZQUFZO1lBQ1gsWUFBWTtZQUNaLCtCQUErQjtZQUNuQixpQkFBaUI7T0FMMUMsdUJBQXVCLENBcUVuQztJQUFELDhCQUFDO0NBQUEsQUFyRUQsSUFxRUM7U0FyRVksdUJBQXVCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgT3B0aW9uYWwgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcblxuaW1wb3J0IHtcbiAgSHR0cEV2ZW50LFxuICBIdHRwSGFuZGxlcixcbiAgSHR0cEludGVyY2VwdG9yLFxuICBIdHRwUmVxdWVzdFxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBvZiwgbWVyZ2UgfSBmcm9tICdyeGpzJztcbmltcG9ydCB7XG4gIGNhdGNoRXJyb3IsXG4gIGZpbHRlcixcbiAgbWFwLFxuICB0YWtlLFxuICBtZXJnZU1hcCxcbiAgdGltZW91dFxufSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyIH0gZnJvbSAnLi9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlcic7XG5pbXBvcnQgeyBPQXV0aE1vZHVsZUNvbmZpZyB9IGZyb20gJy4uL29hdXRoLW1vZHVsZS5jb25maWcnO1xuaW1wb3J0IHsgT0F1dGhTdG9yYWdlIH0gZnJvbSAnLi4vdHlwZXMnO1xuaW1wb3J0IHsgT0F1dGhTZXJ2aWNlIH0gZnJvbSAnLi4vb2F1dGgtc2VydmljZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciBpbXBsZW1lbnRzIEh0dHBJbnRlcmNlcHRvciB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHByaXZhdGUgYXV0aFN0b3JhZ2U6IE9BdXRoU3RvcmFnZSxcbiAgICBwcml2YXRlIG9BdXRoU2VydmljZTogT0F1dGhTZXJ2aWNlLFxuICAgIHByaXZhdGUgZXJyb3JIYW5kbGVyOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICAgIEBPcHRpb25hbCgpIHByaXZhdGUgbW9kdWxlQ29uZmlnOiBPQXV0aE1vZHVsZUNvbmZpZ1xuICApIHt9XG5cbiAgcHJpdmF0ZSBjaGVja1VybCh1cmw6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIGlmICh0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5jdXN0b21VcmxWYWxpZGF0aW9uKSB7XG4gICAgICByZXR1cm4gdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuY3VzdG9tVXJsVmFsaWRhdGlvbih1cmwpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscykge1xuICAgICAgcmV0dXJuICEhdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMuZmluZCh1ID0+XG4gICAgICAgIHVybC5zdGFydHNXaXRoKHUpXG4gICAgICApO1xuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xuICB9XG5cbiAgcHVibGljIGludGVyY2VwdChcbiAgICByZXE6IEh0dHBSZXF1ZXN0PGFueT4sXG4gICAgbmV4dDogSHR0cEhhbmRsZXJcbiAgKTogT2JzZXJ2YWJsZTxIdHRwRXZlbnQ8YW55Pj4ge1xuICAgIGNvbnN0IHVybCA9IHJlcS51cmwudG9Mb3dlckNhc2UoKTtcblxuICAgIGlmIChcbiAgICAgICF0aGlzLm1vZHVsZUNvbmZpZyB8fFxuICAgICAgIXRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyIHx8XG4gICAgICAhdGhpcy5jaGVja1VybCh1cmwpXG4gICAgKSB7XG4gICAgICByZXR1cm4gbmV4dC5oYW5kbGUocmVxKTtcbiAgICB9XG5cbiAgICBjb25zdCBzZW5kQWNjZXNzVG9rZW4gPSB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5zZW5kQWNjZXNzVG9rZW47XG5cbiAgICBpZiAoIXNlbmRBY2Nlc3NUb2tlbikge1xuICAgICAgcmV0dXJuIG5leHRcbiAgICAgICAgLmhhbmRsZShyZXEpXG4gICAgICAgIC5waXBlKGNhdGNoRXJyb3IoZXJyID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcbiAgICB9XG5cbiAgICByZXR1cm4gbWVyZ2UoXG4gICAgICBvZih0aGlzLm9BdXRoU2VydmljZS5nZXRBY2Nlc3NUb2tlbigpKS5waXBlKFxuICAgICAgICBmaWx0ZXIodG9rZW4gPT4gKHRva2VuID8gdHJ1ZSA6IGZhbHNlKSlcbiAgICAgICksXG4gICAgICB0aGlzLm9BdXRoU2VydmljZS5ldmVudHMucGlwZShcbiAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcbiAgICAgICAgdGltZW91dCh0aGlzLm9BdXRoU2VydmljZS53YWl0Rm9yVG9rZW5Jbk1zZWMgfHwgMCksXG4gICAgICAgIGNhdGNoRXJyb3IoXyA9PiBvZihudWxsKSksIC8vIHRpbWVvdXQgaXMgbm90IGFuIGVycm9yXG4gICAgICAgIG1hcChfID0+IHRoaXMub0F1dGhTZXJ2aWNlLmdldEFjY2Vzc1Rva2VuKCkpXG4gICAgICApXG4gICAgKS5waXBlKFxuICAgICAgdGFrZSgxKSxcbiAgICAgIG1lcmdlTWFwKHRva2VuID0+IHtcbiAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgY29uc3QgaGVhZGVyID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgY29uc3QgaGVhZGVycyA9IHJlcS5oZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsIGhlYWRlcik7XG4gICAgICAgICAgcmVxID0gcmVxLmNsb25lKHsgaGVhZGVycyB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXh0XG4gICAgICAgICAgLmhhbmRsZShyZXEpXG4gICAgICAgICAgLnBpcGUoY2F0Y2hFcnJvcihlcnIgPT4gdGhpcy5lcnJvckhhbmRsZXIuaGFuZGxlRXJyb3IoZXJyKSkpO1xuICAgICAgfSlcbiAgICApO1xuICB9XG59XG4iXX0=