import { __decorate } from "tslib";
import { OAuthStorage, OAuthLogger } from './types';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthService } from './oauth-service';
import { UrlHelperService } from './url-helper.service';
import { OAuthModuleConfig } from './oauth-module.config';
import { OAuthResourceServerErrorHandler, OAuthNoopResourceServerErrorHandler } from './interceptors/resource-server-error-handler';
import { DefaultOAuthInterceptor } from './interceptors/default-oauth.interceptor';
import { ValidationHandler } from './token-validation/validation-handler';
import { NullValidationHandler } from './token-validation/null-validation-handler';
import { createDefaultLogger, createDefaultStorage } from './factories';
import { HashHandler, DefaultHashHandler } from './token-validation/hash-handler';
var OAuthModule = /** @class */ (function () {
    function OAuthModule() {
    }
    OAuthModule_1 = OAuthModule;
    OAuthModule.forRoot = function (config, validationHandlerClass) {
        if (config === void 0) { config = null; }
        if (validationHandlerClass === void 0) { validationHandlerClass = NullValidationHandler; }
        return {
            ngModule: OAuthModule_1,
            providers: [
                OAuthService,
                UrlHelperService,
                { provide: OAuthLogger, useFactory: createDefaultLogger },
                { provide: OAuthStorage, useFactory: createDefaultStorage },
                { provide: ValidationHandler, useClass: validationHandlerClass },
                { provide: HashHandler, useClass: DefaultHashHandler },
                {
                    provide: OAuthResourceServerErrorHandler,
                    useClass: OAuthNoopResourceServerErrorHandler
                },
                { provide: OAuthModuleConfig, useValue: config },
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: DefaultOAuthInterceptor,
                    multi: true
                }
            ]
        };
    };
    var OAuthModule_1;
    OAuthModule = OAuthModule_1 = __decorate([
        NgModule({
            imports: [CommonModule],
            declarations: [],
            exports: []
        })
    ], OAuthModule);
    return OAuthModule;
}());
export { OAuthModule };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJhbmd1bGFyLW9hdXRoLW9pZGMubW9kdWxlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsWUFBWSxFQUFFLFdBQVcsRUFBRSxNQUFNLFNBQVMsQ0FBQztBQUNwRCxPQUFPLEVBQUUsUUFBUSxFQUF1QixNQUFNLGVBQWUsQ0FBQztBQUM5RCxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDL0MsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFFekQsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQy9DLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBRXhELE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQzFELE9BQU8sRUFDTCwrQkFBK0IsRUFDL0IsbUNBQW1DLEVBQ3BDLE1BQU0sOENBQThDLENBQUM7QUFDdEQsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sMENBQTBDLENBQUM7QUFDbkYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sdUNBQXVDLENBQUM7QUFDMUUsT0FBTyxFQUFFLHFCQUFxQixFQUFFLE1BQU0sNENBQTRDLENBQUM7QUFDbkYsT0FBTyxFQUFFLG1CQUFtQixFQUFFLG9CQUFvQixFQUFFLE1BQU0sYUFBYSxDQUFDO0FBQ3hFLE9BQU8sRUFDTCxXQUFXLEVBQ1gsa0JBQWtCLEVBQ25CLE1BQU0saUNBQWlDLENBQUM7QUFPekM7SUFBQTtJQTJCQSxDQUFDO29CQTNCWSxXQUFXO0lBQ2YsbUJBQU8sR0FBZCxVQUNFLE1BQWdDLEVBQ2hDLHNCQUE4QztRQUQ5Qyx1QkFBQSxFQUFBLGFBQWdDO1FBQ2hDLHVDQUFBLEVBQUEsOENBQThDO1FBRTlDLE9BQU87WUFDTCxRQUFRLEVBQUUsYUFBVztZQUNyQixTQUFTLEVBQUU7Z0JBQ1QsWUFBWTtnQkFDWixnQkFBZ0I7Z0JBQ2hCLEVBQUUsT0FBTyxFQUFFLFdBQVcsRUFBRSxVQUFVLEVBQUUsbUJBQW1CLEVBQUU7Z0JBQ3pELEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxVQUFVLEVBQUUsb0JBQW9CLEVBQUU7Z0JBQzNELEVBQUUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLFFBQVEsRUFBRSxzQkFBc0IsRUFBRTtnQkFDaEUsRUFBRSxPQUFPLEVBQUUsV0FBVyxFQUFFLFFBQVEsRUFBRSxrQkFBa0IsRUFBRTtnQkFDdEQ7b0JBQ0UsT0FBTyxFQUFFLCtCQUErQjtvQkFDeEMsUUFBUSxFQUFFLG1DQUFtQztpQkFDOUM7Z0JBQ0QsRUFBRSxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsUUFBUSxFQUFFLE1BQU0sRUFBRTtnQkFDaEQ7b0JBQ0UsT0FBTyxFQUFFLGlCQUFpQjtvQkFDMUIsUUFBUSxFQUFFLHVCQUF1QjtvQkFDakMsS0FBSyxFQUFFLElBQUk7aUJBQ1o7YUFDRjtTQUNGLENBQUM7SUFDSixDQUFDOztJQTFCVSxXQUFXO1FBTHZCLFFBQVEsQ0FBQztZQUNSLE9BQU8sRUFBRSxDQUFDLFlBQVksQ0FBQztZQUN2QixZQUFZLEVBQUUsRUFBRTtZQUNoQixPQUFPLEVBQUUsRUFBRTtTQUNaLENBQUM7T0FDVyxXQUFXLENBMkJ2QjtJQUFELGtCQUFDO0NBQUEsQUEzQkQsSUEyQkM7U0EzQlksV0FBVyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE9BdXRoU3RvcmFnZSwgT0F1dGhMb2dnZXIgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IE5nTW9kdWxlLCBNb2R1bGVXaXRoUHJvdmlkZXJzIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBDb21tb25Nb2R1bGUgfSBmcm9tICdAYW5ndWxhci9jb21tb24nO1xuaW1wb3J0IHsgSFRUUF9JTlRFUkNFUFRPUlMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5cbmltcG9ydCB7IE9BdXRoU2VydmljZSB9IGZyb20gJy4vb2F1dGgtc2VydmljZSc7XG5pbXBvcnQgeyBVcmxIZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi91cmwtaGVscGVyLnNlcnZpY2UnO1xuXG5pbXBvcnQgeyBPQXV0aE1vZHVsZUNvbmZpZyB9IGZyb20gJy4vb2F1dGgtbW9kdWxlLmNvbmZpZyc7XG5pbXBvcnQge1xuICBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxufSBmcm9tICcuL2ludGVyY2VwdG9ycy9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlcic7XG5pbXBvcnQgeyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3JzL2RlZmF1bHQtb2F1dGguaW50ZXJjZXB0b3InO1xuaW1wb3J0IHsgVmFsaWRhdGlvbkhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcbmltcG9ydCB7IE51bGxWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9udWxsLXZhbGlkYXRpb24taGFuZGxlcic7XG5pbXBvcnQgeyBjcmVhdGVEZWZhdWx0TG9nZ2VyLCBjcmVhdGVEZWZhdWx0U3RvcmFnZSB9IGZyb20gJy4vZmFjdG9yaWVzJztcbmltcG9ydCB7XG4gIEhhc2hIYW5kbGVyLFxuICBEZWZhdWx0SGFzaEhhbmRsZXJcbn0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL2hhc2gtaGFuZGxlcic7XG5cbkBOZ01vZHVsZSh7XG4gIGltcG9ydHM6IFtDb21tb25Nb2R1bGVdLFxuICBkZWNsYXJhdGlvbnM6IFtdLFxuICBleHBvcnRzOiBbXVxufSlcbmV4cG9ydCBjbGFzcyBPQXV0aE1vZHVsZSB7XG4gIHN0YXRpYyBmb3JSb290KFxuICAgIGNvbmZpZzogT0F1dGhNb2R1bGVDb25maWcgPSBudWxsLFxuICAgIHZhbGlkYXRpb25IYW5kbGVyQ2xhc3MgPSBOdWxsVmFsaWRhdGlvbkhhbmRsZXJcbiAgKTogTW9kdWxlV2l0aFByb3ZpZGVyczxPQXV0aE1vZHVsZT4ge1xuICAgIHJldHVybiB7XG4gICAgICBuZ01vZHVsZTogT0F1dGhNb2R1bGUsXG4gICAgICBwcm92aWRlcnM6IFtcbiAgICAgICAgT0F1dGhTZXJ2aWNlLFxuICAgICAgICBVcmxIZWxwZXJTZXJ2aWNlLFxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoTG9nZ2VyLCB1c2VGYWN0b3J5OiBjcmVhdGVEZWZhdWx0TG9nZ2VyIH0sXG4gICAgICAgIHsgcHJvdmlkZTogT0F1dGhTdG9yYWdlLCB1c2VGYWN0b3J5OiBjcmVhdGVEZWZhdWx0U3RvcmFnZSB9LFxuICAgICAgICB7IHByb3ZpZGU6IFZhbGlkYXRpb25IYW5kbGVyLCB1c2VDbGFzczogdmFsaWRhdGlvbkhhbmRsZXJDbGFzcyB9LFxuICAgICAgICB7IHByb3ZpZGU6IEhhc2hIYW5kbGVyLCB1c2VDbGFzczogRGVmYXVsdEhhc2hIYW5kbGVyIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBwcm92aWRlOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICAgICAgICAgIHVzZUNsYXNzOiBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxuICAgICAgICB9LFxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoTW9kdWxlQ29uZmlnLCB1c2VWYWx1ZTogY29uZmlnIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBwcm92aWRlOiBIVFRQX0lOVEVSQ0VQVE9SUyxcbiAgICAgICAgICB1c2VDbGFzczogRGVmYXVsdE9BdXRoSW50ZXJjZXB0b3IsXG4gICAgICAgICAgbXVsdGk6IHRydWVcbiAgICAgICAgfVxuICAgICAgXVxuICAgIH07XG4gIH1cbn1cbiJdfQ==