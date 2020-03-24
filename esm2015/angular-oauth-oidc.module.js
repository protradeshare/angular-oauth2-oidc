var OAuthModule_1;
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
let OAuthModule = OAuthModule_1 = class OAuthModule {
    static forRoot(config = null, validationHandlerClass = NullValidationHandler) {
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
    }
};
OAuthModule = OAuthModule_1 = __decorate([
    NgModule({
        imports: [CommonModule],
        declarations: [],
        exports: []
    })
], OAuthModule);
export { OAuthModule };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJhbmd1bGFyLW9hdXRoLW9pZGMubW9kdWxlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsT0FBTyxFQUFFLFlBQVksRUFBRSxXQUFXLEVBQUUsTUFBTSxTQUFTLENBQUM7QUFDcEQsT0FBTyxFQUFFLFFBQVEsRUFBdUIsTUFBTSxlQUFlLENBQUM7QUFDOUQsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQy9DLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBRXpELE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUV4RCxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUMxRCxPQUFPLEVBQ0wsK0JBQStCLEVBQy9CLG1DQUFtQyxFQUNwQyxNQUFNLDhDQUE4QyxDQUFDO0FBQ3RELE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxNQUFNLDBDQUEwQyxDQUFDO0FBQ25GLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVDQUF1QyxDQUFDO0FBQzFFLE9BQU8sRUFBRSxxQkFBcUIsRUFBRSxNQUFNLDRDQUE0QyxDQUFDO0FBQ25GLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxvQkFBb0IsRUFBRSxNQUFNLGFBQWEsQ0FBQztBQUN4RSxPQUFPLEVBQ0wsV0FBVyxFQUNYLGtCQUFrQixFQUNuQixNQUFNLGlDQUFpQyxDQUFDO0FBT3pDLElBQWEsV0FBVyxtQkFBeEIsTUFBYSxXQUFXO0lBQ3RCLE1BQU0sQ0FBQyxPQUFPLENBQ1osU0FBNEIsSUFBSSxFQUNoQyxzQkFBc0IsR0FBRyxxQkFBcUI7UUFFOUMsT0FBTztZQUNMLFFBQVEsRUFBRSxhQUFXO1lBQ3JCLFNBQVMsRUFBRTtnQkFDVCxZQUFZO2dCQUNaLGdCQUFnQjtnQkFDaEIsRUFBRSxPQUFPLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxtQkFBbUIsRUFBRTtnQkFDekQsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLFVBQVUsRUFBRSxvQkFBb0IsRUFBRTtnQkFDM0QsRUFBRSxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsUUFBUSxFQUFFLHNCQUFzQixFQUFFO2dCQUNoRSxFQUFFLE9BQU8sRUFBRSxXQUFXLEVBQUUsUUFBUSxFQUFFLGtCQUFrQixFQUFFO2dCQUN0RDtvQkFDRSxPQUFPLEVBQUUsK0JBQStCO29CQUN4QyxRQUFRLEVBQUUsbUNBQW1DO2lCQUM5QztnQkFDRCxFQUFFLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFO2dCQUNoRDtvQkFDRSxPQUFPLEVBQUUsaUJBQWlCO29CQUMxQixRQUFRLEVBQUUsdUJBQXVCO29CQUNqQyxLQUFLLEVBQUUsSUFBSTtpQkFDWjthQUNGO1NBQ0YsQ0FBQztJQUNKLENBQUM7Q0FDRixDQUFBO0FBM0JZLFdBQVc7SUFMdkIsUUFBUSxDQUFDO1FBQ1IsT0FBTyxFQUFFLENBQUMsWUFBWSxDQUFDO1FBQ3ZCLFlBQVksRUFBRSxFQUFFO1FBQ2hCLE9BQU8sRUFBRSxFQUFFO0tBQ1osQ0FBQztHQUNXLFdBQVcsQ0EyQnZCO1NBM0JZLFdBQVciLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBPQXV0aFN0b3JhZ2UsIE9BdXRoTG9nZ2VyIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBOZ01vZHVsZSwgTW9kdWxlV2l0aFByb3ZpZGVycyB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgQ29tbW9uTW9kdWxlIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uJztcbmltcG9ydCB7IEhUVFBfSU5URVJDRVBUT1JTIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuXG5pbXBvcnQgeyBPQXV0aFNlcnZpY2UgfSBmcm9tICcuL29hdXRoLXNlcnZpY2UnO1xuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcblxuaW1wb3J0IHsgT0F1dGhNb2R1bGVDb25maWcgfSBmcm9tICcuL29hdXRoLW1vZHVsZS5jb25maWcnO1xuaW1wb3J0IHtcbiAgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcbiAgT0F1dGhOb29wUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXJcbn0gZnJvbSAnLi9pbnRlcmNlcHRvcnMvcmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXInO1xuaW1wb3J0IHsgRGVmYXVsdE9BdXRoSW50ZXJjZXB0b3IgfSBmcm9tICcuL2ludGVyY2VwdG9ycy9kZWZhdWx0LW9hdXRoLmludGVyY2VwdG9yJztcbmltcG9ydCB7IFZhbGlkYXRpb25IYW5kbGVyIH0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL3ZhbGlkYXRpb24taGFuZGxlcic7XG5pbXBvcnQgeyBOdWxsVmFsaWRhdGlvbkhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vbnVsbC12YWxpZGF0aW9uLWhhbmRsZXInO1xuaW1wb3J0IHsgY3JlYXRlRGVmYXVsdExvZ2dlciwgY3JlYXRlRGVmYXVsdFN0b3JhZ2UgfSBmcm9tICcuL2ZhY3Rvcmllcyc7XG5pbXBvcnQge1xuICBIYXNoSGFuZGxlcixcbiAgRGVmYXVsdEhhc2hIYW5kbGVyXG59IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9oYXNoLWhhbmRsZXInO1xuXG5ATmdNb2R1bGUoe1xuICBpbXBvcnRzOiBbQ29tbW9uTW9kdWxlXSxcbiAgZGVjbGFyYXRpb25zOiBbXSxcbiAgZXhwb3J0czogW11cbn0pXG5leHBvcnQgY2xhc3MgT0F1dGhNb2R1bGUge1xuICBzdGF0aWMgZm9yUm9vdChcbiAgICBjb25maWc6IE9BdXRoTW9kdWxlQ29uZmlnID0gbnVsbCxcbiAgICB2YWxpZGF0aW9uSGFuZGxlckNsYXNzID0gTnVsbFZhbGlkYXRpb25IYW5kbGVyXG4gICk6IE1vZHVsZVdpdGhQcm92aWRlcnM8T0F1dGhNb2R1bGU+IHtcbiAgICByZXR1cm4ge1xuICAgICAgbmdNb2R1bGU6IE9BdXRoTW9kdWxlLFxuICAgICAgcHJvdmlkZXJzOiBbXG4gICAgICAgIE9BdXRoU2VydmljZSxcbiAgICAgICAgVXJsSGVscGVyU2VydmljZSxcbiAgICAgICAgeyBwcm92aWRlOiBPQXV0aExvZ2dlciwgdXNlRmFjdG9yeTogY3JlYXRlRGVmYXVsdExvZ2dlciB9LFxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogY3JlYXRlRGVmYXVsdFN0b3JhZ2UgfSxcbiAgICAgICAgeyBwcm92aWRlOiBWYWxpZGF0aW9uSGFuZGxlciwgdXNlQ2xhc3M6IHZhbGlkYXRpb25IYW5kbGVyQ2xhc3MgfSxcbiAgICAgICAgeyBwcm92aWRlOiBIYXNoSGFuZGxlciwgdXNlQ2xhc3M6IERlZmF1bHRIYXNoSGFuZGxlciB9LFxuICAgICAgICB7XG4gICAgICAgICAgcHJvdmlkZTogT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcbiAgICAgICAgICB1c2VDbGFzczogT0F1dGhOb29wUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXJcbiAgICAgICAgfSxcbiAgICAgICAgeyBwcm92aWRlOiBPQXV0aE1vZHVsZUNvbmZpZywgdXNlVmFsdWU6IGNvbmZpZyB9LFxuICAgICAgICB7XG4gICAgICAgICAgcHJvdmlkZTogSFRUUF9JTlRFUkNFUFRPUlMsXG4gICAgICAgICAgdXNlQ2xhc3M6IERlZmF1bHRPQXV0aEludGVyY2VwdG9yLFxuICAgICAgICAgIG11bHRpOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9O1xuICB9XG59XG4iXX0=