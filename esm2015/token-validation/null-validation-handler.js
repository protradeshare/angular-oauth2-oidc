/**
 * A validation handler that isn't validating nothing.
 * Can be used to skip validation (at your own risk).
 */
export class NullValidationHandler {
    validateSignature(validationParams) {
        return Promise.resolve(null);
    }
    validateAtHash(validationParams) {
        return Promise.resolve(true);
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibnVsbC12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9udWxsLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFFQTs7O0dBR0c7QUFDSCxNQUFNLE9BQU8scUJBQXFCO0lBQ2hDLGlCQUFpQixDQUFDLGdCQUFrQztRQUNsRCxPQUFPLE9BQU8sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUM7SUFDL0IsQ0FBQztJQUNELGNBQWMsQ0FBQyxnQkFBa0M7UUFDL0MsT0FBTyxPQUFPLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO0lBQy9CLENBQUM7Q0FDRiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IFZhbGlkYXRpb25IYW5kbGVyLCBWYWxpZGF0aW9uUGFyYW1zIH0gZnJvbSAnLi92YWxpZGF0aW9uLWhhbmRsZXInO1xuXG4vKipcbiAqIEEgdmFsaWRhdGlvbiBoYW5kbGVyIHRoYXQgaXNuJ3QgdmFsaWRhdGluZyBub3RoaW5nLlxuICogQ2FuIGJlIHVzZWQgdG8gc2tpcCB2YWxpZGF0aW9uIChhdCB5b3VyIG93biByaXNrKS5cbiAqL1xuZXhwb3J0IGNsYXNzIE51bGxWYWxpZGF0aW9uSGFuZGxlciBpbXBsZW1lbnRzIFZhbGlkYXRpb25IYW5kbGVyIHtcbiAgdmFsaWRhdGVTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShudWxsKTtcbiAgfVxuICB2YWxpZGF0ZUF0SGFzaCh2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0cnVlKTtcbiAgfVxufVxuIl19