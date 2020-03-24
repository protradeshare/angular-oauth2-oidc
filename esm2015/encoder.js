/**
 * This custom encoder allows charactes like +, % and / to be used in passwords
 */
export class WebHttpUrlEncodingCodec {
    encodeKey(k) {
        return encodeURIComponent(k);
    }
    encodeValue(v) {
        return encodeURIComponent(v);
    }
    decodeKey(k) {
        return decodeURIComponent(k);
    }
    decodeValue(v) {
        return decodeURIComponent(v);
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZW5jb2Rlci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJlbmNvZGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUNBOztHQUVHO0FBQ0gsTUFBTSxPQUFPLHVCQUF1QjtJQUNsQyxTQUFTLENBQUMsQ0FBUztRQUNqQixPQUFPLGtCQUFrQixDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQy9CLENBQUM7SUFFRCxXQUFXLENBQUMsQ0FBUztRQUNuQixPQUFPLGtCQUFrQixDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQy9CLENBQUM7SUFFRCxTQUFTLENBQUMsQ0FBUztRQUNqQixPQUFPLGtCQUFrQixDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQy9CLENBQUM7SUFFRCxXQUFXLENBQUMsQ0FBUztRQUNuQixPQUFPLGtCQUFrQixDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQy9CLENBQUM7Q0FDRiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEh0dHBQYXJhbWV0ZXJDb2RlYyB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcbi8qKlxuICogVGhpcyBjdXN0b20gZW5jb2RlciBhbGxvd3MgY2hhcmFjdGVzIGxpa2UgKywgJSBhbmQgLyB0byBiZSB1c2VkIGluIHBhc3N3b3Jkc1xuICovXG5leHBvcnQgY2xhc3MgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgaW1wbGVtZW50cyBIdHRwUGFyYW1ldGVyQ29kZWMge1xuICBlbmNvZGVLZXkoazogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KGspO1xuICB9XG5cbiAgZW5jb2RlVmFsdWUodjogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KHYpO1xuICB9XG5cbiAgZGVjb2RlS2V5KGs6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudChrKTtcbiAgfVxuXG4gIGRlY29kZVZhbHVlKHY6IHN0cmluZykge1xuICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQodik7XG4gIH1cbn1cbiJdfQ==