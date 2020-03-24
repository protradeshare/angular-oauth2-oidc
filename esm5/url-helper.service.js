import { __decorate } from "tslib";
import { Injectable } from '@angular/core';
var UrlHelperService = /** @class */ (function () {
    function UrlHelperService() {
    }
    UrlHelperService.prototype.getHashFragmentParams = function (customHashFragment) {
        var hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        var questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    };
    UrlHelperService.prototype.parseQueryString = function (queryString) {
        var data = {};
        var pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (var i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            }
            else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }
            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);
            if (key.substr(0, 1) === '/') {
                key = key.substr(1);
            }
            data[key] = value;
        }
        return data;
    };
    UrlHelperService = __decorate([
        Injectable()
    ], UrlHelperService);
    return UrlHelperService;
}());
export { UrlHelperService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXJsLWhlbHBlci5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInVybC1oZWxwZXIuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUczQztJQUFBO0lBdURBLENBQUM7SUF0RFEsZ0RBQXFCLEdBQTVCLFVBQTZCLGtCQUEyQjtRQUN0RCxJQUFJLElBQUksR0FBRyxrQkFBa0IsSUFBSSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQztRQUV0RCxJQUFJLEdBQUcsa0JBQWtCLENBQUMsSUFBSSxDQUFDLENBQUM7UUFFaEMsSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRTtZQUMzQixPQUFPLEVBQUUsQ0FBQztTQUNYO1FBRUQsSUFBTSxvQkFBb0IsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBRS9DLElBQUksb0JBQW9CLEdBQUcsQ0FBQyxDQUFDLEVBQUU7WUFDN0IsSUFBSSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsb0JBQW9CLEdBQUcsQ0FBQyxDQUFDLENBQUM7U0FDOUM7YUFBTTtZQUNMLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ3ZCO1FBRUQsT0FBTyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsSUFBSSxDQUFDLENBQUM7SUFDckMsQ0FBQztJQUVNLDJDQUFnQixHQUF2QixVQUF3QixXQUFtQjtRQUN6QyxJQUFNLElBQUksR0FBRyxFQUFFLENBQUM7UUFDaEIsSUFBSSxLQUFLLEVBQUUsSUFBSSxFQUFFLGNBQWMsRUFBRSxVQUFVLEVBQUUsWUFBWSxFQUFFLEdBQUcsRUFBRSxLQUFLLENBQUM7UUFFdEUsSUFBSSxXQUFXLEtBQUssSUFBSSxFQUFFO1lBQ3hCLE9BQU8sSUFBSSxDQUFDO1NBQ2I7UUFFRCxLQUFLLEdBQUcsV0FBVyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUUvQixLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsS0FBSyxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRTtZQUNyQyxJQUFJLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLGNBQWMsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBRW5DLElBQUksY0FBYyxLQUFLLENBQUMsQ0FBQyxFQUFFO2dCQUN6QixVQUFVLEdBQUcsSUFBSSxDQUFDO2dCQUNsQixZQUFZLEdBQUcsSUFBSSxDQUFDO2FBQ3JCO2lCQUFNO2dCQUNMLFVBQVUsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxjQUFjLENBQUMsQ0FBQztnQkFDNUMsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsY0FBYyxHQUFHLENBQUMsQ0FBQyxDQUFDO2FBQ2hEO1lBRUQsR0FBRyxHQUFHLGtCQUFrQixDQUFDLFVBQVUsQ0FBQyxDQUFDO1lBQ3JDLEtBQUssR0FBRyxrQkFBa0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztZQUV6QyxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxLQUFLLEdBQUcsRUFBRTtnQkFDNUIsR0FBRyxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7YUFDckI7WUFFRCxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsS0FBSyxDQUFDO1NBQ25CO1FBRUQsT0FBTyxJQUFJLENBQUM7SUFDZCxDQUFDO0lBdERVLGdCQUFnQjtRQUQ1QixVQUFVLEVBQUU7T0FDQSxnQkFBZ0IsQ0F1RDVCO0lBQUQsdUJBQUM7Q0FBQSxBQXZERCxJQXVEQztTQXZEWSxnQkFBZ0IiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBVcmxIZWxwZXJTZXJ2aWNlIHtcbiAgcHVibGljIGdldEhhc2hGcmFnbWVudFBhcmFtcyhjdXN0b21IYXNoRnJhZ21lbnQ/OiBzdHJpbmcpOiBvYmplY3Qge1xuICAgIGxldCBoYXNoID0gY3VzdG9tSGFzaEZyYWdtZW50IHx8IHdpbmRvdy5sb2NhdGlvbi5oYXNoO1xuXG4gICAgaGFzaCA9IGRlY29kZVVSSUNvbXBvbmVudChoYXNoKTtcblxuICAgIGlmIChoYXNoLmluZGV4T2YoJyMnKSAhPT0gMCkge1xuICAgICAgcmV0dXJuIHt9O1xuICAgIH1cblxuICAgIGNvbnN0IHF1ZXN0aW9uTWFya1Bvc2l0aW9uID0gaGFzaC5pbmRleE9mKCc/Jyk7XG5cbiAgICBpZiAocXVlc3Rpb25NYXJrUG9zaXRpb24gPiAtMSkge1xuICAgICAgaGFzaCA9IGhhc2guc3Vic3RyKHF1ZXN0aW9uTWFya1Bvc2l0aW9uICsgMSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGhhc2ggPSBoYXNoLnN1YnN0cigxKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5wYXJzZVF1ZXJ5U3RyaW5nKGhhc2gpO1xuICB9XG5cbiAgcHVibGljIHBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XG4gICAgY29uc3QgZGF0YSA9IHt9O1xuICAgIGxldCBwYWlycywgcGFpciwgc2VwYXJhdG9ySW5kZXgsIGVzY2FwZWRLZXksIGVzY2FwZWRWYWx1ZSwga2V5LCB2YWx1ZTtcblxuICAgIGlmIChxdWVyeVN0cmluZyA9PT0gbnVsbCkge1xuICAgICAgcmV0dXJuIGRhdGE7XG4gICAgfVxuXG4gICAgcGFpcnMgPSBxdWVyeVN0cmluZy5zcGxpdCgnJicpO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBwYWlycy5sZW5ndGg7IGkrKykge1xuICAgICAgcGFpciA9IHBhaXJzW2ldO1xuICAgICAgc2VwYXJhdG9ySW5kZXggPSBwYWlyLmluZGV4T2YoJz0nKTtcblxuICAgICAgaWYgKHNlcGFyYXRvckluZGV4ID09PSAtMSkge1xuICAgICAgICBlc2NhcGVkS2V5ID0gcGFpcjtcbiAgICAgICAgZXNjYXBlZFZhbHVlID0gbnVsbDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGVzY2FwZWRLZXkgPSBwYWlyLnN1YnN0cigwLCBzZXBhcmF0b3JJbmRleCk7XG4gICAgICAgIGVzY2FwZWRWYWx1ZSA9IHBhaXIuc3Vic3RyKHNlcGFyYXRvckluZGV4ICsgMSk7XG4gICAgICB9XG5cbiAgICAgIGtleSA9IGRlY29kZVVSSUNvbXBvbmVudChlc2NhcGVkS2V5KTtcbiAgICAgIHZhbHVlID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZWRWYWx1ZSk7XG5cbiAgICAgIGlmIChrZXkuc3Vic3RyKDAsIDEpID09PSAnLycpIHtcbiAgICAgICAga2V5ID0ga2V5LnN1YnN0cigxKTtcbiAgICAgIH1cblxuICAgICAgZGF0YVtrZXldID0gdmFsdWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIGRhdGE7XG4gIH1cbn1cbiJdfQ==