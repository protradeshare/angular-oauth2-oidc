import { __awaiter, __decorate, __generator, __values } from "tslib";
import { Injectable } from '@angular/core';
import { sha256 } from 'js-sha256';
/**
 * Abstraction for crypto algorithms
 */
var HashHandler = /** @class */ (function () {
    function HashHandler() {
    }
    return HashHandler;
}());
export { HashHandler };
var DefaultHashHandler = /** @class */ (function () {
    function DefaultHashHandler() {
    }
    DefaultHashHandler.prototype.calcHash = function (valueToHash, algorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var hashArray, hashString;
            return __generator(this, function (_a) {
                hashArray = sha256.array(valueToHash);
                hashString = this.toHashString2(hashArray);
                return [2 /*return*/, hashString];
            });
        });
    };
    DefaultHashHandler.prototype.toHashString2 = function (byteArray) {
        var e_1, _a;
        var result = '';
        try {
            for (var byteArray_1 = __values(byteArray), byteArray_1_1 = byteArray_1.next(); !byteArray_1_1.done; byteArray_1_1 = byteArray_1.next()) {
                var e = byteArray_1_1.value;
                result += String.fromCharCode(e);
            }
        }
        catch (e_1_1) { e_1 = { error: e_1_1 }; }
        finally {
            try {
                if (byteArray_1_1 && !byteArray_1_1.done && (_a = byteArray_1.return)) _a.call(byteArray_1);
            }
            finally { if (e_1) throw e_1.error; }
        }
        return result;
    };
    DefaultHashHandler.prototype.toHashString = function (buffer) {
        var e_2, _a;
        var byteArray = new Uint8Array(buffer);
        var result = '';
        try {
            for (var byteArray_2 = __values(byteArray), byteArray_2_1 = byteArray_2.next(); !byteArray_2_1.done; byteArray_2_1 = byteArray_2.next()) {
                var e = byteArray_2_1.value;
                result += String.fromCharCode(e);
            }
        }
        catch (e_2_1) { e_2 = { error: e_2_1 }; }
        finally {
            try {
                if (byteArray_2_1 && !byteArray_2_1.done && (_a = byteArray_2.return)) _a.call(byteArray_2);
            }
            finally { if (e_2) throw e_2.error; }
        }
        return result;
    };
    DefaultHashHandler = __decorate([
        Injectable()
    ], DefaultHashHandler);
    return DefaultHashHandler;
}());
export { DefaultHashHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGFzaC1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRTNDLE9BQU8sRUFBRSxNQUFNLEVBQUUsTUFBTSxXQUFXLENBQUM7QUFFbkM7O0dBRUc7QUFDSDtJQUFBO0lBRUEsQ0FBQztJQUFELGtCQUFDO0FBQUQsQ0FBQyxBQUZELElBRUM7O0FBR0Q7SUFBQTtJQWtEQSxDQUFDO0lBakRPLHFDQUFRLEdBQWQsVUFBZSxXQUFtQixFQUFFLFNBQWlCOzs7O2dCQUs3QyxTQUFTLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxXQUFXLENBQUMsQ0FBQztnQkFFdEMsVUFBVSxHQUFHLElBQUksQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUM7Z0JBRWpELHNCQUFPLFVBQVUsRUFBQzs7O0tBQ25CO0lBRUQsMENBQWEsR0FBYixVQUFjLFNBQW1COztRQUMvQixJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUM7O1lBQ2hCLEtBQWMsSUFBQSxjQUFBLFNBQUEsU0FBUyxDQUFBLG9DQUFBLDJEQUFFO2dCQUFwQixJQUFJLENBQUMsc0JBQUE7Z0JBQ1IsTUFBTSxJQUFJLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLENBQUM7YUFDbEM7Ozs7Ozs7OztRQUNELE9BQU8sTUFBTSxDQUFDO0lBQ2hCLENBQUM7SUFFRCx5Q0FBWSxHQUFaLFVBQWEsTUFBbUI7O1FBQzlCLElBQU0sU0FBUyxHQUFHLElBQUksVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ3pDLElBQUksTUFBTSxHQUFHLEVBQUUsQ0FBQzs7WUFDaEIsS0FBYyxJQUFBLGNBQUEsU0FBQSxTQUFTLENBQUEsb0NBQUEsMkRBQUU7Z0JBQXBCLElBQUksQ0FBQyxzQkFBQTtnQkFDUixNQUFNLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQzthQUNsQzs7Ozs7Ozs7O1FBQ0QsT0FBTyxNQUFNLENBQUM7SUFDaEIsQ0FBQztJQTVCVSxrQkFBa0I7UUFEOUIsVUFBVSxFQUFFO09BQ0Esa0JBQWtCLENBa0Q5QjtJQUFELHlCQUFDO0NBQUEsQUFsREQsSUFrREM7U0FsRFksa0JBQWtCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuXG5pbXBvcnQgeyBzaGEyNTYgfSBmcm9tICdqcy1zaGEyNTYnO1xuXG4vKipcbiAqIEFic3RyYWN0aW9uIGZvciBjcnlwdG8gYWxnb3JpdGhtc1xuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgSGFzaEhhbmRsZXIge1xuICBhYnN0cmFjdCBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPjtcbn1cblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIERlZmF1bHRIYXNoSGFuZGxlciBpbXBsZW1lbnRzIEhhc2hIYW5kbGVyIHtcbiAgYXN5bmMgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIC8vIGNvbnN0IGVuY29kZXIgPSBuZXcgVGV4dEVuY29kZXIoKTtcbiAgICAvLyBjb25zdCBoYXNoQXJyYXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kaWdlc3QoYWxnb3JpdGhtLCBkYXRhKTtcbiAgICAvLyBjb25zdCBkYXRhID0gZW5jb2Rlci5lbmNvZGUodmFsdWVUb0hhc2gpO1xuXG4gICAgY29uc3QgaGFzaEFycmF5ID0gc2hhMjU2LmFycmF5KHZhbHVlVG9IYXNoKTtcbiAgICAvLyBjb25zdCBoYXNoU3RyaW5nID0gdGhpcy50b0hhc2hTdHJpbmcoaGFzaEFycmF5KTtcbiAgICBjb25zdCBoYXNoU3RyaW5nID0gdGhpcy50b0hhc2hTdHJpbmcyKGhhc2hBcnJheSk7XG5cbiAgICByZXR1cm4gaGFzaFN0cmluZztcbiAgfVxuXG4gIHRvSGFzaFN0cmluZzIoYnl0ZUFycmF5OiBudW1iZXJbXSkge1xuICAgIGxldCByZXN1bHQgPSAnJztcbiAgICBmb3IgKGxldCBlIG9mIGJ5dGVBcnJheSkge1xuICAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoZSk7XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICB0b0hhc2hTdHJpbmcoYnVmZmVyOiBBcnJheUJ1ZmZlcikge1xuICAgIGNvbnN0IGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGJ1ZmZlcik7XG4gICAgbGV0IHJlc3VsdCA9ICcnO1xuICAgIGZvciAobGV0IGUgb2YgYnl0ZUFycmF5KSB7XG4gICAgICByZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShlKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIGhleFN0cmluZyhidWZmZXIpIHtcbiAgLy8gICAgIGNvbnN0IGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGJ1ZmZlcik7XG4gIC8vICAgICBjb25zdCBoZXhDb2RlcyA9IFsuLi5ieXRlQXJyYXldLm1hcCh2YWx1ZSA9PiB7XG4gIC8vICAgICAgIGNvbnN0IGhleENvZGUgPSB2YWx1ZS50b1N0cmluZygxNik7XG4gIC8vICAgICAgIGNvbnN0IHBhZGRlZEhleENvZGUgPSBoZXhDb2RlLnBhZFN0YXJ0KDIsICcwJyk7XG4gIC8vICAgICAgIHJldHVybiBwYWRkZWRIZXhDb2RlO1xuICAvLyAgICAgfSk7XG5cbiAgLy8gICAgIHJldHVybiBoZXhDb2Rlcy5qb2luKCcnKTtcbiAgLy8gICB9XG5cbiAgLy8gdG9IYXNoU3RyaW5nKGhleFN0cmluZzogc3RyaW5nKSB7XG4gIC8vICAgbGV0IHJlc3VsdCA9ICcnO1xuICAvLyAgIGZvciAobGV0IGkgPSAwOyBpIDwgaGV4U3RyaW5nLmxlbmd0aDsgaSArPSAyKSB7XG4gIC8vICAgICBsZXQgaGV4RGlnaXQgPSBoZXhTdHJpbmcuY2hhckF0KGkpICsgaGV4U3RyaW5nLmNoYXJBdChpICsgMSk7XG4gIC8vICAgICBsZXQgbnVtID0gcGFyc2VJbnQoaGV4RGlnaXQsIDE2KTtcbiAgLy8gICAgIHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKG51bSk7XG4gIC8vICAgfVxuICAvLyAgIHJldHVybiByZXN1bHQ7XG4gIC8vIH1cbn1cbiJdfQ==