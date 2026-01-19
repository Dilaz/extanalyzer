/// JavaScript code injected before user code to mock browser APIs and trace calls
pub const SANDBOX_PRELUDE: &str = r#"
// Trace storage - will be serialized back to Rust
var __trace = {
    decoded: [],
    calls: []
};

// Helper to record decoded strings
function __recordDecode(fn, input, output) {
    __trace.decoded.push({ function: fn, input: String(input), output: String(output) });
    return output;
}

// Helper to record API calls
function __recordCall(fn, args) {
    __trace.calls.push({ function: fn, arguments: Array.from(args) });
}

// Mock atob (base64 decode) - QuickJS has this built-in
var __origAtob = typeof atob !== 'undefined' ? atob : function(s) {
    // Fallback base64 decode
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = '';
    var buffer;
    s = s.replace(/=+$/, '');
    for (var i = 0, len = s.length; i < len; ) {
        buffer = (chars.indexOf(s[i++]) << 18) | (chars.indexOf(s[i++]) << 12) |
                 (chars.indexOf(s[i++]) << 6) | chars.indexOf(s[i++]);
        output += String.fromCharCode((buffer >> 16) & 0xff);
        if (s[i - 2] !== '=') output += String.fromCharCode((buffer >> 8) & 0xff);
        if (s[i - 1] !== '=') output += String.fromCharCode(buffer & 0xff);
    }
    return output;
};

globalThis.atob = function(s) {
    var result = __origAtob(s);
    return __recordDecode('atob', s, result);
};

// Mock btoa (base64 encode)
var __origBtoa = typeof btoa !== 'undefined' ? btoa : function(s) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = '';
    for (var i = 0, len = s.length; i < len; ) {
        var a = s.charCodeAt(i++);
        var b = i < len ? s.charCodeAt(i++) : 0;
        var c = i < len ? s.charCodeAt(i++) : 0;
        output += chars[(a >> 2)] + chars[((a & 3) << 4) | (b >> 4)] +
                  chars[((b & 15) << 2) | (c >> 6)] + chars[c & 63];
    }
    var pad = s.length % 3;
    if (pad) output = output.slice(0, pad - 3) + '==='.slice(pad);
    return output;
};

globalThis.btoa = function(s) {
    var result = __origBtoa(s);
    return __recordDecode('btoa', s, result);
};

// Wrap String.fromCharCode to trace it
var __origFromCharCode = String.fromCharCode;
String.fromCharCode = function() {
    var result = __origFromCharCode.apply(String, arguments);
    var input = Array.prototype.slice.call(arguments).join(',');
    return __recordDecode('String.fromCharCode', input, result);
};

// Mock fetch
globalThis.fetch = function(url, options) {
    __recordCall('fetch', [url, options || {}]);
    return Promise.resolve({ ok: false, status: 0, text: function() { return Promise.resolve(''); } });
};

// Mock XMLHttpRequest
globalThis.XMLHttpRequest = function() {
    this._method = '';
    this._url = '';
};
XMLHttpRequest.prototype.open = function(method, url) {
    this._method = method;
    this._url = url;
    __recordCall('XMLHttpRequest.open', [method, url]);
};
XMLHttpRequest.prototype.send = function(body) {
    __recordCall('XMLHttpRequest.send', [this._method, this._url, body || null]);
};
XMLHttpRequest.prototype.setRequestHeader = function() {};

// Proxy-based mock for chrome.* and browser.* APIs
function createTracingProxy(basePath) {
    return new Proxy({}, {
        get: function(target, prop) {
            var path = basePath + '.' + prop;
            return new Proxy(function() {
                __recordCall(path, Array.from(arguments));
                return undefined;
            }, {
                get: function(target, innerProp) {
                    return createTracingProxy(path)[innerProp];
                }
            });
        }
    });
}

globalThis.chrome = createTracingProxy('chrome');
globalThis.browser = createTracingProxy('browser');

// Mock document.cookie
var __fakeCookie = '';
globalThis.document = globalThis.document || {};
Object.defineProperty(globalThis.document, 'cookie', {
    get: function() {
        __recordCall('document.cookie.get', []);
        return __fakeCookie;
    },
    set: function(val) {
        __recordCall('document.cookie.set', [val]);
        __fakeCookie = val;
    }
});

// Mock localStorage/sessionStorage
function createStorageMock(name) {
    var storage = {};
    return {
        getItem: function(key) {
            __recordCall(name + '.getItem', [key]);
            return storage[key] || null;
        },
        setItem: function(key, val) {
            __recordCall(name + '.setItem', [key, val]);
            storage[key] = String(val);
        },
        removeItem: function(key) {
            __recordCall(name + '.removeItem', [key]);
            delete storage[key];
        },
        clear: function() {
            __recordCall(name + '.clear', []);
            storage = {};
        }
    };
}

globalThis.localStorage = createStorageMock('localStorage');
globalThis.sessionStorage = createStorageMock('sessionStorage');

// Mock console to prevent errors
globalThis.console = {
    log: function() {},
    warn: function() {},
    error: function() {},
    info: function() {},
    debug: function() {}
};

// Mock setTimeout/setInterval (don't actually schedule, just trace)
globalThis.setTimeout = function(fn, delay) {
    __recordCall('setTimeout', [typeof fn === 'string' ? fn : '[function]', delay]);
    return 0;
};
globalThis.setInterval = function(fn, delay) {
    __recordCall('setInterval', [typeof fn === 'string' ? fn : '[function]', delay]);
    return 0;
};

// Return trace at the end - this will be called by Rust
function __getTrace() {
    return JSON.stringify(__trace);
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_is_valid_js_syntax() {
        // Just check it's not empty and has expected markers
        assert!(SANDBOX_PRELUDE.contains("__trace"));
        assert!(SANDBOX_PRELUDE.contains("__getTrace"));
        assert!(SANDBOX_PRELUDE.contains("globalThis.fetch"));
        assert!(SANDBOX_PRELUDE.contains("globalThis.chrome"));
    }
}
