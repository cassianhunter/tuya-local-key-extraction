// JNI Certificate Spoofing - replaces cert hash during JNI_OnLoad verification
// Hooks GetByteArrayElements to replace SHA-256 digest result with original cert hash
//
// This is the core technique: Tuya's libthing_security.so derives all crypto keys
// from the SHA-256 of the APK's signing certificate. When we re-sign the APK (required
// for Frida injection), the cert changes. This hook intercepts the JNI call that reads
// the digest result and replaces it with the original cert's hash, making the native
// library derive the correct keys.
//
// Set ORIG_HASH_HEX to your target app's original signing certificate SHA-256.
// Get it with: keytool -printcert -jarfile original.apk

var ORIG_HASH_HEX = "9f3b8d59bc4dacc47ebf65aa92ea6ea60bd1f902d50a4b7da0e401b6e9355815";
var origHashBytes = [];
for (var i = 0; i < ORIG_HASH_HEX.length; i += 2) {
    origHashBytes.push(parseInt(ORIG_HASH_HEX.substr(i, 2), 16));
}

function bytesToHex(p, len) {
    var h = "";
    for (var i = 0; i < len; i++) {
        var b = p.add(i).readU8().toString(16);
        if (b.length === 1) b = "0" + b;
        h += b;
    }
    return h;
}

// Load original cert for replacement
var origCertBytes = null;
var origCertLen = 0;
try {
    var libc = Process.getModuleByName("libc.so");
    var fopen = new NativeFunction(libc.findExportByName("fopen"), 'pointer', ['pointer', 'pointer']);
    var fread_fn = new NativeFunction(libc.findExportByName("fread"), 'uint64', ['pointer', 'uint64', 'uint64', 'pointer']);
    var fclose_fn = new NativeFunction(libc.findExportByName("fclose"), 'int', ['pointer']);
    var path = Memory.allocUtf8String("/data/local/tmp/original_cert.der");
    var mode = Memory.allocUtf8String("rb");
    var fp = fopen(path, mode);
    if (!fp.isNull()) {
        origCertBytes = Memory.alloc(1024);
        origCertLen = fread_fn(origCertBytes, 1, 1024, fp);
        fclose_fn(fp);
        send("[+] Loaded original cert: " + origCertLen + " bytes");
    }
} catch(e) {
    send("[-] Cert load: " + e);
}

var secHooked = false;
var jniHooked = false;

// Track state: after digest() is called, the next GetByteArrayElements should be the hash
var digestCalled = false;
var getEncodedCalled = false;
var toByteArrayCalled = false;

function hookSecurityLib(libsec) {
    if (secHooked) return;
    secHooked = true;

    var secBase = libsec.base;
    var secEnd = secBase.add(libsec.size);
    send("[+] libthing_security.so @ " + secBase);

    // Hook JNI_OnLoad at 0x13d50
    Interceptor.attach(secBase.add(0x13d50), {
        onEnter: function(args) {
            send("[JNI_OnLoad] called");
            var javaVM = args[0];
            var vtable = javaVM.readPointer();
            var GetEnv = new NativeFunction(vtable.add(6 * 8).readPointer(), 'int', ['pointer', 'pointer', 'int']);
            var envPtr = Memory.alloc(8);
            var result = GetEnv(javaVM, envPtr, 0x00010006);
            if (result === 0) {
                var env = envPtr.readPointer();
                var jniVtable = env.readPointer();
                installJniHooks(jniVtable, secBase, secEnd);
            } else {
                send("[JNI_OnLoad] GetEnv failed: " + result);
            }
        },
        onLeave: function(retval) {
            send("[JNI_OnLoad] done: " + retval);
        }
    });

    // Monitor native functions
    var funcs = [
        ["doCommandNative", 0x13ed8],
        ["getChKey", 0x16000],
        ["testSign", 0x16408],
        ["getConfig", 0x136e0],
        ["genKey", 0x15720],
        ["encryptPostData", 0x151f8],
        ["decryptResponseData", 0x15e28],
        ["getEncryptoKey", 0x15368],
        ["computeDigest", 0x15ad0],
    ];
    funcs.forEach(function(f) {
        (function(fn, off) {
            Interceptor.attach(secBase.add(off), {
                onEnter: function(args) {
                    if (!jniHooked) {
                        try {
                            installJniHooks(args[0].readPointer(), secBase, secEnd);
                        } catch(e) {}
                    }
                    if (fn === "doCommandNative")
                        send("[" + fn + "] cmd=" + args[2].toInt32());
                    else
                        send("[" + fn + "]");
                },
                onLeave: function(retval) {
                    send("[" + fn + "] => " + (retval.isNull() ? "null" : "ok"));
                }
            });
        })(f[0], f[1]);
    });

    send("[+] Security lib hooks ready");
}

function installJniHooks(vtable, secBase, secEnd) {
    if (jniHooked) return;
    jniHooked = true;

    var GetMethodID = vtable.add(33 * 8).readPointer();
    var CallObjectMethodV = vtable.add(35 * 8).readPointer();
    var GetByteArrayElements = vtable.add(184 * 8).readPointer();
    var ReleaseByteArrayElements = vtable.add(185 * 8).readPointer();
    var GetArrayLength = vtable.add(171 * 8).readPointer();
    var NewStringUTF = vtable.add(167 * 8).readPointer();
    var GetStringUTFChars = vtable.add(169 * 8).readPointer();

    send("[+] JNI vtable hooks installing");

    var certMethodIDs = {};

    // Track method resolutions
    Interceptor.attach(GetMethodID, {
        onEnter: function(args) {
            this.track = false;
            var ra = this.returnAddress;
            if (ra.compare(secBase) >= 0 && ra.compare(secEnd) < 0) {
                try {
                    this.name = args[2].readUtf8String();
                    this.sig = args[3].readUtf8String();
                    send("[GetMethodID] " + this.name + " " + this.sig);
                    if (["toByteArray", "getEncoded", "digest", "getPackageInfo",
                         "getPackageManager", "generateCertificate"].indexOf(this.name) !== -1) {
                        this.track = true;
                    }
                } catch(e) {}
            }
        },
        onLeave: function(retval) {
            if (this.track) {
                certMethodIDs[retval.toString()] = this.name;
            }
        }
    });

    // Track cert flow through CallObjectMethodV
    Interceptor.attach(CallObjectMethodV, {
        onEnter: function(args) {
            var ra = this.returnAddress;
            if (ra.compare(secBase) >= 0 && ra.compare(secEnd) < 0) {
                var mid = args[2].toString();
                var mname = certMethodIDs[mid];
                if (mname) {
                    send("[CallObj] " + mname);
                    if (mname === "toByteArray") toByteArrayCalled = true;
                    if (mname === "getEncoded") getEncodedCalled = true;
                    if (mname === "digest") {
                        digestCalled = true;
                        send("[CallObj] digest called! Next GetByteArrayElements is the HASH");
                    }
                }
            }
        }
    });

    // THE KEY HOOK: GetByteArrayElements
    // After digest() is called, the next GetByteArrayElements from sec lib
    // returns the SHA-256 hash. We replace it with the original cert hash.
    Interceptor.attach(GetByteArrayElements, {
        onEnter: function(args) {
            this.replace = false;
            var ra = this.returnAddress;
            if (ra.compare(secBase) >= 0 && ra.compare(secEnd) < 0) {
                this.jarray = args[1];
                this.isCopy = args[2];

                if (digestCalled) {
                    this.replace = true;
                    send("[GetByteArrayElements] THIS IS THE CERT HASH - will replace!");
                    digestCalled = false; // reset
                }
            }
        },
        onLeave: function(retval) {
            if (this.replace && !retval.isNull()) {
                // retval is a pointer to the byte array contents
                // Read the current hash
                var currentHash = bytesToHex(retval, 32);
                send("[GetByteArrayElements] current hash: " + currentHash);

                // Replace with original hash
                for (var j = 0; j < 32; j++) {
                    retval.add(j).writeU8(origHashBytes[j]);
                }
                send("[GetByteArrayElements] REPLACED with: " + bytesToHex(retval, 32));
            }
        }
    });

    // Monitor strings
    Interceptor.attach(NewStringUTF, {
        onEnter: function(args) {
            var ra = this.returnAddress;
            if (ra.compare(secBase) >= 0 && ra.compare(secEnd) < 0) {
                try {
                    var str = args[1].readUtf8String();
                    if (str && str.length > 0 && str.length < 200) {
                        send("[NewStr] " + str);
                    }
                } catch(e) {}
            }
        }
    });

    Interceptor.attach(GetStringUTFChars, {
        onEnter: function(args) {
            this.fromSec = false;
            var ra = this.returnAddress;
            if (ra.compare(secBase) >= 0 && ra.compare(secEnd) < 0) {
                this.fromSec = true;
            }
        },
        onLeave: function(retval) {
            if (this.fromSec) {
                try {
                    var str = retval.readUtf8String();
                    if (str && str.length > 0 && str.length < 200) {
                        send("[GetStr] " + str);
                    }
                } catch(e) {}
            }
        }
    });

    send("[+] JNI hooks installed!");
}

// Hook dlopen to catch library loading
try {
    var libc = Process.getModuleByName("libc.so");
    var dlext = libc.findExportByName("android_dlopen_ext");
    if (dlext) {
        Interceptor.attach(dlext, {
            onEnter: function(args) {
                this.isSec = false;
                try {
                    var p = args[0].readUtf8String();
                    if (p && p.indexOf("libthing_security.so") !== -1) {
                        this.isSec = true;
                        send("[dlopen] " + p);
                    }
                } catch(e) {}
            },
            onLeave: function(retval) {
                if (this.isSec && !secHooked) {
                    try {
                        var libsec = Process.getModuleByName("libthing_security.so");
                        hookSecurityLib(libsec);
                    } catch(e) {
                        send("[-] post-dlopen: " + e);
                    }
                }
            }
        });
        send("[+] Hooked android_dlopen_ext");
    }
} catch(e) {}

// Fallback: poll
var poll = setInterval(function() {
    if (!secHooked) {
        try {
            var m = Process.getModuleByName("libthing_security.so");
            hookSecurityLib(m);
            clearInterval(poll);
        } catch(e) {}
    } else {
        clearInterval(poll);
    }
}, 50);

send("[*] Ready. Waiting for libthing_security.so...");
