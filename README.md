# Tuya Local Key Extraction via JNI Certificate Spoofing

Get the local encryption key from a Tuya smart device without root, a Tuya developer account, or cloud API access.

Developed against the Wilfa Haze HU-400BCA humidifier (WiLife app) but should work on any Tuya OEM app that ships `libthing_security.so`.

## Why bother

You bought the hardware, but Tuya holds the encryption keys. Your device talks locally over your own LAN, but you can't talk back without a 16-byte key that only Tuya's cloud knows.

So if Tuya's servers go down, or they change their API, or they kill your region, your device stops working through the app. You also can't hook it into Home Assistant or build your own web dashboard on a Raspberry Pi without that key. And every command round-trips through the cloud even though the device is two meters away.

With the local key you can just talk to the device directly over TCP. No cloud, no app, no account. Run it from a Python script, a home server, whatever you want.

## Background

Tuya devices use protocols 3.3/3.4/3.5 over your LAN, but the traffic is AES-encrypted with that local key. It's a 16-byte secret unique to each device, assigned by Tuya's cloud during pairing. The device doesn't store it anywhere accessible. You normally need Tuya developer credentials or the `tinytuya` wizard to get it, and both can fail for OEM-branded devices. MITM won't work either because the apps pin certificates.

This repo takes a different approach: inject Frida into the OEM app, let it authenticate normally, then read the key out of process memory.

## How it works

1. Decompile the OEM APK, pull out credentials
2. Inject Frida Gadget so we can instrument the app at runtime
3. Patch `libthing_security.so` to kill the anti-tamper threads
4. Spoof the certificate hash via JNI vtable hooks so the native lib derives correct keys despite the APK being re-signed
5. Log in, scan memory for `"localKey"`, done

The trick is step 4. Tuya's native library doesn't just *check* the cert hash. It feeds the SHA-256 into its key derivation. Wrong cert = wrong keys = `ILLEGAL_CLIENT_ID` from the cloud. We hook `GetByteArrayElements` in the JNI vtable right after `MessageDigest.digest()` runs and swap the bytes in place. The native library never sees the re-signed cert.

## Skill level

Steps 1–4 are terminal-level stuff. If you're comfortable with `adb`, Python, and following shell commands, you'll be fine.

Steps 8–9 (binary patching and Frida hooking) are the hard part. For the **Wilfa WiLife app specifically**, the scripts and offsets in this repo work as-is. For a **different Tuya OEM app**, you'll need to find the right offsets yourself using a disassembler like Ghidra or IDA. That takes some reverse engineering experience.

## What you need

**On your computer:**
- Python 3.10+
- [apktool](https://apktool.org) (decompile/rebuild APKs)
- [jadx](https://github.com/skylot/jadx) (read decompiled Java)
- [Frida](https://frida.re) (`pip install frida frida-tools`)
- Android SDK build-tools (`zipalign`, `apksigner`)
- [tinytuya](https://github.com/jasonacox/tinytuya) (to verify the key works)

```bash
pip install frida frida-tools tinytuya pycryptodome pyelftools capstone
```

**An Android phone** (iOS won't work, the whole technique is based on APK patching):
- USB debugging enabled, connected via ADB
- The target Tuya OEM app installed (you'll pull the APK from it)
- No root needed

**You'll also need to download:**
- **Frida Gadget** `.so` for your phone's CPU architecture (usually `arm64`). Go to [Frida releases](https://github.com/frida/frida/releases), find the latest release, and download `frida-gadget-<version>-android-arm64.so.xz`. Decompress it with `xz -d`.
- **A debug keystore** for re-signing the APK. Create one if you don't have one:
  ```bash
  keytool -genkey -v -keystore debug.keystore -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass android -keypass android \
    -dname "CN=Debug"
  ```

## Step by step

### 1. Find the device on your network

```bash
python3 scripts/scan_device.py --ip 192.168.1.100
```

Replace the IP with your device's address (check your router's DHCP list). Tuya devices broadcast on UDP 6666/6667 every ~5 seconds using a universal AES key, so the script can decode them and show you the device ID, product key, and protocol version.

You can also run it without `--ip` to just see all Tuya devices on the network.

### 2. Pull the APK from your phone

```bash
# Find where the APK lives on the phone
adb shell pm path com.your.app
```

This prints something like `/data/app/~~abc123==/com.your.app-xyz/base.apk`. The middle part is random, but the structure is always the same. Copy the whole path and pull it:

```bash
adb pull /data/app/~~abc123==/com.your.app-xyz/base.apk app.apk
```

Then decompile it twice, once for reading and once for patching:

```bash
jadx -d decompiled app.apk        # readable Java source
apktool d app.apk -o apk_source/  # editable smali + resources
```

### 3. Find the credentials

Search the decompiled Java for the Tuya OEM keys:

```bash
grep -r "THING_SMART_APPKEY\|THING_SMART_SECRET\|THING_SMART_TTID" decompiled/
```

You're looking for something like this in `BuildConfig.java`:

```java
THING_SMART_APPKEY = "ucrudpqqyf7shnyhgndm"    // client ID
THING_SMART_SECRET = "7r88vgpqg5aygswx7hpatnw55dshruap"  // app secret
THING_SMART_TTID = "wilfasmartlife"             // OEM brand ID
```

Also grab the signing certificate's SHA-256 fingerprint:

```bash
keytool -printcert -jarfile app.apk
```

Look for the `SHA256:` line. Strip the colons and lowercase it. You'll need this later. For example, `9F:3B:8D:59:BC:...` becomes `9f3b8d59bc...`.

### 4. Extract the BMP key (optional)

Tuya hides another secret in `assets/t_s.bmp`. Polynomial coefficients encoded in pixel data, recovered via Gaussian elimination:

```bash
python3 scripts/extract_bmp_key.py \
  --app-id YOUR_CLIENT_ID \
  --bmp apk_source/assets/t_s.bmp \
  --cert-sha256 YOUR_CERT_SHA256 \
  --app-secret YOUR_APP_SECRET
```

Not needed for the local key extraction itself, but useful if you want to understand the full signing chain.

### 5–7. Dead ends (skip these)

These are documented for context, not steps you need to follow:

- Direct API calls all returned `ILLEGAL_CLIENT_ID`. The Wilfa clientId is on Tuya's newer ThingClips platform, not the legacy mobile API
- MITM via mitmproxy failed because the app pins TLS certificates
- The HMAC signing algorithm is compiled into the native `.so`, can't reproduce it outside the app

This is why we need Frida. Let the app do the hard crypto parts for us.

### 8. Patch the binary and inject Frida

> **If you're doing the Wilfa WiLife app**, the scripts and offsets below work as-is.
> **If you're doing a different Tuya app**, see [Adapting to other apps](#using-this-on-a-different-tuya-app) at the bottom.

#### 8a. Disable anti-tamper threads

`libthing_security.so` has background threads that check if the APK has been modified. After a few seconds they crash the app. We patch them out:

```bash
python3 scripts/patch_so.py apk_source/lib/arm64-v8a/libthing_security.so
cp libthing_security_patched.so apk_source/lib/arm64-v8a/libthing_security.so
```

The script patches PLT stubs for `exit()`, `abort()`, and `kill()`. For WiLife v1.6.0, you also need to apply these six patches manually (hex editor or binary patcher):

| Offset | Original | Patch | Why |
|--------|----------|-------|-----|
| `0x13e48` | `bl pthread_create` | `mov w0, #0` | Pretend thread was created |
| `0x13e54` | `bl thread.detach()` | `NOP` | Skip detach |
| `0x13e5c` | `bl ~thread()` | `NOP` | Skip destructor |
| `0x143b8` | `bl pthread_create` | `mov w0, #0` | Second integrity thread |
| `0x17320` | thread entry 1 | `ret` | Thread exits immediately |
| `0x13d34` | thread entry 2 | `ret` | Thread exits immediately |

`NOP` = `0xd503201f`, `ret` = `0xd65f03c0`, `mov w0, #0` = `0x52800000` (all little-endian ARM64).

#### 8b. Create the Frida Gadget config

Create a file called `frida-gadget.config.so` (yes, the extension is `.so` even though it's JSON. Android only loads `.so` files from the lib directory):

```bash
cat > frida-gadget.config.so << 'EOF'
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
EOF
```

The `"on_load": "wait"` part is important. It freezes the app at startup until a Frida client connects, which gives us time to install hooks before the security library loads.

#### 8c. Inject the gadget into the APK

```bash
python3 scripts/inject_frida.py \
  --work-dir apk_source/ \
  --gadget frida-gadget-17.7.3-android-arm64.so \
  --gadget-config frida-gadget.config.so \
  --smali smali_classes4/com/smart/app/SmartApplication.smali \
  --keystore debug.keystore
```

The `--smali` path is the app's entry point class in smali format. For WiLife it's `SmartApplication.smali` in `smali_classes4`. For other apps, look in `apk_source/AndroidManifest.xml` for the `android:name` attribute on the `<application>` tag, then find the corresponding `.smali` file.

The script adds a `System.loadLibrary("frida-gadget")` call, rebuilds the APK, aligns it, and signs it with your debug keystore.

#### 8d. Save the original signing certificate

The patched APK is signed with your debug key, but the native library needs to think it still has the original Tuya cert. We'll extract it and push it to the phone:

```bash
# Extract the cert from the ORIGINAL (unmodified) APK
unzip -p app.apk META-INF/CERT.RSA > cert.p7
openssl pkcs7 -in cert.p7 -inform DER -print_certs | \
  openssl x509 -outform DER -out original_cert.der
rm cert.p7

# Push it to the phone
adb push original_cert.der /data/local/tmp/original_cert.der
```

If `META-INF/CERT.RSA` doesn't exist (some APKs name it differently), list the files to find it: `unzip -l app.apk | grep META-INF`. Look for a `.RSA` or `.DSA` file.

### 9. The cert hash spoof

The Frida script (`scripts/jni_cert_spoof.js`) does the actual magic. It hooks into the JNI function table to intercept the moment `libthing_security.so` reads the certificate hash, and swaps in the original hash.

The call chain inside the native library looks like this:

```
getPackageManager()
  → getPackageInfo(packageName, GET_SIGNATURES)
    → signatures[0].toByteArray()
      → CertificateFactory.getInstance("X509")
        → generateCertificate()
          → getEncoded()
            → MessageDigest.getInstance("SHA256")
              → digest()                    ← we detect this call
                → GetByteArrayElements      ← we replace the hash bytes here
```

The script watches for `digest()` being called, then on the very next `GetByteArrayElements` from within the security library's memory range, it overwrites the returned bytes with the original cert's SHA-256. The library goes on to derive the correct channel key and everything authenticates.

Before running, open `scripts/jni_cert_spoof.js` and check that `ORIG_HASH_HEX` matches your app's original cert SHA-256 (the one from step 3). For WiLife it's already set correctly.

### 10. Launch, log in, grab the key

```bash
python3 scripts/launch_and_hook.py \
  --package com.wilfa.WiLife \
  --activity com.smart.ThingSplashActivity \
  --apk patched_app_aligned.apk \
  --script scripts/jni_cert_spoof.js \
  --cert original_cert.der \
  --duration 120
```

What happens:
1. The script installs the patched APK and launches it
2. The app freezes at startup (Frida Gadget waiting)
3. The script connects to the gadget and loads the cert spoof hooks
4. The app resumes and shows the login screen
5. You log in with your account
6. The local key appears in the console output

Look for lines containing `"localKey"` in the output. You can also scan memory manually in a Frida console:

```javascript
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scanSync(range.base, range.size,
        '6c 6f 63 61 6c 4b 65 79');  // "localKey" in hex
});
```

### 11. Verify it works

```python
import tinytuya

d = tinytuya.Device('YOUR_DEVICE_ID', 'YOUR_DEVICE_IP', 'YOUR_LOCAL_KEY', version=3.3)
print(d.status())
```

If you get back a dict with `"dps"` containing numbered entries, you're done. You now have full local control over the device without the cloud.

## Scripts

| Script | What it does |
|--------|-------------|
| `scripts/scan_device.py` | Listens for Tuya UDP broadcasts, probes TCP 6668 |
| `scripts/extract_bmp_key.py` | Recovers steganographic keys from `t_s.bmp` |
| `scripts/patch_so.py` | Patches PLT stubs in `libthing_security.so` to RET |
| `scripts/inject_frida.py` | Injects Frida Gadget into a decompiled APK |
| `scripts/launch_and_hook.py` | Installs, launches, connects Frida, loads hooks |
| `scripts/jni_cert_spoof.js` | JNI vtable hooks for cert hash replacement |

## Using this on a different Tuya app

Steps 1–4 and 10 are the same for any Tuya OEM app. The parts that change are in step 8 (binary patching) and step 9 (the Frida script config).

**What you need to find:**

1. **The smali entry point.** Open `apk_source/AndroidManifest.xml`, find the `<application android:name="...">` attribute. That class name maps to a `.smali` file somewhere under `apk_source/smali*/`. That's your `--smali` argument.

2. **Anti-tamper thread offsets.** Open your version of `libthing_security.so` in Ghidra or IDA. Search for calls to `pthread_create`. There are usually two. The thread entry functions they point to are what you need to patch to `ret`. The `pthread_create` calls themselves can be patched to `mov w0, #0`.

3. **The `JNI_OnLoad` offset.** This is an exported symbol, so it's easy: look it up in the ELF symbol table. In Ghidra, just search for `JNI_OnLoad` in the symbol list. The offset in `jni_cert_spoof.js` (line 67, `secBase.add(0x13d50)`) needs to match.

4. **The native function offsets.** The `funcs` array in `jni_cert_spoof.js` (around line 89) lists offsets for `doCommandNative`, `getChKey`, etc. Find these in your binary. They're JNI-registered native methods, so look for strings like `"doCommandNative"` in the binary. They're usually near the registration table.

5. **The cert SHA-256.** Update `ORIG_HASH_HEX` at the top of `jni_cert_spoof.js`.

The JNI vtable indices (GetMethodID=33, CallObjectMethodV=35, GetByteArrayElements=184, etc.) are part of the JNI spec and don't change across Android versions, so those you can leave alone.

## References

- [tinytuya](https://github.com/jasonacox/tinytuya): local Tuya device control
- [tuya-sign-hacking](https://github.com/nalajcie/tuya-sign-hacking): BMP key extraction (C, ported here to Python)
- [Frida](https://frida.re): dynamic instrumentation
- [Tuya protocol docs](https://github.com/codetheweb/tuyapi/wiki)

## License

MIT
