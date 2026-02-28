#!/usr/bin/env python3
"""
Inject Frida gadget into a Tuya OEM APK to capture local keys.

Strategy:
1. Copy Frida gadget .so into the APK's native lib directory
2. Add System.loadLibrary("frida-gadget") to the launcher Activity's smali
3. Configure gadget to listen on a port for script injection
4. Rebuild, sign, and install the APK

Prerequisites:
  - apktool: https://apktool.org
  - zipalign & apksigner: from Android SDK build-tools
  - Frida gadget .so for target arch: https://github.com/frida/frida/releases
  - A debug keystore (or create one with keytool)

Usage:
  # First decompile the APK
  apktool d your_app.apk -o apk_source/

  # Then inject Frida
  python3 inject_frida.py \\
    --work-dir apk_source/ \\
    --gadget frida-gadget-arm64.so \\
    --gadget-config frida-gadget.config.so \\
    --smali smali_classes4/com/smart/app/SmartApplication.smali \\
    --keystore debug.keystore
"""

import json
import os
import shutil
import subprocess
import sys
import argparse


def inject_gadget_load(smali_path):
    """Add System.loadLibrary("frida-gadget") to attachBaseContext or static init."""
    with open(smali_path, "r") as f:
        content = f.read()

    # Check if already injected
    if "frida-gadget" in content:
        print("  Frida gadget load already injected")
        return True

    # Find a static constructor or attachBaseContext to inject into
    # attachBaseContext runs very early — before onCreate
    targets = [
        ".method public attachBaseContext(Landroid/content/Context;)V",
        ".method protected attachBaseContext(Landroid/content/Context;)V",
        ".method public onCreate()V",
    ]

    target = None
    for t in targets:
        if t in content:
            target = t
            break

    if target is None:
        print(f"  Cannot find suitable method in {smali_path}")
        for line in content.split("\n"):
            if ".method" in line and ("attach" in line.lower() or "oncreate" in line.lower()):
                print(f"    Found: {line.strip()}")
        return False

    print(f"  Injecting into: {target}")

    # Insert after the .locals/.registers line
    lines = content.split("\n")
    insert_idx = None
    in_target = False
    locals_line_idx = None
    locals_count = 0

    for i, line in enumerate(lines):
        if target in line:
            in_target = True
        if in_target and line.strip().startswith(".locals"):
            locals_line_idx = i
            locals_count = int(line.strip().split()[1])
            insert_idx = i + 1
            break
        if in_target and line.strip().startswith(".registers"):
            locals_line_idx = i
            insert_idx = i + 1
            break

    if insert_idx is None:
        print("  Cannot find .locals in target method")
        return False

    # We need at least 1 local register. If .locals 0, bump to 1
    if locals_count == 0:
        lines[locals_line_idx] = "    .locals 1"
        print("  Bumped .locals 0 -> 1")

    # Use the highest available register (v0 for .locals 1+)
    reg = "v0"

    # Inject the loadLibrary call
    inject_code = [
        "",
        "    # Frida gadget injection - load early to set up hooks",
        f'    const-string {reg}, "frida-gadget"',
        "",
        f"    invoke-static {{{reg}}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
        "",
    ]
    for j, code_line in enumerate(inject_code):
        lines.insert(insert_idx + j, code_line)

    with open(smali_path, "w") as f:
        f.write("\n".join(lines))

    print(f"  Injected loadLibrary into {os.path.basename(smali_path)}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Inject Frida gadget into a Tuya OEM APK")
    parser.add_argument("--work-dir", required=True, help="Path to apktool-decompiled APK directory")
    parser.add_argument("--gadget", required=True, help="Path to Frida gadget .so (e.g., frida-gadget-16.5.2-android-arm64.so)")
    parser.add_argument("--gadget-config", help="Path to Frida gadget config .so file")
    parser.add_argument("--smali", required=True,
                        help="Relative path to the smali entry point (e.g., smali_classes4/com/smart/app/SmartApplication.smali)")
    parser.add_argument("--arch", default="arm64-v8a", help="Target architecture (default: arm64-v8a)")
    parser.add_argument("--keystore", help="Path to keystore for signing (default: debug.keystore)")
    parser.add_argument("--ks-pass", default="android", help="Keystore password (default: android)")
    parser.add_argument("--key-alias", default="androiddebugkey", help="Key alias (default: androiddebugkey)")
    parser.add_argument("-o", "--output", help="Output APK path")
    args = parser.parse_args()

    work_dir = args.work_dir
    lib_dir = os.path.join(work_dir, "lib", args.arch)
    gadget_dest = os.path.join(lib_dir, "libfrida-gadget.so")
    smali_path = os.path.join(work_dir, args.smali)

    print("=" * 60)
    print("Frida Gadget Injection")
    print("=" * 60)

    # Step 1: Copy gadget to lib directory
    print("\n[1/5] Setting up Frida gadget...")
    os.makedirs(lib_dir, exist_ok=True)
    shutil.copy2(args.gadget, gadget_dest)
    print(f"  Copied gadget to {os.path.relpath(gadget_dest, work_dir)}")

    if args.gadget_config:
        config_dest = os.path.join(lib_dir, "libfrida-gadget.config.so")
        shutil.copy2(args.gadget_config, config_dest)
        print(f"  Copied gadget config to {os.path.basename(config_dest)}")

    # Step 2: Inject loadLibrary call into the splash activity
    print("\n[2/5] Injecting gadget loader into smali...")
    if not os.path.exists(smali_path):
        print(f"  ERROR: {smali_path} not found!")
        for root, dirs, files in os.walk(work_dir):
            for f in files:
                if "SmartApplication" in f and f.endswith(".smali"):
                    print(f"  Found: {os.path.join(root, f)}")
        return

    if not inject_gadget_load(smali_path):
        print("  Failed to inject gadget loader!")
        return

    # Step 3: Build APK
    print("\n[3/5] Building APK with apktool...")
    out_apk = args.output or os.path.join(os.path.dirname(work_dir), "output_frida.apk")
    cmd = ["apktool", "b", work_dir, "-o", out_apk]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(f"  Build failed: {result.stderr[-500:]}")
        return
    print(f"  Built: {out_apk}")

    # Step 4: Align and sign
    print("\n[4/5] Aligning and signing...")
    aligned_apk = out_apk.replace(".apk", "_aligned.apk")

    # zipalign
    cmd = ["zipalign", "-p", "4", out_apk, aligned_apk]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  zipalign failed: {result.stderr}")
        return
    print(f"  Aligned: {aligned_apk}")

    # sign with apksigner
    if args.keystore:
        env = os.environ.copy()
        # Use JAVA_HOME from environment if set
        java_home = os.environ.get("JAVA_HOME", "")
        if java_home:
            env["PATH"] = f"{java_home}/bin:{env['PATH']}"

        cmd = [
            "apksigner", "sign",
            "--ks", args.keystore,
            "--ks-pass", f"pass:{args.ks_pass}",
            "--ks-key-alias", args.key_alias,
            "--key-pass", f"pass:{args.ks_pass}",
            aligned_apk,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"  apksigner failed: {result.stderr}")
            return
        print(f"  Signed: {aligned_apk}")
    else:
        print("  Skipping signing (no --keystore provided)")

    # Step 5: Install
    print("\n[5/5] Ready to install!")
    print(f"  APK: {aligned_apk}")
    print("\nTo install, first uninstall the original app, then run:")
    print(f"  adb install {aligned_apk}")
    print("\nAfter app starts, connect Frida:")
    print("  frida -U -n <package_name> -l jni_cert_spoof.js")


if __name__ == "__main__":
    main()
