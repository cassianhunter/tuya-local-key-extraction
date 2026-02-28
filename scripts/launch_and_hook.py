#!/usr/bin/env python3
"""
Launch patched Tuya OEM app with on_load:wait, connect Frida immediately,
install JNI cert spoof hooks, then resume the app.

The Frida gadget must be configured with:
  {"interaction": {"type": "listen", "on_load": "wait"}}

This causes the app to freeze at startup until a Frida client connects,
giving us time to install hooks before any native library loads.

Usage:
  python3 launch_and_hook.py \\
    --package com.wilfa.WiLife \\
    --activity com.smart.ThingSplashActivity \\
    --apk patched_app_aligned.apk \\
    --script jni_cert_spoof.js \\
    --duration 90
"""

import frida
import subprocess
import time
import sys
import os
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def make_logger(lines):
    def log(msg):
        ts = time.strftime('%H:%M:%S')
        line = f"[{ts}] {msg}"
        print(line, flush=True)
        lines.append(line)
    return log


def on_message_handler(log):
    def on_message(message, data):
        if message['type'] == 'send':
            log(f"HOOK: {message['payload']}")
        elif message['type'] == 'error':
            log(f"ERROR: {message.get('description', str(message))}")
        else:
            log(f"MSG: {message}")
    return on_message


def main():
    parser = argparse.ArgumentParser(description="Launch patched app and inject Frida hooks")
    parser.add_argument("--package", required=True, help="Android package name (e.g., com.wilfa.WiLife)")
    parser.add_argument("--activity", required=True, help="Launch activity (e.g., com.smart.ThingSplashActivity)")
    parser.add_argument("--apk", help="APK to install (skips install if not provided)")
    parser.add_argument("--script", default=os.path.join(SCRIPT_DIR, "jni_cert_spoof.js"),
                        help="Frida script to inject (default: scripts/jni_cert_spoof.js)")
    parser.add_argument("--cert", help="Path to original cert DER file to push to device")
    parser.add_argument("--duration", type=int, default=90, help="Monitoring duration in seconds (default: 90)")
    parser.add_argument("--output", help="Save hook output to file")
    args = parser.parse_args()

    lines = []
    log = make_logger(lines)

    log("=== Starting launch_and_hook ===")

    # Step 1: Uninstall old instance
    log("Stopping old app...")
    subprocess.run(["adb", "shell", "pm", "uninstall", args.package], capture_output=True)
    time.sleep(1)

    # Step 2: Install APK (if provided)
    if args.apk:
        log(f"Installing APK: {args.apk}")
        result = subprocess.run(["adb", "install", args.apk],
                               capture_output=True, text=True, timeout=120)
        if "Success" not in result.stdout:
            log(f"Install failed: {result.stdout} {result.stderr}")
            return
        log("Installed successfully")

    # Step 3: Push original cert (if provided)
    if args.cert:
        subprocess.run(["adb", "push", args.cert,
                        "/data/local/tmp/original_cert.der"], capture_output=True)
        log("Pushed original cert to device")

    # Step 4: Set up port forwarding
    subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], capture_output=True)

    # Step 5: Launch app (it will pause at on_load:wait)
    log("Launching app (will pause at Frida gadget)...")
    subprocess.run(["adb", "shell", "am", "start", "-n",
                   f"{args.package}/{args.activity}"],
                  capture_output=True)

    # Step 6: Wait for gadget to start listening
    log("Waiting for Frida gadget to listen...")
    device = None
    session = None
    for attempt in range(30):
        time.sleep(1)
        try:
            device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            procs = device.enumerate_processes()
            log(f"Connected! Processes: {[p.name for p in procs]}")
            session = device.attach("Gadget")
            log(f"Attached to Gadget")
            break
        except Exception as e:
            if attempt % 5 == 4:
                log(f"Attempt {attempt+1}: {e}")
            continue

    if not session:
        log("Failed to connect to Frida gadget")
        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(lines) + "\n")
        return

    # Step 7: Load our hook script
    log("Loading JNI cert spoof hooks...")
    with open(args.script, "r") as f:
        script_code = f.read()

    script = session.create_script(script_code)
    script.on('message', on_message_handler(log))
    script.load()
    log("Script loaded!")

    # Step 8: Resume the app (it was paused by on_load:wait)
    log("Resuming app execution...")
    procs = device.enumerate_processes()
    for p in procs:
        if p.name == "Gadget":
            log(f"Resuming PID {p.pid}...")
            device.resume(p.pid)
            break
    log("App resumed! Monitoring...")
    log("=> Try logging in when the login screen appears!")

    # Step 9: Monitor
    try:
        for i in range(args.duration):
            time.sleep(1)
            if i > 0 and i % 15 == 0:
                log(f"... {i}s elapsed, {len(lines)} messages")
    except KeyboardInterrupt:
        log("Interrupted")

    log("Done monitoring.")

    try:
        script.unload()
        session.detach()
    except:
        pass

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"\n[*] Saved {len(lines)} lines to {args.output}")


if __name__ == "__main__":
    main()
