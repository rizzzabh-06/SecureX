#!/bin/bash
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

echo "Killing existing emulator..."
adb emu kill 2>/dev/null || true
sleep 3

echo "Starting emulator with GUI..."
nohup emulator -avd threat_hunter -no-audio -no-boot-anim -gpu swiftshader_indirect -memory 2048 -no-snapshot-save > /tmp/emulator_gui.log 2>&1 &

echo "Waiting for device..."
adb wait-for-device
echo "✅ Emulator GUI started!"
