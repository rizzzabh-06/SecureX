#!/bin/bash
export ANDROID_HOME=/home/rishabh/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools

echo "Starting emulator..."
$ANDROID_HOME/emulator/emulator -avd threat_hunter -no-window -no-snapshot -no-audio -no-boot-anim &
EMULATOR_PID=$!

echo "Waiting for emulator to boot..."
$ANDROID_HOME/platform-tools/adb wait-for-device
while [ "$($ANDROID_HOME/platform-tools/adb shell getprop sys.boot_completed | tr -d '\r')" != "1" ]; do
    sleep 2
done

echo "Emulator booted successfully. PID: $EMULATOR_PID"
