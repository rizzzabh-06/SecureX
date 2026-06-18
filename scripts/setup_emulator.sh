#!/bin/bash
# ============================================================
# setup_emulator.sh
# Sets up Android emulator + Frida server for dynamic analysis
# ============================================================

set -e

# Get absolute path of the project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export ANDROID_HOME="${ANDROID_HOME:-$PROJECT_ROOT/android_sdk}"
export ANDROID_USER_HOME="$PROJECT_ROOT/android_data"
export ANDROID_AVD_HOME="$PROJECT_ROOT/android_data/avd"

export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

AVD_NAME="threat_hunter"
SYSTEM_IMAGE="system-images;android-34;google_apis;arm64-v8a"
FRIDA_VERSION="17.12.0"  # Must match Python frida package version
FRIDA_ARCH="arm64"      # Match emulator architecture

echo "============================================"
echo " SecureX — Emulator Setup"
echo "============================================"

# --- Step 1: Verify SDK components ---
echo ""
echo "[1/5] Verifying SDK components..."
if ! command -v sdkmanager &>/dev/null; then
    echo "❌ sdkmanager not found. Install Android cmdline-tools first."
    exit 1
fi

if ! command -v adb &>/dev/null; then
    echo "⚠ adb not found, installing platform-tools..."
    yes | sdkmanager --sdk_root="$ANDROID_HOME" "platform-tools" 2>/dev/null
fi

if ! command -v emulator &>/dev/null; then
    echo "⚠ emulator not found, installing..."
    yes | sdkmanager --sdk_root="$ANDROID_HOME" "emulator" 2>/dev/null
fi

# Check system image
if [ ! -d "$ANDROID_HOME/system-images/android-34/google_apis/x86_64" ]; then
    echo "⚠ System image not found, installing (this may take a while)..."
    yes | sdkmanager --sdk_root="$ANDROID_HOME" "$SYSTEM_IMAGE" 2>/dev/null
fi

echo "✅ SDK components verified"

# --- Step 2: Create AVD ---
echo ""
echo "[2/5] Creating AVD '$AVD_NAME'..."
if avdmanager list avd 2>/dev/null | grep -q "$AVD_NAME"; then
    echo "   AVD '$AVD_NAME' already exists, skipping creation"
else
    echo "no" | avdmanager create avd \
        --name "$AVD_NAME" \
        --package "$SYSTEM_IMAGE" \
        --device "pixel_6" \
        --force 2>/dev/null
    echo "✅ AVD created"
fi

# --- Step 3: Download frida-server ---
echo ""
echo "[3/5] Setting up frida-server v${FRIDA_VERSION}..."
FRIDA_DIR="$PROJECT_ROOT/.frida-server"
FRIDA_BIN="$FRIDA_DIR/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}.xz"

mkdir -p "$FRIDA_DIR"

if [ -f "$FRIDA_BIN" ]; then
    echo "   frida-server binary already downloaded"
else
    echo "   Downloading frida-server from GitHub..."
    curl -L -o "${FRIDA_BIN}.xz" "$FRIDA_URL" 2>/dev/null
    echo "   Decompressing..."
    xz -d "${FRIDA_BIN}.xz"
    chmod +x "$FRIDA_BIN"
    echo "✅ frida-server downloaded to $FRIDA_BIN"
fi

# --- Step 4: Start emulator ---
echo ""
echo "[4/5] Starting emulator..."

# Check if already running
if adb devices 2>/dev/null | grep -q "emulator-"; then
    echo "   Emulator already running"
else
    echo "   Launching emulator in background (headless: -no-window)..."
    echo "   Use '-gpu swiftshader_indirect' for software rendering"
    nohup emulator -avd "$AVD_NAME" \
        -no-window \
        -no-audio \
        -no-boot-anim \
        -gpu swiftshader_indirect \
        -memory 2048 \
        -no-snapshot-save \
        > /tmp/emulator.log 2>&1 &
    
    EMULATOR_PID=$!
    echo "   Emulator PID: $EMULATOR_PID"
    echo "   Waiting for boot (this takes 1-3 minutes)..."
    
    # Wait for device
    adb wait-for-device
    
    # Wait for boot_completed
    BOOT_TIMEOUT=180
    ELAPSED=0
    while [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; do
        sleep 5
        ELAPSED=$((ELAPSED + 5))
        if [ $ELAPSED -ge $BOOT_TIMEOUT ]; then
            echo "❌ Emulator boot timed out after ${BOOT_TIMEOUT}s"
            echo "   Check /tmp/emulator.log for errors"
            exit 1
        fi
        echo "   Still booting... (${ELAPSED}s)"
    done
    echo "✅ Emulator booted"
fi

# --- Step 5: Push and start frida-server ---
echo ""
echo "[5/5] Deploying frida-server to emulator..."

# Root the emulator (emulators with google_apis are rootable)
adb root 2>/dev/null && sleep 2

# Push frida-server
adb push "$FRIDA_BIN" /data/local/tmp/frida-server 2>/dev/null
adb shell "chmod 755 /data/local/tmp/frida-server"

# Kill any existing frida-server
adb shell "pkill -f frida-server" 2>/dev/null || true
sleep 1

# Start frida-server in background
adb shell "/data/local/tmp/frida-server -D &" 2>/dev/null
sleep 2

# Verify
if adb shell "pidof frida-server" 2>/dev/null | grep -q "[0-9]"; then
    echo "✅ frida-server is running on emulator!"
else
    echo "⚠ frida-server may not have started. Trying alternative method..."
    adb shell "nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &"
    sleep 2
    if adb shell "pidof frida-server" 2>/dev/null | grep -q "[0-9]"; then
        echo "✅ frida-server is running (alternative method)"
    else
        echo "❌ Could not start frida-server. Check manually."
        exit 1
    fi
fi

echo ""
echo "============================================"
echo " ✅ Setup Complete!"
echo "============================================"
echo ""
echo " Emulator:     $AVD_NAME (Android 14, x86_64)"
echo " frida-server: v${FRIDA_VERSION} running on device"
echo " ADB:          $(adb devices | grep emulator)"
echo ""
echo " Test with:  frida-ps -U"
echo " Run app:    python -m uvicorn app.main:app --reload"
echo ""
echo "============================================"
