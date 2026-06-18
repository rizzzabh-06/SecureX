# SecureX Services Management Guide

This guide describes how to check ports/emulators, stop any running components safely, and restart everything cleanly after a system reboot.

---

## 1. Checking Currently Active Ports & Processes

Before starting anything, run these commands to verify if any ports or emulators are already in use.

### A. Check Network Ports
Identify if the frontend, backend, MobSF, or Redis are already bound to their respective ports:
```bash
# Check Backend API (Port 8000)
lsof -i :8000

# Check Frontend Next.js (Port 3000)
lsof -i :3000

# Check MobSF (Port 8008)
lsof -i :8008

# Check Redis (Port 6379)
lsof -i :6379
```

### B. Check Docker (Colima VM & Containers)
Since Docker containers run in an isolated Lima VM inside this directory, check the status using the project-specific environment variables:
```bash
export LIMA_HOME="/Users/rishabhrajsingh/Downloads/genai/.lima"
export DOCKER_CONFIG="/Users/rishabhrajsingh/Downloads/genai/.docker"

# Check if the Colima VM is running
colima status

# List active Docker containers
docker ps -a
```

### C. Check Android Emulator & Frida
Check if the emulator process is running and whether `adb` can detect it:
```bash
export ANDROID_HOME="/Users/rishabhrajsingh/Downloads/genai/android_sdk"
export PATH="$ANDROID_HOME/platform-tools:$PATH"

# List devices connected to adb
adb devices

# Check running processes for the emulator
ps aux | grep -i emulator
```

---

## 2. Stopping Services Safely

If any service is running and you want a clean state, follow these procedures:

### A. Stop Ports 8000 and 3000 (Backend / Frontend PIDs)
If `lsof` returns a PID, kill the processes:
```bash
# Safely kill process running on port 8000 (Backend)
kill -9 $(lsof -t -i :8000) 2>/dev/null || true

# Safely kill process running on port 3000 (Frontend)
kill -9 $(lsof -t -i :3000) 2>/dev/null || true
```

### B. Stop Docker Containers & Colima VM
Stop and remove the Docker containers, and shut down the Colima VM:
```bash
cd /Users/rishabhrajsingh/Downloads/genai

export LIMA_HOME="/Users/rishabhrajsingh/Downloads/genai/.lima"
export DOCKER_CONFIG="/Users/rishabhrajsingh/Downloads/genai/.docker"

# Stop MobSF and Redis containers
docker compose down

# Stop the Colima VM
colima stop
```

### C. Stop Android Emulator & Frida
```bash
export ANDROID_HOME="/Users/rishabhrajsingh/Downloads/genai/android_sdk"
export PATH="$ANDROID_HOME/platform-tools:$PATH"

# Tell the emulator to save state and shut down
adb emu kill 2>/dev/null || true

# Or forcefully kill the emulator process
pkill -f emulator
```

---

## 3. Starting Everything Again Safely

Follow this step-by-step sequence to bring up all services cleanly.

### Step 1: Docker (Colima VM + MobSF + Redis)
Start the VM first, then use Docker Compose to start the dependent services:
```bash
cd /Users/rishabhrajsingh/Downloads/genai

# 1. Set Lima & Docker Isolation Variables
export LIMA_HOME="/Users/rishabhrajsingh/Downloads/genai/.lima"
export DOCKER_CONFIG="/Users/rishabhrajsingh/Downloads/genai/.docker"

# 2. Spin up Colima VM
colima start --cpu 2 --memory 4 --disk 20

# 3. Start MobSF and Redis containers
docker compose up -d
```

---

### Step 2: Android Emulator & Frida Server
Choose either **Headless Mode** or **GUI Mode** to run the emulator:

#### Option A: Headless Mode (Recommended for CLI)
Run the project's setup script. This automatically verifies AVDs, starts the emulator in headless mode, waits for boot, pushes `frida-server`, and launches it:
```bash
cd /Users/rishabhrajsingh/Downloads/genai
chmod +x scripts/setup_emulator.sh
./scripts/setup_emulator.sh
```

#### Option B: GUI Mode (To see the Android device screen)
If you want to view the emulator window, start the GUI emulator manually with local SDK paths, then run the frida-server setup:
```bash
# 1. Set Local Android Environment Variables
export ANDROID_HOME="/Users/rishabhrajsingh/Downloads/genai/android_sdk"
export ANDROID_USER_HOME="/Users/rishabhrajsingh/Downloads/genai/android_data"
export ANDROID_AVD_HOME="/Users/rishabhrajsingh/Downloads/genai/android_data/avd"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

# 2. Launch GUI Emulator in the background
nohup emulator -avd threat_hunter \
    -no-audio \
    -no-boot-anim \
    -gpu swiftshader_indirect \
    -memory 2048 \
    -no-snapshot-save > /tmp/emulator_gui.log 2>&1 &

# 3. Wait for boot and start Frida
adb wait-for-device
adb root && sleep 2

# Push and run frida-server
FRIDA_BIN="/Users/rishabhrajsingh/Downloads/genai/.frida-server/frida-server-17.12.0-android-arm64"
adb push "$FRIDA_BIN" /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "pkill -f frida-server" 2>/dev/null || true
adb shell "/data/local/tmp/frida-server -D &"

# Verify frida is reachable
frida-ps -U
```

---

### Step 3: Backend API (Python 3.11 with Frida)
> [!IMPORTANT]
> You **MUST** run the backend using the virtual environment's **Python 3.11** binary explicitly. Frida is compiled and installed in `python3.11`'s site-packages, and system Python (3.12) will crash or throw missing module errors.

```bash
cd /Users/rishabhrajsingh/Downloads/genai

# Run backend using python3.11 module call
/Users/rishabhrajsingh/Downloads/genai/.venv/bin/python3.11 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

### Step 4: Frontend (Next.js)
Launch the Next.js development server:
```bash
cd /Users/rishabhrajsingh/Downloads/genai/frontend

# Start frontend
npm run dev
```

You can now open `http://localhost:3000` to start analyzing APKs!
