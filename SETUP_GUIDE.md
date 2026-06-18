# SecureX Setup & Installation Guide

Welcome to SecureX! Because some components of this project (like the Android SDK, emulator images, and AI models) are extremely massive, they have been intentionally excluded from the Git repository via `.gitignore`. 

If you have just cloned this repository, follow this step-by-step guide to download all the necessary tools and set up your environment perfectly.

---



## 1. Environment Setup

First, you need to set up your environment variables and API keys.

1. Copy the example environment file to create your local `.env`:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and fill in your API keys (Groq, Gemini, VirusTotal, Supabase, etc.).
   * *Note: If you do not have a HuggingFace Token for `HF_TOKEN`, the RAG engine will still download the open-source models, but you may hit rate limits.*

---

## 2. Backend & Frontend Dependencies

### Python Backend
SecureX uses Python for the core analysis pipeline and AI agents.

1. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

### Next.js Frontend
The dashboard is built with React/Next.js.

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install Node.js dependencies:
   ```bash
   npm install
   ```

---

## 3. Android SDK & Emulator Setup (Dynamic Analysis)

To perform dynamic analysis with Frida, SecureX requires a local headless Android Emulator. Because the Android system images are massive, we use automated scripts to download and configure them inside the `android_sdk/` directory.

1. Make the setup scripts executable:
   ```bash
   chmod +x scripts/setup_emulator.sh
   chmod +x start_emulator.sh
   ```
2. Run the emulator setup script. This will download the Android command-line tools, system images (API 34), create the Virtual Device, and download the correct `frida-server` binary:
   ```bash
   ./scripts/setup_emulator.sh
   ```
   *(Note: This step requires a stable internet connection and will download several gigabytes of data.)*

---

## 4. Running SecureX

Once everything is installed, you need to start three separate processes. Open three different terminal windows:

**Terminal 1: Start the Android Emulator**
```bash
# Wait for the "Boot completed" message before starting analysis
./start_emulator.sh
```

**Terminal 2: Start the FastAPI Backend**
```bash
source .venv/bin/activate
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 3: Start the Next.js Frontend**
```bash
cd frontend
npm run dev
```

You can now access the SecureX dashboard at [http://localhost:3000](http://localhost:3000) and begin analyzing APKs!


## 5. Excluded Files (What wasn't pushed and why)

Based on the `.gitignore` rules, the following large directories and files were not pushed to GitHub:

* **`.venv/`, `node_modules/`**: Python and Node.js dependencies (can be reinstalled via `pip` and `npm`).
* **`android_sdk/`, `android_data/`**: The entire Android SDK, command-line tools, and virtual device images. These can exceed 10GB+ in size.
* **`.frida-server/`**: The Frida server binaries used for dynamic analysis hook injection.
* **`.hf_cache/`**: HuggingFace transformer models downloaded by the RAG engine for semantic search.
* **`chromadb_data/`, `uploads/`, `reports/`**: Local database, uploaded APKs, and generated PDF reports.
* **`.env`**: Contains sensitive API keys and secrets.

---
