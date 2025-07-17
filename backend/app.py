import os
import subprocess
import shutil
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS # type: ignore
from werkzeug.utils import secure_filename
import scanner

app = Flask(__name__)
CORS(app) # Allow requests from the React frontend

UPLOAD_FOLDER = 'uploads'
DECOMPILED_FOLDER = 'decompiled'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/scan', methods=['POST'])
def scan_apk():
    if 'apkfile' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['apkfile']
    if file.filename == '' or not file.filename.endswith('.apk'):
        return jsonify({"error": "Invalid file"}), 400

    # Create a unique directory for this scan
    scan_id = str(uuid.uuid4())
    apk_filename = secure_filename(file.filename)
    apk_path = os.path.join(UPLOAD_FOLDER, apk_filename)
    decompiled_path = os.path.join(DECOMPILED_FOLDER, scan_id)
    
    file.save(apk_path)

    try:
        # 1. Decompile the APK using apktool
        print(f"[*] Decompiling {apk_path}...")
        subprocess.run(
            ['java', '-jar', 'C:/Apktool/apktool.jar', 'd', apk_path, '-o', decompiled_path, '-f'],
            check=True,
            capture_output=True,
            text=True
        )

        # 2. Run the actual analysis
        print(f"[*] Analyzing files in {decompiled_path}...")
        report = scanner.analyze_apk(decompiled_path)
        
        return jsonify(report)

    except subprocess.CalledProcessError as e:
        print(f"ERROR: apktool failed: {e.stderr}")
        return jsonify({"error": "Failed to decompile APK.", "details": e.stderr}), 500
    except Exception as e:
        print(f"ERROR: Analysis failed: {e}")
        return jsonify({"error": "An unexpected error occurred during analysis."}), 500
    finally:
        # 3. Clean up the uploaded and decompiled files
        if os.path.exists(apk_path):
            os.remove(apk_path)
        if os.path.exists(decompiled_path):
            shutil.rmtree(decompiled_path)
        print("[*] Cleanup complete.")


if __name__ == '__main__':
    app.run(debug=True, port=5000)