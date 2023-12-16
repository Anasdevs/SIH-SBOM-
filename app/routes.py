# app/routes.py

from flask import Blueprint, jsonify, request, json, Response
from app.parsers.package_lock_parser import parse_package_lock, write_to_file
from dotenv import load_dotenv, dotenv_values
import os

routes = Blueprint('routes', __name__)

load_dotenv()

@routes.route('/')
def starter_function():
    return "Flask: Parser for SIH"

@routes.route('/generate')
def create_js_sbom():
    package_lock_path = "./package-lock.json"
    package_audit_path="./package_audit.json"
    output = parse_package_lock(package_lock_path, package_audit_path)

    output_file_path = 'js-sbom.json'
    write_to_file(output, output_file_path)

    return jsonify({"message": "Parsed data written to js-sbom.json file."})

@routes.route('/js/npm-parser', methods=['POST'])
def npm_parser():
    try:
        uploaded_package_lock = request.files['package_lock']
        uploaded_package_audit = request.files['package_audit']

        if uploaded_package_lock and uploaded_package_audit:  
            package_lock_path = f"uploads/{uploaded_package_lock.filename}"
            package_audit_path = f"uploads/{uploaded_package_audit.filename}"
            uploaded_package_lock.save(package_lock_path)
            uploaded_package_audit.save(package_audit_path)

            parsed_data = parse_package_lock(package_lock_path, package_audit_path)
            json_string = json.dumps(
                parsed_data, separators=(",", ":"))
            os.remove(package_lock_path)
            os.remove(package_audit_path)

            return jsonify(json_string)
    
    except Exception as e:
        return jsonify({"error": str(e)})

# ============== ZIP File handling =====================
def extract_zip(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

import shutil
def clean_temp_directory(extract_dir):
    shutil.rmtree(extract_dir)

import requests
def post_request_with_file(package_json_file_path, package_lock_file_path):
    try:
        url = os.getenv("js-server-url") +"/api/javascript/generateSbom"
        headers = {'auth-type':'backend', 'auth-token':os.getenv('js-server-auth-key')}
        print(headers)

        files = {
            'package_json_file': ('package.json', open(package_json_file_path, 'rb')),
            'package_lock_file': ('package-lock.json', open(package_lock_file_path, 'rb'))
        }
        response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            print("Request successful!")
            print("Response:")
            print(response.json())
        else:
            print(f"Request failed with status code: {response.status_code}")
            print("Response:")
            print(response.text)

    except Exception as e:
        print(f"Error: {e}")

import zipfile
import os
@routes.route('/parse_zip', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not file.filename.endswith('.zip'):
        return jsonify({"error": "Invalid file format. Please provide a ZIP file"}), 400
    
    extract_dir = 'temp_extract'
    os.makedirs(extract_dir, exist_ok=True)

    try:
        zip_path = os.path.join(extract_dir, file.filename)
        file.save(zip_path)

        extract_zip(zip_path, extract_dir)

        # package_json_files = []
        # requirement_txt_files = []
        package_files = {"package":"",'package_lock':""}

        for root, dirs, files in os.walk(extract_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Main Code 
                print("hit main code ",file_name)

                if file_name == 'package.json':
                    package_files['package'] = file_path
                    # content = read_package_json(file_path)
                    # package_json_files.append(content)

                if file_name == 'package-lock.json':
                    package_files['package_lock'] = file_path

                    # content = read_package_json(file_path)
                    # package_json_files.append(content)
                    

                elif file_name == 'REQUIREMENT.txt':
                    # content = read_requirement_txt(file_path)
                    # requirement_txt_files.append(content)
                    pass

                if package_files['package'] !='' and package_files['package_lock'] != '':
                    print('creating post req')
                    post_request_with_file(package_json_file_path=package_files['package'], package_lock_file_path=package_files['package_lock'])

        result = {
            "success": True,
            "SBOM":{"package.json":package_json_files,
                    "requirement":requirement_txt_files},
            "files found":{
                "package.json":package_json_files,
                "requirement":requirement_txt_files
            }
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        clean_temp_directory(extract_dir)


