import os
import shutil
import zipfile
import requests
import json
from app.parsers.package_lock_parser import parse_package_lock
from app.parsers.oss_python_parser import parse_requirements
from app.parsers.maven_parser import parse_pom_and_fetch_vulnerabilities
from flask import jsonify


def extract_zip(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

def clean_temp_directory(extract_dir):
    shutil.rmtree(extract_dir)

def post_request_with_file(package_json_file_path, package_lock_file_path):
    try:
        url = os.getenv("js-server-url") + "/api/javascript/auditJsPackage"
        headers = {'auth_type': 'backend', 'auth_code': os.getenv('js-server-auth-key')}

        files = {
            'package_json_file': ('package.json', open(package_json_file_path, 'rb')),
            'package_lock_file': ('package-lock.json', open(package_lock_file_path, 'rb'))
        }
        response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Request failed with status code: {response.status_code}")
    

    except Exception as e:
        print(f"Error: {e}")

def parse_zip_file(zip_path, extract_dir):
    try:
        extract_zip(zip_path, extract_dir)

        package_files = {"package": "", "package_lock" : "", "requirements" : "", "pom" : ""}

        components = []
        for root, dirs, files in os.walk(extract_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                if file_name == 'package.json':
                    package_files['package'] = file_path

                if file_name == 'package-lock.json':
                    package_files['package_lock'] = file_path

                if file_name in ['requirements.txt', 'REQUIREMENTS.txt']:
                    package_files['requirements'] = file_path

                if file_name in ['pom.xml']:
                    package_files['pom'] = file_path

                    
                if package_files['package'] != '' and package_files['package_lock'] != '':
                    res = post_request_with_file(
                        package_json_file_path=package_files['package'], package_lock_file_path=package_files['package_lock'])
    
                    audit_obj = res["data"]

                    parsed_data = parse_package_lock(
                        package_lock_path=package_files['package_lock'], package_audit_path=audit_obj, obj=True)
                    components.extend(parsed_data)
                    package_files['package'] = ''
                    package_files['package_lock'] = ''
                
                if package_files['requirements'] != '':
                    parsed_data = parse_requirements(requirements_path=package_files['requirements'])
                    components.extend(parsed_data)
                    package_files['requirements'] = ''

                if package_files['pom'] != '':
                    parsed_data = parse_pom_and_fetch_vulnerabilities(xml_data=package_files['pom'])
                    components.extend(parsed_data)
                    package_files['pom'] = ''
                    

        json_string = json.dumps(
            components, sort_keys=False, ensure_ascii=False)
        return jsonify(json_string)

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

    finally:
        clean_temp_directory(extract_dir)
