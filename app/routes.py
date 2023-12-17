# app/routes.py

import zipfile
import requests
import shutil
from flask import Blueprint, jsonify, request, json, Response
from app.parsers.package_lock_parser import parse_package_lock, write_to_file
from app.parsers.oss_python_parser import parse_requirements, fetch_vulnerabilities, update_vulnerabilities
from dotenv import load_dotenv, dotenv_values
import os
import uuid

routes = Blueprint('routes', __name__)

load_dotenv()


@routes.route('/')
def starter_function():
    return "Flask: Parser for SIH"

# javascript parser for local testing


@routes.route('/generate')
def create_js_sbom():
    package_lock_path = "./package-lock.json"
    package_audit_path = "./package_audit.json"
    output = parse_package_lock(package_lock_path, package_audit_path)

    output_file_path = 'js-sbom.json'
    write_to_file(output, output_file_path)

    return jsonify({"message": "Parsed data written to js-sbom.json file."})


# javascript parser for postman testing
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

            parsed_data = parse_package_lock(
                package_lock_path, package_audit_path)
            json_string = json.dumps(
                parsed_data, separators=(",", ":"), sort_keys=False, ensure_ascii=False)
            os.remove(package_lock_path)
            os.remove(package_audit_path)

            return jsonify(json_string, )

    except Exception as e:
        return jsonify({"error": str(e)})


# python routes

# use this route to test locally (put requirements.txt in uploads folder)
@routes.route('/python-parser')
def create_python_sbom():
    try:
        requirements_path = os.path.join(
            os.getcwd(), 'uploads', 'requirements.txt')

        # Parsing requirements and fetching vulnerabilities from OSS Index API
        components = parse_requirements(requirements_path)
        purls = [component["purl"] for component in components]

        vulnerabilities_data = fetch_vulnerabilities(purls)

        if vulnerabilities_data:
            # Updating vulnerabilities in the components array
            update_vulnerabilities(components, vulnerabilities_data)

        output_file_path = os.path.join(
            os.getcwd(), 'uploads', 'python-sbom.json')

        # Writes the parsed data to the 'python-sbom.json' file
        write_to_file(components, output_file_path)

        return jsonify({"message": "Parsed data written to python-sbom file."})

    except Exception as e:
        return jsonify({"error": str(e)})


# this route was using pip-audit to fetch vulnerabilities which was taking so long to fetch the vulnerabilities so that's why not using this
# use for postman
# @routes.route('/python/pip-parser-audit', methods=['POST'])
# def pip_parser():
#     try:
#         if 'requirements_file' not in request.files:
#             return jsonify({"error": "'requirements_file' is required."})

#         uploaded_requirements_file = request.files['requirements_file']

#         if not uploaded_requirements_file.filename:
#             return jsonify({"error": "File name cannot be empty."})

#         # Create paths using os.path.join
#         uploads_folder = 'uploads'
#         requirements_filename = uploaded_requirements_file.filename
#         requirements_path = os.path.join(uploads_folder, requirements_filename)
#         vulnerabilities_path = os.path.join(uploads_folder, 'audit.json')

#         uploaded_requirements_file.save(requirements_path)

#         # This will generate /uploads/audit.json (temporarily)
#         fetch_vulnerabilities(requirements_path)

#         output = parse_requirements(requirements_path)
#         update_vulnerabilities(output, vulnerabilities_path)

#         json_string = json.dumps(output, sort_keys=False, ensure_ascii=False)

#         # Remove the uploaded files
#         os.remove(requirements_path)
#         os.remove(vulnerabilities_path)

#         return jsonify(json_string)

#     except Exception as e:
#         return jsonify({"error": str(e)})


# use this route for postman
@routes.route('/python/pip-parser', methods=['POST'])
def pip_parser():
    try:
        if 'requirements_file' not in request.files:
            return jsonify({"error": "'requirements_file' is required."})

        uploaded_requirements_file = request.files['requirements_file']

        if not uploaded_requirements_file.filename:
            return jsonify({"error": "File name cannot be empty."})

        # Generate a unique identifier for this request (you can use a timestamp or UUID)
        unique_identifier = str(uuid.uuid4())[:8]  # Using a UUID as an example

        # Create paths using os.path.join
        uploads_folder = 'uploads'
        requirements_filename = f"{unique_identifier}_requirements.txt"
        requirements_path = os.path.join(uploads_folder, requirements_filename)

        uploaded_requirements_file.save(requirements_path)

        # Parse requirements and fetch vulnerabilities from OSS Index API
        components = parse_requirements(requirements_path)
        # purls = [component["purl"] for component in components]

        # vulnerabilities_data = fetch_vulnerabilities(purls)

        # if vulnerabilities_data:
        #     # Update vulnerabilities in the components array
        #     update_vulnerabilities(components, vulnerabilities_data)

        json_string = json.dumps(
            components, sort_keys=False, ensure_ascii=False)

        # Remove the uploaded file
        os.remove(requirements_path)

        return jsonify(json_string)

    except Exception as e:
        return jsonify({"error": str(e)})


# ============== ZIP File handling =====================
def extract_zip(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)


def clean_temp_directory(extract_dir):
    shutil.rmtree(extract_dir)


def post_request_with_file(package_json_file_path, package_lock_file_path):
    try:
        url = os.getenv("js-server-url") + "/api/javascript/auditJsPackage"
        headers = {'auth_type': 'backend',
                   'auth_code': os.getenv('js-server-auth-key')}
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
            return response.json()
        else:
            print(f"Request failed with status code: {response.status_code}")
            print("Response:")
            print(response.text)

    except Exception as e:
        print(f"Error: {e}")


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
        package_files = {"package": "", 'package_lock': ""}

        components = []
        for root, dirs, files in os.walk(extract_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                print("hit main code ", file_name)

                if file_name == 'package.json':
                    package_files['package'] = file_path

                if file_name == 'package-lock.json':
                    package_files['package_lock'] = file_path

                elif file_name == 'REQUIREMENTS.txt':
                    pass

                if package_files['package'] != '' and package_files['package_lock'] != '':
                    print('creating post req')
                    res = post_request_with_file(
                        package_json_file_path=package_files['package'], package_lock_file_path=package_files['package_lock'])
                    print(res.keys())
                    audit_obj = res["data"]

                    parsed_data = parse_package_lock(
                        package_lock_path=package_files['package_lock'], package_audit_path=audit_obj, obj=True)
                    components.extend(parsed_data)
                    package_files['package'] = ''
                    package_files['package_lock'] = ''
        json_string = json.dumps(
            components, sort_keys=False, ensure_ascii=False)
        return jsonify(json_string)

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

    finally:
        clean_temp_directory(extract_dir)
