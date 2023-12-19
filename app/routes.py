# app/routes.py

from flask import Blueprint, jsonify, request, json, Response
from app.parsers.package_lock_parser import parse_package_lock, write_to_file
from app.parsers.oss_python_parser import parse_requirements, fetch_vulnerabilities, update_vulnerabilities
from app.parsers.maven_parser import parse_pom_and_fetch_vulnerabilities, fetch_vulnerabilities, update_vulnerabilities
from app.parsers.zip_parser import parse_zip_file
from werkzeug.utils import secure_filename
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

        # Call the function from zip_parser to handle the main logic
        return parse_zip_file(zip_path, extract_dir)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    



@routes.route('/java/maven-parser', methods=['POST'])
def maven_parser():
    try:
        if 'pom_file' not in request.files:
            return jsonify({"error": "'pom_file' is required."})

        uploaded_pom_file = request.files['pom_file']

        if not uploaded_pom_file.filename:
            return jsonify({"error": "File name cannot be empty."})

        pom_data = uploaded_pom_file.read()

        # Parse pom.xml and fetch vulnerabilities
        components = parse_pom_and_fetch_vulnerabilities(pom_data)

        json_string = json.dumps(components, sort_keys=False, ensure_ascii=False)

        return jsonify(json_string)

    except Exception as e:
        return jsonify({"error": str(e)})