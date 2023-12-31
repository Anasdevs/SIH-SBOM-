# app/routes.py

from flask import Blueprint, jsonify, request, json, Response, send_file
from app.parsers.package_lock_parser import parse_package_lock, write_to_file
from app.parsers.oss_python_parser import parse_requirements, fetch_vulnerabilities, update_vulnerabilities
from app.parsers.maven_parser import parse_pom_and_fetch_vulnerabilities, fetch_vulnerabilities, update_vulnerabilities
from app.parsers.composer_parser import parse_composer_json, fetch_vulnerabilities, update_vulnerabilities
from app.parsers.cargo_parser import parse_cargo_lock, fetch_vulnerabilities, update_vulnerabilities
from app.parsers.zip_parser import parse_zip_file
import os
import uuid

routes = Blueprint('routes', __name__)

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

    print("Got file")
    extract_dir = 'temp_extract'
    os.makedirs(extract_dir, exist_ok=True)
    print("Made directory")

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

import io
@routes.route('/get_pdf', methods=['post'])
def get_pdf():
    data = request.get_json()
    # try:
    # if 'sbom_file' not in request.files:
    #     return {"Error": "No 'sbom_file' provided in the request."}, 400

    # sbom_file = request.files['sbom_file']

    # if sbom_file.filename == '':
    #     return {"Error": "No selected file."}, 400

    # if sbom_file and sbom_file.filename.endswith('.json'):
    sbom_data = data['data']

    from .helper import create_markdown_report, get_pdf, preset_gpt
    sys_prompt = 'give me a breif report of the given SBOM, include number of components, dependencies and vulnerabilities, etc, give 2 page worth of paragraph each time'
    # gpt_gen = preset_gpt(System_prompt=sys_prompt, prompt=json.dumps(sbom_data))
    # print(gpt_gen)
    # markdown = create_markdown_report(sbom_data, gpt_gen)
    markdown = create_markdown_report(sbom_data)
    pdf_content = get_pdf(markdown)

    if pdf_content is not None:
        return send_file(
            io.BytesIO(pdf_content),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='generated_pdf.pdf'
        )
    else:
        return "PDF generation failed.", 500
    # except Exception as e:
    #     print(e)
    #     return {"Error":"An error occurred while generating the PDF"}

@routes.route("/mail_notification", methods=['POST'])
def mailing_function():
    data = request.get_json()
        
    email = data['email']
    message = data['message']
    subject = data['subject']

    from .helper import send_email

    res = send_email(email= email, message1=message,subject= subject)
    if res:
        return jsonify({"Status":True}), 200
    else:
        return jsonify({"Status":False}), 200
    
'''
{
	"email":"harshagnihotri90@gmail.com",
	"liberary":"pandas",
	"version":"1.2.3",
	"message":"super serious message",
	"link":"a very orignal link"
}
'''

@routes.route('/php/composer-parser', methods=['POST'])
def composer_parser():
    try:
        if 'composer_file' not in request.files:
            return jsonify({"error": "'composer_file' is required."})

        uploaded_composer_file = request.files['composer_file']

        if not uploaded_composer_file.filename:
            return jsonify({"error": "File name cannot be empty."})

        uploads_folder = 'uploads'
        current_directory = os.getcwd()
        composer_json_path = os.path.join(current_directory, uploads_folder, 'composer.json')

        # Save the uploaded file to the 'uploads' folder
        uploaded_composer_file.save(composer_json_path)

        # Parse composer.json and fetch vulnerabilities
        components = parse_composer_json(composer_json_path)

        json_string = json.dumps(components, sort_keys=False, ensure_ascii=False)

        # Optionally, remove the uploaded file after parsing
        os.remove(composer_json_path)


        return jsonify(json_string)

    except Exception as e:
        return jsonify({"error": str(e)})

import subprocess
import tempfile

import os
import tempfile
import shutil
@routes.route('/upload_exe', methods=['POST'])
def upload_exe():
    # try:
        # Check if the POST request has the file part
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    # Check if the file is empty
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    # Check if the file has a valid extension (e.g., .exe)
    if not file.filename.endswith('.exe'):
        return jsonify({'error': 'Invalid file extension'})

    # Create a temporary directory to store the file
    temp_dir = tempfile.mkdtemp()
    temp_file_path = os.path.join(temp_dir, file.filename)

    # Save the file to the temporary directory
    file.save(temp_file_path)

    # Provide the repo information (replace with your actual repo logic)
    # repo_info = {'repo_url': 'https://example.com/repo'}

    # Run the process_exe function
    from .parsers.exe_parser import analyze_pe_file
    result = analyze_pe_file(temp_file_path)


    # Delete the temporary directory and its contents
    shutil.rmtree(temp_dir, ignore_errors=True)

    return jsonify({'result': result})


    # except Exception as e:
    #     return jsonify({'error': str(e)})



@routes.route('/rust/cargo-parser', methods=['POST'])
def cargo_parser():
    try:
        if 'cargo_file' not in request.files:
            return jsonify({"error": "Cargo file is required."})

        uploaded_cargo_file = request.files['cargo_file']

        if not uploaded_cargo_file.filename:
            return jsonify({"error": "File name cannot be empty."})

        uploads_folder = 'uploads'
        current_directory = os.getcwd()
        cargo_json_path = os.path.join(current_directory, uploads_folder, 'cargo.json')

        # Save the uploaded file to the 'uploads' folder
        uploaded_cargo_file.save(cargo_json_path)

        # Parse composer.json and fetch vulnerabilities
        components = parse_cargo_lock(cargo_json_path)

        json_string = json.dumps(components, sort_keys=False, ensure_ascii=False)

        os.remove(cargo_json_path)


        return jsonify(json_string)

    except Exception as e:
        return jsonify({"error": str(e)})