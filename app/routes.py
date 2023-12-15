# app/routes.py

from flask import Blueprint, jsonify, request, json, Response
from app.parsers.package_lock_parser import parse_package_lock, write_to_file
from app.parsers.requirements_parser import parse_requirements, fetch_vulnerabilities, update_vulnerabilities
import os

routes = Blueprint('routes', __name__)


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
    



#python routes 

@routes.route('/python-parser') #use this route to test locally  (put requirements.txt in uploads folder)
def create_python_sbom():
    # Path to the requirements.txt file in the 'uploads' folder
    requirements_path = './uploads/requirements.txt'
    
    # Path to the vulnerabilities JSON file in the 'uploads' folder
    vulnerabilities_path = './uploads/audit.json'
    
    # Path to the output JSON file
    output_file_path = './uploads/python-sbom.json'
    
    # Fetch vulnerabilities (this will generate 'uploads/audit.json')
    fetch_vulnerabilities(requirements_path)

    # Parse requirements and update vulnerabilities
    output = parse_requirements(requirements_path)
    update_vulnerabilities(output, vulnerabilities_path)

    write_to_file(output, output_file_path)

    return jsonify({"message": "Parsed data written to python-sbom file."})



#use for postman
@routes.route('/python/pip-parser', methods=['POST']) #you can use this route in postman
def pip_parser():
    try:
        if 'requirements_file' not in request.files:
            return jsonify({"error": "'requirements_file' is required."})

        uploaded_requirements_file = request.files['requirements_file']

        if not uploaded_requirements_file.filename:
            return jsonify({"error": "File name cannot be empty."})

        requirements_path = f"uploads/{uploaded_requirements_file.filename}"
        uploaded_requirements_file.save(requirements_path)

        vulnerabilities_path = './uploads/audit.json'

        #this will generate /uploads/audit.json (temporarily)
        fetch_vulnerabilities(requirements_path)

        output = parse_requirements(requirements_path)
        update_vulnerabilities(output, vulnerabilities_path)


        json_string = json.dumps(output, sort_keys=False)
        
        os.remove(requirements_path) 
        os.remove(vulnerabilities_path)

        return jsonify(json_string)

    except Exception as e:
        return jsonify({"error": str(e)})

