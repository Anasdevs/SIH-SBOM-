# app/routes.py

from flask import Blueprint, jsonify, request, json, Response
from app.parsers.package_lock_parser import parse_package_lock, write_to_file
import os

routes = Blueprint('routes', __name__)

@routes.route('/')
def create_js_sbom():
    package_lock_path = "./package-lock.json"
    output = parse_package_lock(package_lock_path)

    output_file_path = 'js-sbom.json'
    write_to_file(output, output_file_path)

    return jsonify({"message": "Parsed data written to js-sbom.json file."})

@routes.route('/js/npm-parser', methods=['POST'])
def npm_parser():
    try:
        uploaded_file = request.files['package_lock']
        if uploaded_file.filename != '':
            file_path = f"uploads/{uploaded_file.filename}"
            uploaded_file.save(file_path)

            parsed_data = parse_package_lock(file_path)

            parsed_data_str = str(parsed_data)

            os.remove(file_path)
            return Response(parsed_data_str, content_type='text/plain')
    except Exception as e:
        return jsonify({"error": str(e)})