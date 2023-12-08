from flask import render_template, url_for, redirect, jsonify
from app import app
from app.parsers.package_lock_parser import parse_package_lock
import os 

@app.route('/')
def index():
    package_lock_path = os.path.join(os.path.dirname(__file__), '..', 'package-lock.json')
    sbom_data = parse_package_lock(package_lock_path)
    sbom_dict = sbom_data.to_dict()

    # Use 'jsonify' to ensure proper JSON response
    return jsonify(sbom_dict)