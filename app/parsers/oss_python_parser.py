import requests
import json
import os
import chardet
import re
from dotenv import load_dotenv

load_dotenv()

# Function to fetch vulnerabilities from OSS Index API
def fetch_vulnerabilities(purls):
    url = "https://ossindex.sonatype.org/api/v3/authorized/component-report"

    headers = {
        "Content-Type": "application/vnd.ossindex.component-report-request.v1+json"
    }

    username = os.getenv("OSS_INDEX_USERNAME")
    password = os.getenv("OSS_INDEX_PASSWORD")

    auth = (username, password)

    data = {"coordinates": purls}

    response = requests.post(url, headers=headers, auth=auth, json=data)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching vulnerabilities: {response.status_code}")
        return None

# Function to update vulnerabilities in the components array
def update_vulnerabilities(components, vulnerabilities_data):
    for component in components:
        component_purl = component["purl"]
        for vulnerability_info in vulnerabilities_data:
            vulnerability_coordinates = vulnerability_info.get("coordinates", "")
            if component_purl.lower() == vulnerability_coordinates.lower():
                vulnerabilities = vulnerability_info.get("vulnerabilities", [])
                for vulnerability in vulnerabilities:
                    component["vulnerabilities"].append({
                        "id": vulnerability.get("id"),
                        "title": vulnerability.get("title"),
                        "description": vulnerability.get("description"),
                        "cvss_score": vulnerability.get("cvssScore")
                    })

# Function to parse requirements and fetch vulnerabilities
def parse_requirements(requirements_path):
    components = []

    # Read and detect encoding of the requirements file
    with open(requirements_path, 'rb') as f:
        raw_data = f.read()
        encoding = chardet.detect(raw_data)['encoding']

    # Parse requirements file
    with open(requirements_path, encoding=encoding) as f:
        requirements_data = f.read()

    requirements_list = requirements_data.split('\n')

    purls = []

    # Extract components and create purls
    for requirement in requirements_list:
        if not requirement or requirement.startswith("#"):  # for comments
            continue

        # Splitting the requirement into name and version
        parts = re.split(r'[=<>!]+', requirement, 1)
        name = parts[0].strip().lower()
        version = parts[1].strip() if len(parts) > 1 else "unknown"

        purl = f"pkg:pypi/{name}@{version}"
        purls.append(purl)

        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "dependencies": [],
            "vulnerabilities": []
        }

        components.append(component)

    # Fetching vulnerabilities from OSS Index API
    vulnerabilities_data = fetch_vulnerabilities(purls)

    if vulnerabilities_data:
        # Updating vulnerabilities in the components array
        update_vulnerabilities(components, vulnerabilities_data)

    # Adding the default object with dependencies (may change in future)
    default_object = {
        "type": "application",
        "name": "python-backend",
        "version": "1.0.0",
        "purl": "pkg:pypi/python-backend@1.0.0",
        "dependencies": components,
    }
    components = [default_object]

    return components
