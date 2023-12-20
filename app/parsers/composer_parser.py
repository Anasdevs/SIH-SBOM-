import json
import re
import chardet
import os
import requests
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
    print(purls)

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

# Function to parse composer.json file and fetch vulnerabilities
def parse_composer_json(composer_json_path):
    with open(composer_json_path, 'rb') as f:
        raw_data = f.read()
        encoding = chardet.detect(raw_data)['encoding']

    with open(composer_json_path, encoding=encoding) as f:
        composer_json_data = json.load(f)

    components = []

    def extract_first_version(version):
        # Extract the first version from the provided string
        match = re.search(r'(\d+\.\d+(\.\d+)*)', version)
        return match.group(1) if match else version

    def parse_dependencies(dependencies):
        parsed_deps = []

        for name, version in dependencies.items():
            name = name.lower()  # Convert to lowercase for consistency with pip
            api_version = extract_first_version(version)

            purl = f"pkg:composer/{name}@v{api_version}"

            component = {
                "type": "library",
                "name": name,
                "version": api_version,
                "purl": purl,
                "dependencies": [],
                "vulnerabilities": []
            }

            parsed_deps.append(component)

        return parsed_deps

    # Parse require dependencies
    require_deps = composer_json_data.get("require", {})
    components.extend(parse_dependencies(require_deps))

    # Parse require-dev dependencies
    require_dev_deps = composer_json_data.get("require-dev", {})
    components.extend(parse_dependencies(require_dev_deps))

    # Fetching vulnerabilities from OSS Index API
    purls = [f"pkg:composer/{component['name']}@v{component['version']}" for component in components]
    vulnerabilities_data = fetch_vulnerabilities(purls)

    if vulnerabilities_data:
        # Updating vulnerabilities in the components array
        update_vulnerabilities(components, vulnerabilities_data)

    # Adding the default object with dependencies
    default_object = {
        "type": "application",
        "name": composer_json_data.get("name", "unknown"),
        "version": composer_json_data.get("version", "0.0.0"),
        "purl": f"pkg:composer/{composer_json_data.get('name', 'unknown')}@v{composer_json_data.get('version', '0.0.0')}",
        "language": "php",
        "dependencies": components,
    }

    output = [default_object]

    return output

# Example usage:
# composer_json_path = './uploads/composer.json'
# output = parse_composer_json(composer_json_path)

# # For testing within the environment
# output_file_path = './uploads/composer-PARSED.json'
# with open(output_file_path, 'w', encoding='utf-8') as output_file:
#     json.dump(output, output_file, indent=2, ensure_ascii=False)
