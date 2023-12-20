import toml
import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

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

def parse_cargo_lock(lockfile_path):
    with open(lockfile_path, 'r') as f:
        lockfile_data = toml.load(f)

    # Extracting the package list from the Cargo.lock file
    packages = lockfile_data.get('package', [])

    components = []

    for package in packages:
        name = package.get('name', '')
        version = package.get('version', '')
        checksum = package.get('checksum', '')

        purl = f"pkg:cargo/{name}@{version}"

        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "dependencies": [],
            "vulnerabilities": []
        }

        # If there are dependencies, process them
        dependencies = package.get('dependencies', [])
        if dependencies:
            component["dependencies"] = parse_dependencies(dependencies)

        components.append(component)

    # Fetching vulnerabilities from OSS Index API
    purls = [f"pkg:cargo/{component['name']}@{component['version']}" for component in components]
    vulnerabilities_data = fetch_vulnerabilities(purls)

    if vulnerabilities_data:
        # Updating vulnerabilities in the components array
        update_vulnerabilities(components, vulnerabilities_data)

    # Adding the default object with dependencies
    default_object = {
        "type": "application",
        "name": "rust-application",  # You can customize this
        "version": "0.0.0",  # You can customize this
        "purl": "pkg:cargo/rust-application@v0.0.0",  # You can customize this
        "language": "rust",
        "dependencies": components,
    }

    output = [default_object]

    return output



def parse_dependencies(dependencies):
    parsed_deps = []

    if isinstance(dependencies, list):
        # If dependencies is already a list, use it as is
        dep_list = dependencies
    elif isinstance(dependencies, str):
        # If dependencies is a string, treat it as a single-element list
        dep_list = [dependencies]
    else:
        # If it's neither a list nor a string, treat it as an empty list
        dep_list = []

    for dep in dep_list:
        if isinstance(dep, dict):
            # If dep is a dictionary, extract name and version
            name = dep.get('name', '')
            version = dep.get('version', '')
        else:
            # If dep is a string, use it as the name directly
            name = dep
            version = ''

        purl = f"pkg:cargo/{name}@{version}"

        parsed_dep = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "dependencies": [],
            "vulnerabilities": []
        }

        parsed_deps.append(parsed_dep)

    return parsed_deps




if __name__ == "__main__":
    # Example usage
    lockfile_path = "./uploads/Cargo.lock"  
    cargo_output = parse_cargo_lock(lockfile_path)

    # Output in JSON format
    json_output = json.dumps(cargo_output, indent=2)
    print(json_output)
