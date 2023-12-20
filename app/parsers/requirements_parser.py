import re
import subprocess
import json
import os
import chardet


def parse_requirements(requirements_path):
    components = []

    with open(requirements_path, 'rb') as f:
        raw_data = f.read()
        encoding = chardet.detect(raw_data)['encoding']

    with open(requirements_path, encoding=encoding) as f:
        requirements_data = f.read()

    requirements_list = requirements_data.split('\n')

    for requirement in requirements_list:
        if not requirement or requirement.startswith("#"):  # for comments
            continue

        # Splitting the requirement into name and version
        parts = re.split(r'[=<>!]+', requirement, 1)
        # in some requirements files some libraries starting with capital letter and in pip audit all libraries are lowercase
        name = parts[0].strip().lower()
        version = parts[1].strip() if len(parts) > 1 else "unknown"

        purl = f"pkg:pypi/{name}@{version}"

        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "dependencies": [],
            "vulnerabilities": []
        }

        components.append(component)

    # Adding the default object with dependencies (may change in future)
    default_object = {
        "type": "application",
        "name": "python-backend",
        "version": "1.0.0",
        "purl": "pkg:pypi/python-backend@1.0.0",
        "language": "python",

        "dependencies": components,
    }
    components = [default_object]

    return components


# for testing within the environment
def write_to_file(output, output_file_path):
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        json.dump(output, output_file, indent=2, ensure_ascii=False)


def update_vulnerabilities(output, vulnerabilities_path):
    with open(vulnerabilities_path) as f:
        vulnerabilities_data = json.load(f)["dependencies"]

    for default_object in output:
        dependencies = default_object.get("dependencies", [])

        for component in dependencies:
            name = component["name"]
            matching_vulnerabilities = [
                v for v in vulnerabilities_data if v["name"] == name]

            # Clear existing vulnerabilities for the component
            component["vulnerabilities"] = []  # to prevent duplicate entries

            for vulnerability in matching_vulnerabilities:
                if vulnerability.get("vulns"):
                    for vuln in vulnerability["vulns"]:
                        vulnerability_info = {
                            "id": vuln["id"],
                            "fix_versions": vuln["fix_versions"],
                            "description": vuln["description"]
                        }

                        component["vulnerabilities"].append(vulnerability_info)




# def fetch_vulnerabilities(requirements_path):
#     # Get the absolute path to the requirements file
#     abs_requirements_path = os.path.abspath(requirements_path)

#     # Construct the absolute path for the 'audit.json' file in the 'uploads' folder
#     audit_json_path = os.path.join(os.getcwd(), 'uploads', 'audit.json')

#     try:

#         # Run pip-audit on the specified requirements.txt file and capture the output in audit.json
#         with open(audit_json_path, 'w') as audit_file:
#             result = subprocess.run(["pip-audit", "-f", "json", "-r", abs_requirements_path], stdout=audit_file, stderr=subprocess.PIPE)

#     except subprocess.CalledProcessError as e:
#         print(f"Error running pip-audit: {e}")


# for updating vulnerabilities array after we get audit.json