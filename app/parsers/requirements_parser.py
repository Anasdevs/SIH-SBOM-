import re
import subprocess
import json
import os
import chardet 
import sys

try:
    print(sys.executable)
    import pip_audit
    subprocess.run(["pip-audit", "--version"])

except Exception as e:
    print(f"pip-audit error: {e}")

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
        #in some requirements files some libraries starting with capital letter and in pip audit all libraries are lowercase
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
        "dependencies": components,
    }
    components = [default_object]

    return components



#for testing within the environment
def write_to_file(output, output_file_path):
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        json.dump(output, output_file, indent=2, ensure_ascii=False)

        

#it will run the pip-audit on requirements.txt 
def fetch_vulnerabilities(requirements_path):
    os.chdir('uploads')
    try:
        # Use subprocess.PIPE to capture the output for debugging
        result = subprocess.run(
            ["pip-audit", "-f", "json", "|", "python", "-m", "json.tool", ">", "audit.json"],
            shell=True,
            capture_output=True,
            text=True
        )
        
        # Print the result for debugging
        print("Subprocess result:", result)
        
        if result.returncode != 0:
            print("Error running pip-audit:", result.stderr)
        
    finally:
        os.chdir('..')


#for updating vulnerabilities array after we get audit.json
def update_vulnerabilities(output, vulnerabilities_path):
    with open(vulnerabilities_path) as f:
        vulnerabilities_data = json.load(f)["dependencies"]

    for default_object in output:
        dependencies = default_object.get("dependencies", [])

        for component in dependencies:
            name = component["name"]
            matching_vulnerabilities = [v for v in vulnerabilities_data if v["name"] == name]

            # Clear existing vulnerabilities for the component
            component["vulnerabilities"] = [] #to prevent duplicate entries

            for vulnerability in matching_vulnerabilities:
                if vulnerability.get("vulns"):
                    for vuln in vulnerability["vulns"]:
                        vulnerability_info = {
                            "id": vuln["id"],
                            "fix_versions": vuln["fix_versions"],
                            "description": vuln["description"]
                        }

                        component["vulnerabilities"].append(vulnerability_info)
