import re
import subprocess
import json
import os

def parse_requirements(requirements_path):
    components = []

    with open(requirements_path, encoding='utf-16') as f:
        requirements_data = f.read()

    requirements_list = requirements_data.split('\n')

    for requirement in requirements_list:
        if not requirement or requirement.startswith("#"): #for comments
            continue

        # Split the requirement into name and version
        parts = re.split(r'[=<>!]+', requirement, 1)
        name = parts[0].strip()
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

    return components


#for testing within the environment
def write_to_file(output, output_file_path):
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        json.dump(output, output_file, indent=2, ensure_ascii=False)

        

def fetch_vulnerabilities(requirements_path):
    os.chdir('uploads')
    subprocess.run(["pip-audit", "-f", "json", "|", "python", "-m", "json.tool", ">", "audit.json"], shell=True)
    os.chdir('..')

def update_vulnerabilities(output, vulnerabilities_path):
    with open(vulnerabilities_path) as f:
        vulnerabilities_data = json.load(f)["dependencies"]

    for component in output:
        name = component["name"]
        matching_vulnerabilities = [v for v in vulnerabilities_data if v["name"] == name]

        for vulnerability in matching_vulnerabilities:
            if vulnerability.get("vulns"):
                vulnerability_info = {
                    "id": vulnerability["vulns"][0]["id"],
                    "fix_versions": vulnerability["vulns"][0]["fix_versions"],
                    "description": vulnerability["vulns"][0]["description"]
                }

                component["vulnerabilities"].append(vulnerability_info)


