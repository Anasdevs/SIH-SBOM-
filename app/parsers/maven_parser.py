import os
import xmltodict
import json
import requests
from flask import Flask, jsonify, request
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

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

# Function to parse the pom.xml and fetch vulnerabilities
def parse_pom_and_fetch_vulnerabilities(xml_data):
    # Convert XML to dictionary
    pom_data = xmltodict.parse(xml_data)

    project_name = pom_data["project"].get("name", "")
    project_groupId = pom_data["project"].get("groupId", "")
    project_artifactId = pom_data["project"].get("artifactId", "")
    project_version = pom_data["project"].get("version", "")
    project_purl = f"pkg:maven/{project_groupId}/{project_artifactId}@{project_version}"

    # Extracting dependencies from the pom.xml
    dependencies = pom_data["project"].get("dependencies", {}).get("dependency", [])

    components = []

    # Handle the case where dependencies is not a list
    if not isinstance(dependencies, list):
        dependencies = [dependencies]

    # Iterating through dependencies to create components
    for dependency in dependencies:
        # Accessing nested keys using get
        group_id = dependency.get("groupId", "")
        artifact_id = dependency.get("artifactId", "")
        version = dependency.get("version", "")

        component_purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
        component = {
            "type": "library",
            "name": artifact_id,
            "version": version,
            "purl": component_purl,
            "dependencies": [],
            "vulnerabilities": []
        }
        components.append(component)

    # Fetching vulnerabilities from OSS Index API and updating vulnerabilities
    purls = [component["purl"] for component in components]

    vulnerabilities_data = fetch_vulnerabilities(purls)
    if vulnerabilities_data:
        update_vulnerabilities(components, vulnerabilities_data)

    # Constructing the transformed project_info
    project_info = {
        "type": "application",
        "name": project_name,
        "version": project_version,
        "purl": project_purl,
        "language": "java",
        "dependencies": components
    }

    return project_info