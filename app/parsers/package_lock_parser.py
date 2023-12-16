import json 

def parse_package_lock(package_lock_path, package_audit_path, obj=False):

    components = []

    with open(package_lock_path) as f:
        pkg_json = json.load(f)  
    if obj == False:
        with open(package_audit_path) as f:
            vulnerabilities_data = json.load(f)["vulnerabilities"]
    else:
        vulnerabilities_data = package_audit_path['vulnerabilities']

    application = {
        "type": "application",
        "name": pkg_json["name"],
        "version": pkg_json["version"],
        "purl": f"pkg:npm/{pkg_json['name']}@{pkg_json['version']}",
        "dependencies": [],
    }
    components.append(application)

    def add_component(name, version, purl, dependencies=[]):
        component = {
            "type": "library", 
            "name": name,
            "version": version,
            "purl": purl,
            "dependencies": dependencies,
            "vulnerabilities": [],   
        }
        return component

    def add_vulnerabilities(component, vulnerabilities_data):

        component_name = component["name"]

        if component_name in vulnerabilities_data:

           vulnerability_info = vulnerabilities_data[component_name]

           vulnerability = {
               "name": vulnerability_info["name"],
               "severity": vulnerability_info["severity"],
               "via": vulnerability_info["via"],
               "effects": vulnerability_info["effects"]  
           }

           component["vulnerabilities"].append(vulnerability)

    def process_deps(deps, parent):
        if not deps:
            return
        for name, dep_info in deps.items():
            version = "unknown"
            if isinstance(dep_info, str):
                version = dep_info
            else:
                version = dep_info.get("version")
            if not version:
                version = "unknown"
            if not name:
                purl = f"pkg:npm/{parent['name']}@{version}"
                child_component = add_component(name, version, purl, [])
                if parent:
                    parent["dependencies"].append(child_component)
                    add_vulnerabilities(child_component, vulnerabilities_data)
            else:
                purl = f"pkg:npm/{name}@{version}"
                child_component = add_component(name, version, purl, [])
                if parent:
                    parent["dependencies"].append(child_component)
                    add_vulnerabilities(child_component, vulnerabilities_data)
            if isinstance(dep_info, str):
                process_deps(False, child_component)
            else:
                process_deps(dep_info.get("dependencies"), child_component)

    process_deps(pkg_json.get("packages"), application)

    return components

def write_to_file(output, output_file_path):
    with open(output_file_path, 'w') as output_file:

        json.dump(output, output_file, indent=2)
