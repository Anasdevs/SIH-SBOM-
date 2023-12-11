# app/parsers/package_parser.py

import json

def parse_package_lock(package_lock_path):
    components = []

    with open(package_lock_path) as f:
        pkg_json = json.load(f)

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
        }
        return component

    def process_deps(deps, parent):
        if not deps:
            return
        for name in deps.keys():
            version = "unknown"
            if isinstance(deps[name], str):
                version = deps[name]
            else:
                version = deps[name].get("version")
            if not version:
                version = "unknown"
            if not name:
                purl = f"pkg:npm/{parent['name']}@{version}"
                childComponent = add_component(name, version, purl, [])
                if parent:
                    parent["dependencies"].append(childComponent)
            else:
                purl = f"pkg:npm/{name}@{version}"
                childComponent = add_component(name, version, purl, [])
                if parent:
                    parent["dependencies"].append(childComponent)
            if isinstance(deps[name], str):
                process_deps(False, childComponent)
            else:
                process_deps(deps[name].get("dependencies"), childComponent)

    process_deps(pkg_json.get("packages"), application)

    return components

def write_to_file(output, output_file_path):
    with open(output_file_path, 'w') as output_file:
        json.dump(output, output_file, indent=2)
