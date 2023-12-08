
import json
from sbom import UniversalSBOM, Component

def parse_package_lock(package_lock_path):
    with open(package_lock_path, 'r') as f:
        package_data = json.load(f)

    def parse_deps(dep_data):
        components = []
        for dep_name, dep_info in dep_data.items():
            if isinstance(dep_info, (str, int)):
                # Handle case where dependency is a string or int (no nested dependencies)
                version = str(dep_info)
                dependencies = []
            else:
                # Use get method to provide a default value for version
                version = str(dep_info.get('version', 'Unknown'))
                dependencies = parse_deps(dep_info.get('dependencies', {}))

            c = Component(
                component_type="library",
                name=dep_name,
                version=version,
                purl=f"pkg:npm/{dep_name}@{version}",
                dependencies=dependencies
            )
            components.append(c)
        return components

    metadata = {
        "tools": [],
        "authors": [],
        "componentCounts": {
            "total": 0,
            "languages": ["js"]
        }
    }

    app_component = Component(
        component_type="application",
        name="My App",
        version=package_data.get('version', 'Unknown'),
        purl=f"pkg:npm/my-app@{package_data.get('version', 'Unknown')}",
        dependencies=parse_deps(package_data.get('packages', {}))
    )

    components = [app_component]

    sbom = UniversalSBOM(
        metadata=metadata,
        components=components
    )

    return sbom
