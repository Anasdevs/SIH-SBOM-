class UniversalSBOM:
    def __init__(self, metadata, components):
        self.bom_format = "UniversalSBOM-1.0"
        self.spec_version = "1.0"
        self.metadata = metadata
        self.components = components

    def to_dict(self):
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "metadata": self.metadata,
            "components": [component.to_dict() for component in self.components],
        }


class Component:
    def __init__(self, component_type, name, version, purl, dependencies=None):
        self.type = component_type
        self.name = name
        self.version = version
        self.purl = purl
        self.dependencies = dependencies or []

    def to_dict(self):
        return {
            "type": self.type,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "dependencies": [dep.to_dict() for dep in self.dependencies],
        }

# Example Usage
metadata = {
    "tools": [],
    "authors": [],
    "componentCounts": {
        "total": 15,
        "languages": ["js"],
    },
}

components = [
    Component(
        "application",
        "My App",
        "1.0.0",
        "pkg:npm/my-app@1.0.0",
        dependencies=[
            Component(
                "library",
                "express",
                "4.17.1",
                "pkg:npm/express@4.17.1",
                dependencies=[
                    Component(
                        "library",
                        "dep-1",
                        "1.0.0",
                        "pkg:npm/dep-1@1.0.0",
                        dependencies=[
                            Component(
                                "library",
                                "nested-dep-1",
                                "2.0.0",
                                "pkg:npm/nested-dep-1@2.0.0",
                            ),
                        ],
                    ),
                ],
            ),
            Component(
                "library",
                "react",
                "17.0.2",
                "pkg:npm/react@17.0.2",
                dependencies=[
                    Component(
                        "library",
                        "dep-2",
                        "3.0.0",
                        "pkg:npm/dep-2@3.0.0",
                        dependencies=[
                            Component(
                                "library",
                                "nested-dep-2",
                                "4.0.0",
                                "pkg:npm/nested-dep-2@4.0.0",
                            ),
                            Component(
                                "library",
                                "nested-dep-3",
                                "5.0.0",
                                "pkg:npm/nested-dep-3@5.0.0",
                            ),
                        ],
                    ),
                ],
            ),
            Component(
                "library",
                "library-3",
                "6.0.0",
                "pkg:npm/library-3@6.0.0",
                dependencies=[
                    Component(
                        "library",
                        "dep-3",
                        "7.0.0",
                        "pkg:npm/dep-3@7.0.0",
                        dependencies=[
                            Component(
                                "library",
                                "nested-dep-4",
                                "8.0.0",
                                "pkg:npm/nested-dep-4@8.0.0",
                            ),
                        ],
                    ),
                ],
            ),
        ],
    ),
]

# Create an instance of UniversalSBOM
sbom_instance = UniversalSBOM(metadata, components)

# Now sbom_instance represents the SBOM in the required format
