from jsonschema import validate


def validate_software(instance):
    schema = {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string"},
            "name": {"type": "string"},
            "environment": {
                "type": "object",
                "properties": {
                    "distro": {
                        "type": "string",
                        "enum": ["ubuntu", "debian", "fedora", "arch"],
                    },
                    "dependencies": {"type": "array"},
                },
            },
            "software": {
                "type": "object",
                "properties": {"source": {"type": "string"}},
                "allOf": [
                    {
                        "if": {"properties": {"source": {"const": "github"}},
                               "required": ["source"]
                               },
                        "then": {
                            "properties": {
                                "user": {"type": "string"},
                                "repo": {"type": "string"},
                            },
                            "required": ["user", "repo"]
                        },
                    },
                    {
                        "if": {"properties": {"source": {"const": "tarball"}},
                               "required": ["source"]
                               },
                        "then": {
                            "properties": {"url": {"type": "string", "format": "uri"}},
                            "required": ["url"]
                        },
                    },
                ],
            },
            "build": {"type": "string"},
        },
        "required": ["schema_version", "name", "software"],
    }

    validate(instance, schema)


def validate_vuln(instance):
    schema = {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string"},
            "id": {"type": "string"},
            "category": {"type": "string"},
            "version": {"type": "string"},
            "build": {"type": "string"},
            "trigger": {
                "type": "object",
                "properties": {
                    "poc": {"type": "string", "format": "uri"},
                    "guide": {"type": "string"},
                    "config": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["poc", "guide"],
            },
        },
        "required": ["schema_version", "id", "category", "trigger"],
    }

    validate(instance, schema)
