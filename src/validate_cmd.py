from jsonschema import validate

from utils import logger


def validate_software(instance: dict) -> bool:
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
                "required": ["distro"],
            },
            "software": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "enum": ["github", "tarball"]}
                },
                "required": ["source"],
                "allOf": [
                    {
                        "if": {
                            "properties": {"source": {"const": "github"}},
                        },
                        "then": {
                            "properties": {
                                "user": {"type": "string"},
                                "repo": {"type": "string"},
                            },
                            "required": ["user", "repo"],
                        },
                    },
                    {
                        "if": {
                            "properties": {"source": {"const": "tarball"}},
                        },
                        "then": {
                            "properties": {
                                "packages": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "url": {"type": "string", "format": "uri"},
                                            "version": {"type": "string"},
                                        },
                                        "required": ["url"],
                                        "additionalProperties": False,
                                    },
                                },
                            },
                            "required": ["packages"],
                        },
                    },
                ],
            },
            "build": {"type": "string"},
        },
        "required": ["schema_version", "name", "software", "build"],
    }
    try:
        validate(instance, schema)
        return True
    except Exception as e:
        logger.warning(e.message)
        return False


def validate_vuln(instance: dict) -> bool:
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

    try:
        validate(instance, schema)
        return True
    except Exception as e:
        logger.warning(e.message)
        return False
