#!/usr/bin/env python3
"""
Configuration Validation for LAN Reconnaissance Framework
=========================================================

Provides schema-based configuration validation to ensure
configuration files are correct before scan execution.

Features:
- JSON Schema validation
- Custom validators
- Default value injection
- Environment variable expansion
- Configuration migration

Usage:
    from config_validator import ConfigValidator
    
    validator = ConfigValidator()
    config = validator.validate_and_load('config.json')
"""

import os
import re
import json
import ipaddress
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime


class ValidationError(Exception):
    """Configuration validation error."""
    
    def __init__(self, message: str, path: str = "", value: Any = None):
        super().__init__(message)
        self.path = path
        self.value = value


class ConfigValidator:
    """
    Validates configuration against a schema.
    
    Supports:
    - Type checking
    - Required fields
    - Default values
    - Custom validators
    - Environment variable expansion
    """
    
    # Configuration schema
    SCHEMA = {
        "type": "object",
        "properties": {
            "target_network": {
                "type": "string",
                "description": "Target network in CIDR notation",
                "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$",
                "validator": "validate_cidr",
                "required": True
            },
            "router_ip": {
                "type": "string",
                "description": "Router IP address",
                "validator": "validate_ip",
                "required": True
            },
            "passive_duration": {
                "type": "integer",
                "description": "Duration for passive scanning in seconds",
                "min": 5,
                "max": 3600,
                "default": 30
            },
            "discovery_rate": {
                "type": "integer",
                "description": "Discovery rate in packets per second",
                "min": 10,
                "max": 10000,
                "default": 1000
            },
            "nuclei_severity": {
                "type": "string",
                "description": "Severity levels for Nuclei scanning",
                "pattern": r"^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$",
                "default": "critical,high,medium"
            },
            "parallel_execution": {
                "type": "boolean",
                "description": "Enable parallel phase execution",
                "default": True
            },
            "scan_timeout": {
                "type": "integer",
                "description": "Overall scan timeout in seconds",
                "min": 60,
                "max": 86400,
                "default": 600
            },
            "verbose": {
                "type": "boolean",
                "description": "Enable verbose logging",
                "default": False
            },
            "output_dir": {
                "type": "string",
                "description": "Output directory for results",
                "default": "/output"
            },
            "notifications": {
                "type": "object",
                "description": "Notification settings",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "default": False
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "default": "high"
                    },
                    "slack_webhook": {
                        "type": "string",
                        "description": "Slack webhook URL",
                        "pattern": r"^https://hooks\.slack\.com/.*$"
                    },
                    "discord_webhook": {
                        "type": "string",
                        "description": "Discord webhook URL",
                        "pattern": r"^https://discord\.com/api/webhooks/.*$"
                    },
                    "email": {
                        "type": "object",
                        "properties": {
                            "smtp_server": {"type": "string"},
                            "smtp_port": {"type": "integer", "default": 587},
                            "from": {"type": "string", "validator": "validate_email"},
                            "to": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                }
            },
            "phases": {
                "type": "object",
                "description": "Phase configuration",
                "properties": {
                    "passive": {"type": "boolean", "default": True},
                    "discovery": {"type": "boolean", "default": True},
                    "fingerprint": {"type": "boolean", "default": True},
                    "iot": {"type": "boolean", "default": True},
                    "nuclei": {"type": "boolean", "default": True},
                    "webshot": {"type": "boolean", "default": True},
                    "advanced_monitor": {"type": "boolean", "default": True},
                    "attack_surface": {"type": "boolean", "default": True},
                    "report": {"type": "boolean", "default": True}
                }
            },
            "targets": {
                "type": "object",
                "description": "Known device IPs",
                "properties": {
                    "chromecast_ip": {"type": "string", "validator": "validate_ip"},
                    "tv_ip": {"type": "string", "validator": "validate_ip"},
                    "printer_ip": {"type": "string", "validator": "validate_ip"},
                    "dlna_ips": {"type": "array", "items": {"type": "string"}}
                }
            },
            "retry": {
                "type": "object",
                "description": "Retry configuration",
                "properties": {
                    "max_retries": {"type": "integer", "min": 0, "max": 10, "default": 3},
                    "base_delay": {"type": "number", "min": 0.1, "max": 60, "default": 1.0},
                    "max_delay": {"type": "number", "min": 1, "max": 300, "default": 60.0}
                }
            }
        }
    }
    
    def __init__(self):
        """Initialize validator with custom validators."""
        self.custom_validators = {
            "validate_cidr": self._validate_cidr,
            "validate_ip": self._validate_ip,
            "validate_email": self._validate_email,
            "validate_port": self._validate_port
        }
        self.errors: List[ValidationError] = []
    
    def validate(self, config: Dict, schema: Optional[Dict] = None) -> bool:
        """
        Validate configuration against schema.
        
        Args:
            config: Configuration dictionary
            schema: Schema to validate against (default: SCHEMA)
            
        Returns:
            True if valid, False otherwise
        """
        self.errors = []
        schema = schema or self.SCHEMA
        
        self._validate_object(config, schema, "")
        
        return len(self.errors) == 0
    
    def _validate_object(self, obj: Dict, schema: Dict, path: str):
        """Validate an object against schema."""
        properties = schema.get("properties", {})
        
        # Check for unknown keys
        for key in obj:
            if key not in properties:
                # Allow additional properties by default
                pass
        
        # Validate each property
        for prop_name, prop_schema in properties.items():
            prop_path = f"{path}.{prop_name}" if path else prop_name
            
            if prop_name in obj:
                value = obj[prop_name]
                self._validate_value(value, prop_schema, prop_path)
            elif prop_schema.get("required"):
                self.errors.append(
                    ValidationError(f"Required field missing", prop_path)
                )
    
    def _validate_value(self, value: Any, schema: Dict, path: str):
        """Validate a value against its schema."""
        expected_type = schema.get("type")
        
        # Type checking
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict
        }
        
        if expected_type and expected_type in type_map:
            expected_python_type = type_map[expected_type]
            if not isinstance(value, expected_python_type):
                self.errors.append(
                    ValidationError(
                        f"Expected {expected_type}, got {type(value).__name__}",
                        path, value
                    )
                )
                return
        
        # String pattern validation
        if expected_type == "string" and "pattern" in schema:
            if not re.match(schema["pattern"], str(value)):
                self.errors.append(
                    ValidationError(
                        f"Value does not match pattern: {schema['pattern']}",
                        path, value
                    )
                )
        
        # Enum validation
        if "enum" in schema and value not in schema["enum"]:
            self.errors.append(
                ValidationError(
                    f"Value must be one of: {schema['enum']}",
                    path, value
                )
            )
        
        # Min/max validation for numbers
        if expected_type in ("integer", "number"):
            if "min" in schema and value < schema["min"]:
                self.errors.append(
                    ValidationError(
                        f"Value must be >= {schema['min']}",
                        path, value
                    )
                )
            if "max" in schema and value > schema["max"]:
                self.errors.append(
                    ValidationError(
                        f"Value must be <= {schema['max']}",
                        path, value
                    )
                )
        
        # Custom validator
        if "validator" in schema:
            validator_name = schema["validator"]
            if validator_name in self.custom_validators:
                try:
                    self.custom_validators[validator_name](value)
                except ValidationError as e:
                    e.path = path
                    e.value = value
                    self.errors.append(e)
        
        # Nested object validation
        if expected_type == "object" and isinstance(value, dict):
            self._validate_object(value, schema, path)
        
        # Array item validation
        if expected_type == "array" and isinstance(value, list):
            item_schema = schema.get("items", {})
            for i, item in enumerate(value):
                self._validate_value(item, item_schema, f"{path}[{i}]")
    
    # Custom validators
    
    def _validate_cidr(self, value: str):
        """Validate CIDR notation."""
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR notation: {e}")
    
    def _validate_ip(self, value: str):
        """Validate IP address."""
        try:
            ipaddress.ip_address(value)
        except ValueError as e:
            raise ValidationError(f"Invalid IP address: {e}")
    
    def _validate_email(self, value: str):
        """Validate email address."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, value):
            raise ValidationError("Invalid email address format")
    
    def _validate_port(self, value: int):
        """Validate port number."""
        if not 1 <= value <= 65535:
            raise ValidationError("Port must be between 1 and 65535")
    
    # Utility methods
    
    def apply_defaults(self, config: Dict, schema: Optional[Dict] = None) -> Dict:
        """
        Apply default values from schema to configuration.
        
        Args:
            config: Configuration dictionary
            schema: Schema with defaults
            
        Returns:
            Configuration with defaults applied
        """
        schema = schema or self.SCHEMA
        return self._apply_defaults_recursive(config, schema)
    
    def _apply_defaults_recursive(self, config: Dict, schema: Dict) -> Dict:
        """Recursively apply defaults."""
        result = dict(config)
        properties = schema.get("properties", {})
        
        for prop_name, prop_schema in properties.items():
            if prop_name not in result and "default" in prop_schema:
                result[prop_name] = prop_schema["default"]
            elif prop_name in result and prop_schema.get("type") == "object":
                result[prop_name] = self._apply_defaults_recursive(
                    result[prop_name],
                    prop_schema
                )
        
        return result
    
    def expand_env_vars(self, config: Dict) -> Dict:
        """
        Expand environment variables in configuration.
        
        Supports ${VAR} and ${VAR:-default} syntax.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Configuration with environment variables expanded
        """
        return self._expand_env_recursive(config)
    
    def _expand_env_recursive(self, obj: Any) -> Any:
        """Recursively expand environment variables."""
        if isinstance(obj, str):
            # Match ${VAR} or ${VAR:-default}
            pattern = r'\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}'
            
            def replace(match):
                var_name = match.group(1)
                default = match.group(2)
                return os.getenv(var_name, default or "")
            
            return re.sub(pattern, replace, obj)
        elif isinstance(obj, dict):
            return {k: self._expand_env_recursive(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._expand_env_recursive(item) for item in obj]
        return obj
    
    def validate_and_load(
        self,
        config_path: Optional[str] = None,
        config_dict: Optional[Dict] = None
    ) -> Dict:
        """
        Validate and load configuration with all processing.
        
        Args:
            config_path: Path to configuration file
            config_dict: Configuration dictionary (alternative to file)
            
        Returns:
            Processed and validated configuration
            
        Raises:
            ValidationError: If configuration is invalid
        """
        # Load configuration
        if config_path:
            if not os.path.exists(config_path):
                raise ValidationError(f"Configuration file not found: {config_path}")
            
            with open(config_path) as f:
                config = json.load(f)
        elif config_dict:
            config = config_dict
        else:
            config = {}
        
        # Expand environment variables
        config = self.expand_env_vars(config)
        
        # Apply defaults
        config = self.apply_defaults(config)
        
        # Validate
        if not self.validate(config):
            error_msgs = [f"{e.path}: {e}" for e in self.errors]
            raise ValidationError(
                f"Configuration validation failed:\n" + "\n".join(error_msgs)
            )
        
        return config
    
    def get_errors(self) -> List[str]:
        """Get list of validation errors."""
        return [f"{e.path}: {str(e)}" for e in self.errors]
    
    def generate_example_config(self) -> Dict:
        """Generate example configuration from schema."""
        return self._generate_example(self.SCHEMA)
    
    def _generate_example(self, schema: Dict) -> Any:
        """Generate example value from schema."""
        if schema.get("type") == "object":
            result = {}
            for prop_name, prop_schema in schema.get("properties", {}).items():
                if "default" in prop_schema:
                    result[prop_name] = prop_schema["default"]
                elif "example" in prop_schema:
                    result[prop_name] = prop_schema["example"]
                elif prop_schema.get("type") == "object":
                    result[prop_name] = self._generate_example(prop_schema)
            return result
        elif "default" in schema:
            return schema["default"]
        elif "example" in schema:
            return schema["example"]
        return None


def load_config(config_path: Optional[str] = None) -> Dict:
    """
    Convenience function to load and validate configuration.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Validated configuration dictionary
    """
    validator = ConfigValidator()
    
    # Try loading from various sources
    config = {}
    
    # Load from file if provided
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
    
    # Override with environment variables
    env_mappings = {
        "TARGET_NETWORK": "target_network",
        "ROUTER_IP": "router_ip",
        "PASSIVE_DURATION": ("passive_duration", int),
        "DISCOVERY_RATE": ("discovery_rate", int),
        "NUCLEI_SEVERITY": "nuclei_severity",
        "PARALLEL_EXECUTION": ("parallel_execution", lambda x: x.lower() == "true"),
        "SCAN_TIMEOUT": ("scan_timeout", int),
        "VERBOSE": ("verbose", lambda x: x.lower() == "true")
    }
    
    for env_var, mapping in env_mappings.items():
        env_value = os.getenv(env_var)
        if env_value:
            if isinstance(mapping, tuple):
                config_key, converter = mapping
                config[config_key] = converter(env_value)
            else:
                config[mapping] = env_value
    
    return validator.validate_and_load(config_dict=config)


if __name__ == "__main__":
    # Demo usage
    print("Configuration Validator Demo")
    print("=" * 40)
    
    validator = ConfigValidator()
    
    # Generate example config
    example = validator.generate_example_config()
    print("Example configuration:")
    print(json.dumps(example, indent=2))
    
    # Validate a test config
    test_config = {
        "target_network": "192.168.1.0/24",
        "router_ip": "192.168.1.1",
        "passive_duration": 30
    }
    
    if validator.validate(test_config):
        print("\n✅ Configuration is valid")
        config = validator.apply_defaults(test_config)
        print(f"With defaults: {json.dumps(config, indent=2)}")
    else:
        print("\n❌ Configuration errors:")
        for error in validator.get_errors():
            print(f"  - {error}")
