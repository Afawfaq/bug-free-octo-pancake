"""
Unit tests for the Config Validator module.
"""

import os
import json
import pytest
import tempfile
from unittest.mock import patch


class TestValidationError:
    """Test ValidationError exception."""
    
    def test_validation_error_creation(self):
        """Test creating a ValidationError."""
        from config_validator import ValidationError
        
        error = ValidationError("Test message", path="config.key", value="bad_value")
        
        assert str(error) == "Test message"
        assert error.path == "config.key"
        assert error.value == "bad_value"


class TestConfigValidatorInitialization:
    """Test ConfigValidator initialization."""
    
    def test_default_initialization(self):
        """Test that validator initializes with default schema."""
        from config_validator import ConfigValidator
        
        validator = ConfigValidator()
        
        assert validator.SCHEMA is not None
        assert "properties" in validator.SCHEMA
        assert validator.errors == []
    
    def test_custom_validators_registered(self):
        """Test that custom validators are registered."""
        from config_validator import ConfigValidator
        
        validator = ConfigValidator()
        
        assert "validate_cidr" in validator.custom_validators
        assert "validate_ip" in validator.custom_validators
        assert "validate_email" in validator.custom_validators
        assert "validate_port" in validator.custom_validators


class TestTypeValidation:
    """Test type validation."""
    
    @pytest.fixture
    def validator(self):
        """Create a ConfigValidator instance."""
        from config_validator import ConfigValidator
        return ConfigValidator()
    
    def test_string_type_validation(self, validator):
        """Test string type validation."""
        config = {"target_network": "192.168.1.0/24", "router_ip": "192.168.1.1"}
        
        result = validator.validate(config)
        
        assert result == True
    
    def test_integer_type_validation(self, validator):
        """Test integer type validation."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "passive_duration": 60
        }
        
        result = validator.validate(config)
        
        assert result == True
    
    def test_boolean_type_validation(self, validator):
        """Test boolean type validation."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "parallel_execution": True,
            "verbose": False
        }
        
        result = validator.validate(config)
        
        assert result == True
    
    def test_wrong_type_validation(self, validator):
        """Test validation fails for wrong types."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "passive_duration": "not_an_integer"  # Should be integer
        }
        
        result = validator.validate(config)
        
        assert result == False
        assert len(validator.errors) > 0


class TestRangeValidation:
    """Test min/max range validation."""
    
    @pytest.fixture
    def validator(self):
        """Create a ConfigValidator instance."""
        from config_validator import ConfigValidator
        return ConfigValidator()
    
    def test_valid_range(self, validator):
        """Test value within valid range."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "passive_duration": 30  # Min: 5, Max: 3600
        }
        
        result = validator.validate(config)
        
        assert result == True
    
    def test_below_minimum(self, validator):
        """Test value below minimum."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "passive_duration": 1  # Min: 5
        }
        
        result = validator.validate(config)
        
        assert result == False
    
    def test_above_maximum(self, validator):
        """Test value above maximum."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "passive_duration": 10000  # Max: 3600
        }
        
        result = validator.validate(config)
        
        assert result == False


class TestCustomValidators:
    """Test custom validators."""
    
    @pytest.fixture
    def validator(self):
        """Create a ConfigValidator instance."""
        from config_validator import ConfigValidator
        return ConfigValidator()
    
    def test_validate_cidr_valid(self, validator):
        """Test valid CIDR notation."""
        from config_validator import ValidationError
        
        # Should not raise
        validator._validate_cidr("192.168.1.0/24")
        validator._validate_cidr("10.0.0.0/8")
        validator._validate_cidr("172.16.0.0/16")
    
    def test_validate_cidr_invalid(self, validator):
        """Test invalid CIDR notation."""
        from config_validator import ValidationError
        
        with pytest.raises(ValidationError):
            validator._validate_cidr("not_a_cidr")
        
        with pytest.raises(ValidationError):
            validator._validate_cidr("192.168.1.0/33")  # Invalid prefix
    
    def test_validate_ip_valid(self, validator):
        """Test valid IP addresses."""
        # Should not raise
        validator._validate_ip("192.168.1.1")
        validator._validate_ip("10.0.0.1")
        validator._validate_ip("255.255.255.255")
    
    def test_validate_ip_invalid(self, validator):
        """Test invalid IP addresses."""
        from config_validator import ValidationError
        
        with pytest.raises(ValidationError):
            validator._validate_ip("not_an_ip")
        
        with pytest.raises(ValidationError):
            validator._validate_ip("256.1.1.1")  # Invalid octet
    
    def test_validate_email_valid(self, validator):
        """Test valid email addresses."""
        # Should not raise
        validator._validate_email("test@example.com")
        validator._validate_email("user.name@domain.org")
    
    def test_validate_email_invalid(self, validator):
        """Test invalid email addresses."""
        from config_validator import ValidationError
        
        with pytest.raises(ValidationError):
            validator._validate_email("not_an_email")
        
        with pytest.raises(ValidationError):
            validator._validate_email("missing@tld")
    
    def test_validate_port_valid(self, validator):
        """Test valid port numbers."""
        # Should not raise
        validator._validate_port(80)
        validator._validate_port(443)
        validator._validate_port(65535)
        validator._validate_port(1)
    
    def test_validate_port_invalid(self, validator):
        """Test invalid port numbers."""
        from config_validator import ValidationError
        
        with pytest.raises(ValidationError):
            validator._validate_port(0)
        
        with pytest.raises(ValidationError):
            validator._validate_port(65536)


class TestDefaultValues:
    """Test default value application."""
    
    @pytest.fixture
    def validator(self):
        """Create a ConfigValidator instance."""
        from config_validator import ConfigValidator
        return ConfigValidator()
    
    def test_apply_defaults(self, validator):
        """Test applying default values."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1"
        }
        
        result = validator.apply_defaults(config)
        
        assert result["passive_duration"] == 30  # Default
        assert result["parallel_execution"] == True  # Default
        assert result["verbose"] == False  # Default
        assert result["output_dir"] == "/output"  # Default
    
    def test_defaults_not_override(self, validator):
        """Test that existing values are not overridden."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "passive_duration": 60
        }
        
        result = validator.apply_defaults(config)
        
        assert result["passive_duration"] == 60  # Preserved


class TestEnvironmentVariableExpansion:
    """Test environment variable expansion."""
    
    @pytest.fixture
    def validator(self):
        """Create a ConfigValidator instance."""
        from config_validator import ConfigValidator
        return ConfigValidator()
    
    def test_expand_env_vars(self, validator):
        """Test expanding environment variables."""
        with patch.dict(os.environ, {"TEST_VAR": "test_value"}):
            config = {"key": "${TEST_VAR}"}
            
            result = validator.expand_env_vars(config)
            
            assert result["key"] == "test_value"
    
    def test_expand_env_vars_with_default(self, validator):
        """Test expanding environment variables with defaults."""
        with patch.dict(os.environ, {}, clear=True):
            config = {"key": "${MISSING_VAR:-default_value}"}
            
            result = validator.expand_env_vars(config)
            
            assert result["key"] == "default_value"
    
    def test_expand_env_vars_nested(self, validator):
        """Test expanding environment variables in nested structures."""
        with patch.dict(os.environ, {"NESTED_VAR": "nested_value"}):
            config = {
                "outer": {
                    "inner": "${NESTED_VAR}"
                }
            }
            
            result = validator.expand_env_vars(config)
            
            assert result["outer"]["inner"] == "nested_value"
    
    def test_expand_env_vars_in_array(self, validator):
        """Test expanding environment variables in arrays."""
        with patch.dict(os.environ, {"ARRAY_VAR": "array_value"}):
            config = {
                "list": ["item1", "${ARRAY_VAR}", "item3"]
            }
            
            result = validator.expand_env_vars(config)
            
            assert result["list"][1] == "array_value"


class TestValidateAndLoad:
    """Test the validate_and_load method."""
    
    @pytest.fixture
    def validator(self):
        """Create a ConfigValidator instance."""
        from config_validator import ConfigValidator
        return ConfigValidator()
    
    def test_validate_and_load_dict(self, validator):
        """Test validating and loading from dictionary."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1"
        }
        
        result = validator.validate_and_load(config_dict=config)
        
        assert "target_network" in result
        assert "passive_duration" in result  # Default applied
    
    def test_validate_and_load_file(self, validator, tmp_path):
        """Test validating and loading from file."""
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1"
        }
        
        config_file = tmp_path / "config.json"
        with open(config_file, "w") as f:
            json.dump(config, f)
        
        result = validator.validate_and_load(config_path=str(config_file))
        
        assert result["target_network"] == "192.168.1.0/24"
    
    def test_validate_and_load_invalid_file(self, validator):
        """Test loading from non-existent file."""
        from config_validator import ValidationError
        
        with pytest.raises(ValidationError):
            validator.validate_and_load(config_path="/nonexistent/path/config.json")


class TestGenerateExampleConfig:
    """Test example configuration generation."""
    
    def test_generate_example_config(self):
        """Test generating example configuration."""
        from config_validator import ConfigValidator
        
        validator = ConfigValidator()
        example = validator.generate_example_config()
        
        assert isinstance(example, dict)
        # Should have some default values
        assert "passive_duration" in example or "parallel_execution" in example


class TestLoadConfigFunction:
    """Test the load_config convenience function."""
    
    def test_load_config_with_env_vars(self):
        """Test loading config with environment variables."""
        env = {
            "TARGET_NETWORK": "10.0.0.0/24",
            "ROUTER_IP": "10.0.0.1",
            "PASSIVE_DURATION": "60",
            "PARALLEL_EXECUTION": "false",
            "VERBOSE": "true"
        }
        
        with patch.dict(os.environ, env, clear=True):
            from config_validator import load_config
            
            config = load_config()
            
            assert config["target_network"] == "10.0.0.0/24"
            assert config["router_ip"] == "10.0.0.1"
            assert config["passive_duration"] == 60
            assert config["parallel_execution"] == False
            assert config["verbose"] == True


class TestGetErrors:
    """Test error retrieval."""
    
    def test_get_errors(self):
        """Test getting validation errors."""
        from config_validator import ConfigValidator
        
        validator = ConfigValidator()
        
        # Invalid config to generate errors
        config = {
            "target_network": "192.168.1.0/24",
            "router_ip": "192.168.1.1",
            "passive_duration": "not_an_integer"
        }
        
        validator.validate(config)
        errors = validator.get_errors()
        
        assert len(errors) > 0
        assert all(isinstance(e, str) for e in errors)
