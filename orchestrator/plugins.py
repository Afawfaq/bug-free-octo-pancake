#!/usr/bin/env python3
"""
Plugin Architecture for LAN Reconnaissance Framework
=====================================================

Provides a modular plugin system that allows users to:
- Create custom scanning modules
- Register hooks for scan events
- Extend functionality without modifying core code

Usage:
    from plugins import PluginManager
    
    pm = PluginManager()
    pm.load_plugins('/path/to/plugins')
    pm.execute_hook('pre_scan', context)
"""

import os
import sys
import json
import importlib.util
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime


class PluginBase(ABC):
    """
    Base class for all plugins.
    
    All custom plugins must inherit from this class and implement
    the required methods.
    """
    
    # Plugin metadata - override in subclasses
    name: str = "BasePlugin"
    version: str = "1.0.0"
    description: str = "Base plugin class"
    author: str = "Unknown"
    
    # Plugin capabilities
    hooks: List[str] = []  # Events this plugin listens to
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize plugin with optional configuration."""
        self.config = config or {}
        self.enabled = True
        self.logger = None
    
    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the plugin. Called once when plugin is loaded.
        
        Returns:
            True if initialization successful, False otherwise.
        """
        pass
    
    @abstractmethod
    def execute(self, context: Dict) -> Dict:
        """
        Main execution method for the plugin.
        
        Args:
            context: Dictionary containing scan context and data
            
        Returns:
            Dictionary with plugin results
        """
        pass
    
    def cleanup(self):
        """Cleanup resources. Called when plugin is unloaded."""
        pass
    
    def get_info(self) -> Dict:
        """Return plugin metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "hooks": self.hooks,
            "enabled": self.enabled
        }


class ScannerPlugin(PluginBase):
    """Base class for scanner plugins that perform active scanning."""
    
    plugin_type = "scanner"
    
    @abstractmethod
    def scan(self, targets: List[str], options: Dict) -> Dict:
        """
        Perform scanning on targets.
        
        Args:
            targets: List of target IPs or hostnames
            options: Scanning options
            
        Returns:
            Scan results dictionary
        """
        pass


class AnalyzerPlugin(PluginBase):
    """Base class for analyzer plugins that process scan results."""
    
    plugin_type = "analyzer"
    
    @abstractmethod
    def analyze(self, data: Dict) -> Dict:
        """
        Analyze scan data.
        
        Args:
            data: Scan data to analyze
            
        Returns:
            Analysis results
        """
        pass


class ReporterPlugin(PluginBase):
    """Base class for reporter plugins that generate output."""
    
    plugin_type = "reporter"
    
    @abstractmethod
    def generate_report(self, data: Dict, output_path: str) -> str:
        """
        Generate a report from scan data.
        
        Args:
            data: Scan data to report on
            output_path: Path to write report
            
        Returns:
            Path to generated report
        """
        pass


class PluginManager:
    """
    Manages plugin lifecycle and execution.
    
    Handles:
    - Plugin discovery and loading
    - Hook registration and execution
    - Plugin configuration
    - Error handling
    """
    
    # Available hook points in the scan lifecycle
    HOOKS = [
        "pre_scan",           # Before scan starts
        "post_discovery",     # After host discovery
        "post_fingerprint",   # After service fingerprinting
        "post_vuln_scan",     # After vulnerability scanning
        "post_scan",          # After scan completes
        "on_finding",         # When a finding is detected
        "on_error",           # When an error occurs
        "pre_report",         # Before report generation
        "post_report"         # After report generation
    ]
    
    def __init__(self, plugin_dir: Optional[str] = None):
        """
        Initialize the plugin manager.
        
        Args:
            plugin_dir: Directory containing plugins
        """
        self.plugins: Dict[str, PluginBase] = {}
        self.hooks: Dict[str, List[Callable]] = {hook: [] for hook in self.HOOKS}
        self.plugin_dir = plugin_dir or os.path.join(os.path.dirname(__file__), "plugins")
        self.config: Dict = {}
    
    def load_plugins(self, plugin_dir: Optional[str] = None) -> int:
        """
        Load all plugins from a directory.
        
        Args:
            plugin_dir: Directory to load plugins from
            
        Returns:
            Number of plugins loaded
        """
        plugin_dir = plugin_dir or self.plugin_dir
        
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir, exist_ok=True)
            return 0
        
        loaded = 0
        for filename in os.listdir(plugin_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                plugin_path = os.path.join(plugin_dir, filename)
                if self.load_plugin(plugin_path):
                    loaded += 1
        
        return loaded
    
    def load_plugin(self, plugin_path: str) -> bool:
        """
        Load a single plugin from a file.
        
        Args:
            plugin_path: Path to plugin file
            
        Returns:
            True if plugin loaded successfully
        """
        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(
                os.path.basename(plugin_path)[:-3],
                plugin_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes in module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, PluginBase) and 
                    attr is not PluginBase and
                    attr is not ScannerPlugin and
                    attr is not AnalyzerPlugin and
                    attr is not ReporterPlugin):
                    
                    # Instantiate plugin
                    plugin = attr(self.config.get(attr.name, {}))
                    
                    if plugin.initialize():
                        self.plugins[plugin.name] = plugin
                        self._register_hooks(plugin)
                        print(f"[+] Loaded plugin: {plugin.name} v{plugin.version}")
                        return True
            
            return False
            
        except Exception as e:
            print(f"[-] Failed to load plugin {plugin_path}: {e}")
            return False
    
    def _register_hooks(self, plugin: PluginBase):
        """Register plugin's hooks."""
        for hook in plugin.hooks:
            if hook in self.hooks:
                self.hooks[hook].append(plugin.execute)
    
    def execute_hook(self, hook_name: str, context: Dict) -> List[Dict]:
        """
        Execute all plugins registered for a hook.
        
        Args:
            hook_name: Name of the hook to execute
            context: Context data to pass to plugins
            
        Returns:
            List of results from all plugins
        """
        if hook_name not in self.hooks:
            return []
        
        results = []
        for handler in self.hooks[hook_name]:
            try:
                result = handler(context)
                if result:
                    results.append(result)
            except Exception as e:
                print(f"[-] Plugin hook error: {e}")
                # Execute error handlers
                if hook_name != "on_error":
                    self.execute_hook("on_error", {
                        "error": str(e),
                        "hook": hook_name,
                        "context": context
                    })
        
        return results
    
    def get_plugin(self, name: str) -> Optional[PluginBase]:
        """Get a plugin by name."""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict]:
        """List all loaded plugins."""
        return [plugin.get_info() for plugin in self.plugins.values()]
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = True
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = False
            return True
        return False
    
    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin."""
        if name in self.plugins:
            plugin = self.plugins[name]
            plugin.cleanup()
            
            # Remove from hooks
            for hook in plugin.hooks:
                if hook in self.hooks:
                    self.hooks[hook] = [
                        h for h in self.hooks[hook] 
                        if h != plugin.execute
                    ]
            
            del self.plugins[name]
            return True
        return False
    
    def set_config(self, config: Dict):
        """Set plugin configuration."""
        self.config = config
    
    def cleanup(self):
        """Cleanup all plugins."""
        for plugin in self.plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                print(f"[-] Plugin cleanup error: {e}")


# Example plugin template
PLUGIN_TEMPLATE = '''#!/usr/bin/env python3
"""
Custom Plugin Template
======================

This is a template for creating custom plugins.
"""

from plugins import PluginBase


class MyCustomPlugin(PluginBase):
    """Example custom plugin."""
    
    name = "MyCustomPlugin"
    version = "1.0.0"
    description = "A custom plugin example"
    author = "Your Name"
    hooks = ["post_discovery"]  # Events to listen to
    
    def initialize(self) -> bool:
        """Initialize the plugin."""
        print(f"[*] {self.name} initialized")
        return True
    
    def execute(self, context: dict) -> dict:
        """Execute plugin logic."""
        # Your custom logic here
        results = {
            "plugin": self.name,
            "status": "success",
            "data": {}
        }
        return results
    
    def cleanup(self):
        """Cleanup resources."""
        pass
'''


def create_plugin_template(output_path: str) -> str:
    """
    Create a plugin template file.
    
    Args:
        output_path: Path to write template
        
    Returns:
        Path to created template
    """
    with open(output_path, 'w') as f:
        f.write(PLUGIN_TEMPLATE)
    return output_path


if __name__ == "__main__":
    # Demo usage
    pm = PluginManager()
    
    print("Plugin Manager Demo")
    print("=" * 40)
    print(f"Available hooks: {pm.HOOKS}")
    print(f"Plugin directory: {pm.plugin_dir}")
    
    # Load plugins
    count = pm.load_plugins()
    print(f"Loaded {count} plugins")
    
    # List plugins
    plugins = pm.list_plugins()
    print(f"Active plugins: {plugins}")
