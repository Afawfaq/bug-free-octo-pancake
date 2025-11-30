"""
Pytest configuration and fixtures for LAN Reconnaissance Framework tests.
"""

import os
import sys

# Add orchestrator directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))
