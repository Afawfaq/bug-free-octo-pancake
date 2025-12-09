#!/usr/bin/env python3
"""
Adaptive Honeypot Module
Implements adaptive high-interaction honeypot concepts from research:
- HoneyIoT: Adaptive High-Interaction Honeypot for IoT Devices (arXiv 2023)
- Advancing Cybersecurity with Honeypots and Deception Strategies (MDPI 2024)

Features:
- Behavioral mimicry to appear more realistic
- Adaptive responses based on attacker behavior
- Attacker profiling and classification
- Anti-fingerprinting techniques
"""

import json
import time
import random
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict
import os


class AttackerProfile:
    """Profile of an attacker's behavior and capabilities."""
    
    def __init__(self, source_ip: str):
        self.source_ip = source_ip
        self.first_seen = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.actions = []
        self.techniques = set()
        self.skill_level = 'UNKNOWN'
        self.intent = 'RECONNAISSANCE'
        self.interaction_count = 0
        
    def add_action(self, action: Dict):
        """Record an attacker action."""
        self.last_seen = datetime.utcnow()
        self.actions.append(action)
        self.interaction_count += 1
        
        # Update techniques
        if 'technique' in action:
            self.techniques.add(action['technique'])
        
        # Classify skill level based on actions
        self._update_skill_level()
        self._update_intent()
    
    def _update_skill_level(self):
        """Classify attacker skill level based on behavior."""
        advanced_techniques = {
            'SQL_INJECTION', 'BUFFER_OVERFLOW', 'PRIVILEGE_ESCALATION',
            'LATERAL_MOVEMENT', 'CREDENTIAL_HARVESTING'
        }
        
        if len(self.techniques & advanced_techniques) >= 2:
            self.skill_level = 'ADVANCED'
        elif len(self.techniques) >= 3:
            self.skill_level = 'INTERMEDIATE'
        elif len(self.techniques) >= 1:
            self.skill_level = 'NOVICE'
        else:
            self.skill_level = 'SCANNER'
    
    def _update_intent(self):
        """Determine attacker intent from behavior patterns."""
        if self.interaction_count < 3:
            self.intent = 'RECONNAISSANCE'
        elif any('EXPLOIT' in t for t in self.techniques):
            self.intent = 'EXPLOITATION'
        elif any('HARVEST' in t or 'STEAL' in t for t in self.techniques):
            self.intent = 'DATA_THEFT'
        elif self.interaction_count > 10:
            self.intent = 'PERSISTENT_ACCESS'
    
    def to_dict(self) -> Dict:
        """Convert profile to dictionary."""
        return {
            'source_ip': self.source_ip,
            'first_seen': self.first_seen.isoformat() + 'Z',
            'last_seen': self.last_seen.isoformat() + 'Z',
            'interaction_count': self.interaction_count,
            'skill_level': self.skill_level,
            'intent': self.intent,
            'techniques': list(self.techniques),
            'action_count': len(self.actions)
        }


class AdaptiveHoneypot:
    """
    Adaptive honeypot that adjusts responses based on attacker behavior.
    Implements research-based deception strategies.
    """
    
    def __init__(self, service_type: str = 'web', realism_level: float = 0.8):
        self.service_type = service_type
        self.realism_level = realism_level  # 0.0 to 1.0
        self.attacker_profiles = {}
        self.interaction_log = []
        self.deception_strategies = self._initialize_strategies()
        
    def _initialize_strategies(self) -> Dict:
        """Initialize deception strategies based on service type."""
        strategies = {
            'web': {
                'response_delays': [0.1, 0.3, 0.5],  # Simulate real server processing
                'error_messages': [
                    'Database connection timeout',
                    'Internal server error',
                    'Access denied - insufficient privileges',
                ],
                'fake_directories': [
                    '/admin', '/backup', '/config', '/api/v1', '/uploads'
                ],
                'honeytokens': [
                    'admin:P@ssw0rd123',  # Fake credentials
                    'api_key=hpot_test_tracking_token_12345'  # Fake API key for tracking
                ]
            },
            'ssh': {
                'response_delays': [0.2, 0.5, 1.0],
                'banner_messages': [
                    'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
                    'SSH-2.0-OpenSSH_7.4',
                ],
                'fake_commands': ['ls', 'cat', 'cd', 'pwd', 'whoami'],
                'fake_files': ['/etc/passwd', '/var/log/auth.log', '~/.ssh/authorized_keys']
            },
            'smb': {
                'response_delays': [0.1, 0.2, 0.4],
                'shares': ['backup$', 'admin$', 'documents', 'finance'],
                'fake_files': ['passwords.txt', 'budget.xlsx', 'confidential.doc']
            }
        }
        
        return strategies.get(self.service_type, strategies['web'])
    
    def get_attacker_profile(self, source_ip: str) -> AttackerProfile:
        """Get or create attacker profile."""
        if source_ip not in self.attacker_profiles:
            self.attacker_profiles[source_ip] = AttackerProfile(source_ip)
        return self.attacker_profiles[source_ip]
    
    def handle_interaction(self, source_ip: str, action: Dict) -> Dict:
        """
        Handle attacker interaction with adaptive response.
        Returns response dictionary with deception elements.
        """
        profile = self.get_attacker_profile(source_ip)
        profile.add_action(action)
        
        # Log interaction
        interaction = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source_ip': source_ip,
            'action': action,
            'attacker_profile': profile.to_dict()
        }
        self.interaction_log.append(interaction)
        
        # Generate adaptive response
        response = self._generate_adaptive_response(profile, action)
        
        return response
    
    def _generate_adaptive_response(self, profile: AttackerProfile, action: Dict) -> Dict:
        """
        Generate response adapted to attacker skill level and intent.
        More sophisticated attackers get more realistic responses.
        """
        response = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'response_type': 'adaptive',
            'success': False  # Default to failure
        }
        
        # Add realistic delay based on skill level
        delay = self._calculate_response_delay(profile)
        time.sleep(delay)
        response['processing_time'] = delay
        
        # Adjust realism based on attacker skill
        if profile.skill_level == 'ADVANCED':
            # Advanced attackers get more realistic responses to keep them engaged
            response['realism'] = min(self.realism_level * 1.2, 1.0)
            response['success'] = random.random() < 0.3  # Occasionally succeed
        elif profile.skill_level == 'INTERMEDIATE':
            response['realism'] = self.realism_level
            response['success'] = random.random() < 0.1
        else:
            # Scanners get basic responses
            response['realism'] = self.realism_level * 0.8
            response['success'] = False
        
        # Add service-specific response elements
        if self.service_type == 'web':
            response.update(self._web_response(profile, action))
        elif self.service_type == 'ssh':
            response.update(self._ssh_response(profile, action))
        elif self.service_type == 'smb':
            response.update(self._smb_response(profile, action))
        
        # Add honeytokens for advanced attackers
        if profile.skill_level == 'ADVANCED' and random.random() < 0.2:
            response['honeytoken'] = self._get_honeytoken()
        
        return response
    
    def _calculate_response_delay(self, profile: AttackerProfile) -> float:
        """Calculate realistic response delay."""
        base_delays = self.deception_strategies.get('response_delays', [0.1, 0.3, 0.5])
        
        # More realistic delays for advanced attackers
        if profile.skill_level == 'ADVANCED':
            return random.choice(base_delays) * (0.8 + random.random() * 0.4)
        else:
            return random.choice(base_delays) * 0.5
    
    def _web_response(self, profile: AttackerProfile, action: Dict) -> Dict:
        """Generate web service response."""
        response = {}
        
        if action.get('type') == 'directory_enumeration':
            # Return fake directories
            dirs = self.deception_strategies.get('fake_directories', [])
            response['directories'] = random.sample(dirs, min(3, len(dirs)))
        elif action.get('type') == 'file_access':
            # Simulate file access
            if profile.skill_level == 'ADVANCED':
                response['content'] = "Partial file content..."
                response['size'] = random.randint(1000, 10000)
            else:
                response['error'] = random.choice(self.deception_strategies.get('error_messages', []))
        
        response['http_status'] = 200 if response.get('content') else 403
        return response
    
    def _ssh_response(self, profile: AttackerProfile, action: Dict) -> Dict:
        """Generate SSH service response."""
        response = {}
        
        if action.get('type') == 'banner_grab':
            response['banner'] = random.choice(
                self.deception_strategies.get('banner_messages', ['SSH-2.0-OpenSSH'])
            )
        elif action.get('type') == 'command':
            cmd = action.get('command', '')
            if cmd in self.deception_strategies.get('fake_commands', []):
                response['output'] = f"Simulated output for: {cmd}"
                response['exit_code'] = 0
            else:
                response['error'] = f"Command not found: {cmd}"
                response['exit_code'] = 127
        
        return response
    
    def _smb_response(self, profile: AttackerProfile, action: Dict) -> Dict:
        """Generate SMB service response."""
        response = {}
        
        if action.get('type') == 'share_enumeration':
            shares = self.deception_strategies.get('shares', [])
            response['shares'] = shares
        elif action.get('type') == 'file_list':
            files = self.deception_strategies.get('fake_files', [])
            response['files'] = files
        
        return response
    
    def _get_honeytoken(self) -> str:
        """Get a honeytoken to track attacker movements."""
        tokens = self.deception_strategies.get('honeytokens', [])
        if tokens:
            return random.choice(tokens)
        return "tracking_token_" + str(random.randint(1000, 9999))
    
    def get_statistics(self) -> Dict:
        """Get honeypot statistics and attacker analytics."""
        stats = {
            'total_interactions': len(self.interaction_log),
            'unique_attackers': len(self.attacker_profiles),
            'by_skill_level': defaultdict(int),
            'by_intent': defaultdict(int),
            'top_techniques': defaultdict(int)
        }
        
        for profile in self.attacker_profiles.values():
            stats['by_skill_level'][profile.skill_level] += 1
            stats['by_intent'][profile.intent] += 1
            for technique in profile.techniques:
                stats['top_techniques'][technique] += 1
        
        return stats
    
    def save_report(self, output_dir: str = '/output/deception'):
        """Save adaptive honeypot report."""
        os.makedirs(output_dir, exist_ok=True)
        
        report = {
            'service_type': self.service_type,
            'realism_level': self.realism_level,
            'statistics': self.get_statistics(),
            'attacker_profiles': [p.to_dict() for p in self.attacker_profiles.values()],
            'interactions': self.interaction_log[-100:]  # Last 100 interactions
        }
        
        output_file = f"{output_dir}/adaptive_honeypot_{self.service_type}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"[Adaptive Honeypot] Report saved to {output_file}")
        print(f"[Adaptive Honeypot] Total interactions: {len(self.interaction_log)}")
        print(f"[Adaptive Honeypot] Unique attackers: {len(self.attacker_profiles)}")


def main():
    """Example usage."""
    honeypot = AdaptiveHoneypot(service_type='web', realism_level=0.8)
    
    # Simulate attacker interactions
    test_actions = [
        {'type': 'directory_enumeration', 'technique': 'RECONNAISSANCE'},
        {'type': 'file_access', 'technique': 'DATA_ACCESS', 'file': '/etc/passwd'},
        {'type': 'sql_injection', 'technique': 'SQL_INJECTION'},
    ]
    
    for action in test_actions:
        response = honeypot.handle_interaction('192.168.1.100', action)
        print(f"\nAction: {action['type']}")
        print(f"Response: {json.dumps(response, indent=2)}")
    
    honeypot.save_report()
    
    # Print statistics
    stats = honeypot.get_statistics()
    print(f"\n[Statistics]")
    print(f"Total interactions: {stats['total_interactions']}")
    print(f"Skill levels: {dict(stats['by_skill_level'])}")


if __name__ == '__main__':
    main()
