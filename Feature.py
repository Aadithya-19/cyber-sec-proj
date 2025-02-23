"""
Feature.py
----------
Purpose:
    Implements the FeatureExtractor which:
      - Converts raw log records into a set of features for the ML model.
      - Extracts time-based features (hour, day, and their sinusoidal transformations).
      - Computes authentication metrics from 'auth_attempts'.
      - Extracts session behavior metrics (duration, unique commands, command entropy, etc.).
      - Counts suspicious commands.
      - Retrieves an IP reputation score and country risk.
      - Provides a method 'get_location()' to lookup the geographical location of an IP.
"""

from datetime import datetime
import geoip2.database
import os
from collections import Counter
import math

class FeatureExtractor:
    def __init__(self):
        geoip_path = os.getenv("GEOIP_PATH")
        if not geoip_path:
            raise ValueError("GEOIP_PATH environment variable is not set.")
        self.geoip = geoip2.database.Reader(
            os.path.join(geoip_path, 'GeoLite2-City.mmdb')
        )
        self.suspicious_commands = {
            'wget', 'curl', 'chmod', 'chown', 'passwd',
            'rm', 'mv', 'tar', 'nc', 'telnet', 'su', 'sudo', 'ssh', 'ftp', 'uname', 'id'
        }

    def transform(self, log_entry):
        features = {}
        timestamp = datetime.fromisoformat(log_entry['timestamp'])
        hour = timestamp.hour
        features['hour_of_day'] = hour
        features['hour_sin'] = math.sin(2 * math.pi * hour / 24)
        features['hour_cos'] = math.cos(2 * math.pi * hour / 24)
        features['is_night'] = int(hour >= 22 or hour < 4)
        day = timestamp.weekday()
        features['day_of_week'] = day
        features['day_sin'] = math.sin(2 * math.pi * day / 7)
        features['day_cos'] = math.cos(2 * math.pi * day / 7)
        
        auth_attempts = log_entry.get('auth_attempts', {'failed': 0, 'success': 0})
        failed = auth_attempts.get('failed', 0)
        success = auth_attempts.get('success', 0)
        features['failed_logins'] = failed
        features['success_logins'] = success
        features['login_attempt_ratio'] = failed / (failed + success + 1e-6)
        
        duration = log_entry.get('duration', 0)
        commands = log_entry.get('commands', [])
        features['session_duration'] = duration
        features['unique_commands'] = len(set(commands))
        features['total_commands'] = len(commands)
        features['suspicious_command_count'] = self._count_suspicious_commands(log_entry)
        if features['total_commands'] > 0:
            features['proportion_suspicious_commands'] = features['suspicious_command_count'] / features['total_commands']
        else:
            features['proportion_suspicious_commands'] = 0
        if commands:
            freq = Counter(commands)
            total = len(commands)
            entropy = -sum((count / total) * math.log2(count / total) for count in freq.values() if count > 0)
            features['command_entropy'] = entropy
        else:
            features['command_entropy'] = 0
        
        features['ip_reputation'] = self._get_ip_reputation(log_entry['source_ip'])
        features['country_risk'] = self._get_country_risk(log_entry['source_ip'])
        
        if duration > 0:
            features['commands_per_minute'] = features['unique_commands'] / (duration / 60 + 1e-6)
        else:
            features['commands_per_minute'] = 0
        
        return features

    def _count_suspicious_commands(self, log_entry):
        commands = log_entry.get('commands', [])
        return sum(1 for cmd in commands if isinstance(cmd, str) and cmd.split()[0] in self.suspicious_commands)

    def _get_ip_reputation(self, ip):
        return 0.5

    def _get_country_risk(self, ip):
        try:
            country = self.geoip.city(ip).country.iso_code
            risk_scores = {
                'CN': 0.8, 'RU': 0.7, 'US': 0.2,
                'RO': 0.6, 'NG': 0.55, 'BR': 0.4,
            }
            return risk_scores.get(country, 0.5)
        except Exception:
            return 0.5

    def get_location(self, ip):
        """
        Look up location information for a given IP address.
        Returns a string in the format 'City, Country'. If lookup fails, returns 'Unknown'.
        """
        try:
            geo_info = self.geoip.city(ip)
            city = geo_info.city.name if geo_info.city.name else "Unknown City"
            country = geo_info.country.iso_code if geo_info.country.iso_code else "Unknown Country"
            return f"{city}, {country}"
        except Exception:
            return "Unknown"

