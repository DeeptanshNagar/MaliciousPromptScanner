"""
Layer 2: Regex Pattern Detection Module
=======================================
Detects malicious prompts using predefined regex patterns.
"""

import re
import json
import logging
from typing import List, Dict, Optional
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RegexPattern:
    name: str
    pattern: str
    compiled: re.Pattern
    category: str
    severity: str
    description: str


class RegexDetector:
    """Detects malicious prompts using regex pattern matching."""
    
    DEFAULT_PATTERNS = [
        {
            'name': 'ignore_previous',
            'pattern': r'ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|commands?|prompts?)',
            'category': 'instruction_override',
            'severity': 'high',
            'description': 'Attempts to ignore previous instructions'
        },
        {
            'name': 'reveal_system_prompt',
            'pattern': r'(reveal|show|display|print|output)\s+(your|the|system\s+)?(prompt|instructions?|system)',
            'category': 'system_extraction',
            'severity': 'critical',
            'description': 'Attempts to extract system prompt'
        },
        {
            'name': 'developer_mode',
            'pattern': r'(developer|dev)\s+mode|developer\s+access',
            'category': 'jailbreak',
            'severity': 'high',
            'description': 'Attempts to enable developer mode'
        },
        {
            'name': 'dan_mode',
            'pattern': r'\b(dan|d\.a\.n)\b.*\bmode\b|\bdo\s+anything\s+now\b',
            'category': 'jailbreak',
            'severity': 'high',
            'description': 'DAN jailbreak attempt'
        },
        {
            'name': 'roleplay_override',
            'pattern': r'(act\s+as|behave\s+as|respond\s+as|you\s+are\s+now)\s+(.{3,50})',
            'category': 'roleplay',
            'severity': 'medium',
            'description': 'Roleplay-based instruction override'
        },
        {
            'name': 'bypass_safety',
            'pattern': r'(bypass|circumvent|work\s+around|get\s+around)\s+(safety|filter|restriction|guideline)',
            'category': 'bypass',
            'severity': 'high',
            'description': 'Attempts to bypass safety filters'
        },
        {
            'name': 'no_restrictions',
            'pattern': r'(no\s+restrictions?|without\s+restrictions?|unrestricted|uncensored|unfiltered)',
            'category': 'bypass',
            'severity': 'medium',
            'description': 'Requests for unrestricted output'
        },
        {
            'name': 'refusal_suppression',
            'pattern': r'(never\s+refuse|cannot\s+refuse|will\s+not\s+refuse|no\s+refusal)',
            'category': 'instruction_override',
            'severity': 'high',
            'description': 'Attempts to suppress refusal behavior'
        },
    ]
    
    SEVERITY_WEIGHTS = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
    
    def __init__(self, patterns_file: Optional[Path] = None):
        self.patterns: List[RegexPattern] = []
        
        if patterns_file and patterns_file.exists():
            self.load_patterns(patterns_file)
        else:
            self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load default regex patterns."""
        for p in self.DEFAULT_PATTERNS:
            try:
                compiled = re.compile(p['pattern'], re.IGNORECASE | re.MULTILINE)
                self.patterns.append(RegexPattern(
                    name=p['name'],
                    pattern=p['pattern'],
                    compiled=compiled,
                    category=p['category'],
                    severity=p['severity'],
                    description=p['description']
                ))
            except re.error as e:
                logger.warning(f"Invalid regex pattern {p['name']}: {e}")
        
        logger.info(f"Loaded {len(self.patterns)} default regex patterns")
    
    def detect(self, prompt: str) -> Dict:
        """Detect regex patterns in a prompt."""
        matches = []
        severity_scores = []
        categories = set()
        
        for pattern in self.patterns:
            if pattern.compiled.search(prompt):
                matches.append({
                    'name': pattern.name,
                    'category': pattern.category,
                    'severity': pattern.severity,
                    'description': pattern.description,
                    'pattern': pattern.pattern
                })
                severity_scores.append(self.SEVERITY_WEIGHTS[pattern.severity])
                categories.add(pattern.category)
        
        if severity_scores:
            base_confidence = max(severity_scores)
            count_bonus = min(len(matches) * 0.1, 0.3)
            confidence = min(base_confidence + count_bonus, 1.0)
        else:
            confidence = 0.0
        
        return {
            'layer': 'regex_detection',
            'triggered': len(matches) > 0,
            'confidence': confidence,
            'matches': matches,
            'categories': list(categories),
            'details': {
                'num_matches': len(matches),
                'triggered_patterns': [m['name'] for m in matches],
                'severity_breakdown': self._get_severity_breakdown(matches)
            }
        }
    
    def _get_severity_breakdown(self, matches: List[Dict]) -> Dict[str, int]:
        breakdown = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for match in matches:
            severity = match.get('severity', 'low')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown
    
    def save_patterns(self, filepath: Path):
        patterns_data = [
            {'name': p.name, 'pattern': p.pattern, 'category': p.category,
             'severity': p.severity, 'description': p.description}
            for p in self.patterns
        ]
        with open(filepath, 'w') as f:
            json.dump(patterns_data, f, indent=2)
    
    def load_patterns(self, filepath: Path):
        with open(filepath, 'r') as f:
            patterns_data = json.load(f)
        
        self.patterns = []
        for p in patterns_data:
            try:
                compiled = re.compile(p['pattern'], re.IGNORECASE | re.MULTILINE)
                self.patterns.append(RegexPattern(
                    name=p['name'], pattern=p['pattern'], compiled=compiled,
                    category=p['category'], severity=p['severity'], description=p['description']
                ))
            except re.error as e:
                logger.warning(f"Invalid regex pattern {p['name']}: {e}")
