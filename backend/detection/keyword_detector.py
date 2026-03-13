"""
Layer 1: Keyword Detection Module
=================================
Detects malicious prompts by matching against known attack keywords.
"""

import re
import json
import logging
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class KeywordDetector:
    """Detects malicious prompts using keyword matching."""
    
    def __init__(
        self,
        keywords_file: Optional[Path] = None,
        similarity_threshold: int = 80,
        min_keyword_length: int = 4
    ):
        self.similarity_threshold = similarity_threshold
        self.min_keyword_length = min_keyword_length
        self.keywords: Dict[str, List[str]] = {
            'injection': [],
            'jailbreak': [],
            'override': [],
            'extraction': [],
            'bypass': [],
            'hacking': [],
            'malware': [],
            'illegal': [],
            'violence': [],
            'social_engineering': []
        }
        
        if keywords_file and keywords_file.exists():
            self.load_keywords(keywords_file)
        else:
            self._load_default_keywords()
    
    def _load_default_keywords(self):
        """Load default attack keywords."""
        self.keywords = {
            'injection': [
                'ignore previous', 'ignore the above', 'ignore all',
                'disregard previous', 'disregard the above',
                'forget previous', 'forget the above',
                'override instructions', 'override previous',
                'new instructions', 'instead of',
                'prompt injection', 'inject prompt',
            ],
            'jailbreak': [
                'do anything now', 'dan mode', 'developer mode',
                'jailbreak', 'uncensored', 'unfiltered',
                'no restrictions', 'no limitations',
                'd mode', 'evil mode', 'hypothetical',
                'for educational purposes', 'in a fictional',
                'roleplay as', 'pretend to be',
            ],
            'override': [
                'you are now', 'you will now', 'you must',
                'act as', 'behave as', 'respond as',
                'from now on', 'starting now',
                'system override', 'admin mode',
                'root access', 'sudo mode',
            ],
            'extraction': [
                'system prompt', 'your instructions',
                'reveal your', 'show me your',
                'what are your instructions',
                'print your system',
                'output your prompt',
                'repeat the above',
                'repeat your instructions',
            ],
            'bypass': [
                'bypass', 'circumvent', 'work around',
                'get around', 'avoid detection',
                'safety filter', 'content filter',
                'ethical guidelines', 'safety guidelines',
                'without restrictions', 'without filters',
            ],
            'hacking': [
                'hack the', 'how to hack', 'hacking into',
                'crack the password', 'crack wifi', 'crack password',
                'hack wifi', 'hack into', 'break into',
                'exploit vulnerability', 'sql injection',
                'xss attack', 'ddos attack', 'brute force',
                'phishing attack', 'man in the middle',
                'zero day exploit', 'remote code execution',
                'privilege escalation', 'reverse shell',
                'keylogger', 'packet sniffing', 'port scanning',
                'vulnerability scan', 'penetration test without permission',
                'unauthorized access', 'bypass authentication',
                'steal credentials', 'password cracking',
                'network intrusion', 'wifi password',
                'steal data', 'data breach', 'exfiltrate',
            ],
            'malware': [
                'create malware', 'write malware', 'build malware',
                'create virus', 'write virus', 'make ransomware',
                'create ransomware', 'write ransomware',
                'create trojan', 'write trojan', 'write spyware',
                'create spyware', 'create worm', 'write worm',
                'create botnet', 'write exploit', 'create exploit',
                'malicious code', 'malicious script',
                'write a script to', 'automate attack',
            ],
            'illegal': [
                'how to make drugs', 'how to synthesize',
                'drug synthesis', 'make meth', 'make cocaine',
                'how to make a bomb', 'build a bomb', 'explosive device',
                'illegal weapons', 'buy illegal', 'sell illegal',
                'money laundering', 'how to launder',
                'credit card fraud', 'identity theft',
                'how to steal', 'how to rob',
                'child exploitation', 'illegal content',
            ],
            'violence': [
                'how to kill', 'how to hurt', 'how to harm',
                'how to attack', 'how to assault',
                'make someone suffer', 'torture',
                'how to poison', 'how to stalk',
                'threaten someone', 'make a threat',
            ],
            'social_engineering': [
                'pretend to be my', 'impersonate',
                'fake identity', 'social engineering',
                'manipulate someone', 'trick someone into',
                'deceive someone', 'scam someone',
                'phishing email', 'fake email',
                'spoof identity', 'fake website',
            ]
        }
        logger.info("Loaded default keywords")
    
    def detect(self, prompt: str) -> Dict:
        """Detect keywords in a prompt."""
        prompt_lower = prompt.lower()
        matches = []
        scores = []
        categories = set()
        
        for category, keywords in self.keywords.items():
            for keyword in keywords:
                if keyword in prompt_lower:
                    matches.append(keyword)
                    scores.append(100)
                    categories.add(category)
                    continue
                
                # Simple fuzzy matching without fuzzywuzzy
                if len(keyword) >= 8:
                    # Check for partial matches
                    kw_parts = keyword.split()
                    match_count = sum(1 for part in kw_parts if part in prompt_lower)
                    if match_count >= len(kw_parts) * 0.7:
                        matches.append(f"{keyword} (partial)")
                        scores.append(70 + match_count * 5)
                        categories.add(category)
        
        confidence = max(scores) / 100.0 if scores else 0.0
        
        return {
            'layer': 'keyword_detection',
            'triggered': len(matches) > 0,
            'confidence': confidence,
            'matches': matches,
            'categories': list(categories),
            'details': {
                'num_matches': len(matches),
                'match_categories': list(categories)
            }
        }
    
    def get_all_keywords(self) -> List[str]:
        """Get all keywords as a flat list."""
        all_keywords = []
        for keywords in self.keywords.values():
            all_keywords.extend(keywords)
        return all_keywords
    
    def save_keywords(self, filepath: Path):
        with open(filepath, 'w') as f:
            json.dump(self.keywords, f, indent=2)
    
    def load_keywords(self, filepath: Path):
        with open(filepath, 'r') as f:
            self.keywords = json.load(f)