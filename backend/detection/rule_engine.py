"""
Layer 6: Rule Engine Module
===========================
Combines outputs from all detection layers using configurable rules.
"""

import json
import logging
from typing import List, Dict, Optional, Callable
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    name: str
    condition: Callable[[List[Dict]], bool]
    description: str
    severity: str
    category: str


class RuleEngine:
    """Rule-based engine for combining detection layer outputs."""
    
    SEVERITY_WEIGHTS = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    
    def __init__(self, rules_file: Optional[Path] = None):
        self.rules: List[DetectionRule] = []
        self.layer_results: List[Dict] = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default detection rules."""
        self.rules = [
            DetectionRule(
                name='critical_keyword_and_semantic',
                condition=self._rule_critical_keyword_semantic,
                description='Critical keyword detected with high semantic similarity',
                severity='critical',
                category='combined_attack'
            ),
            DetectionRule(
                name='multiple_high_confidence',
                condition=self._rule_multiple_high_confidence,
                description='Multiple layers report high confidence',
                severity='critical',
                category='layer_consensus'
            ),
            DetectionRule(
                name='regex_and_ml_agreement',
                condition=self._rule_regex_ml_agreement,
                description='Regex and ML classifier both detect malicious content',
                severity='high',
                category='classifier_consensus'
            ),
            DetectionRule(
                name='single_high_confidence',
                condition=self._rule_single_high_confidence,
                description='Single layer reports very high confidence',
                severity='medium',
                category='single_indicator'
            ),
        ]
        logger.info(f"Loaded {len(self.rules)} default rules")
    
    def _rule_critical_keyword_semantic(self, layers: List[Dict]) -> bool:
        keyword = self._get_layer_result(layers, 'keyword_detection')
        semantic = self._get_layer_result(layers, 'semantic_similarity')
        
        if keyword and semantic:
            critical_keywords = ['system prompt', 'reveal your', 'ignore previous']
            has_critical = any(kw in str(keyword.get('matches', [])).lower() 
                             for kw in critical_keywords)
            high_semantic = semantic.get('confidence', 0) > 0.8
            return has_critical and high_semantic
        return False
    
    def _rule_multiple_high_confidence(self, layers: List[Dict]) -> bool:
        high_confidence_count = sum(
            1 for layer in layers
            if layer.get('confidence', 0) > 0.8 and layer.get('triggered', False)
        )
        return high_confidence_count >= 2
    
    def _rule_regex_ml_agreement(self, layers: List[Dict]) -> bool:
        regex = self._get_layer_result(layers, 'regex_detection')
        ml = self._get_layer_result(layers, 'ml_classifier')
        
        if regex and ml:
            return (regex.get('triggered', False) and 
                   ml.get('triggered', False) and
                   ml.get('confidence', 0) > 0.6)
        return False
    
    def _rule_single_high_confidence(self, layers: List[Dict]) -> bool:
        return any(
            layer.get('confidence', 0) > 0.9 and layer.get('triggered', False)
            for layer in layers
        )
    
    def _get_layer_result(self, layers: List[Dict], layer_name: str) -> Optional[Dict]:
        for layer in layers:
            if layer.get('layer') == layer_name:
                return layer
        return None
    
    def evaluate(self, layer_results: List[Dict]) -> Dict:
        self.layer_results = layer_results
        
        triggered_rules = []
        total_severity_score = 0
        
        for rule in self.rules:
            try:
                if rule.condition(layer_results):
                    triggered_rules.append({
                        'name': rule.name,
                        'description': rule.description,
                        'severity': rule.severity,
                        'category': rule.category,
                        'severity_score': self.SEVERITY_WEIGHTS[rule.severity]
                    })
                    total_severity_score += self.SEVERITY_WEIGHTS[rule.severity]
            except Exception as e:
                logger.warning(f"Error evaluating rule {rule.name}: {e}")
        
        triggered_rules.sort(key=lambda x: self.SEVERITY_WEIGHTS[x['severity']], reverse=True)
        
        if triggered_rules:
            max_severity = self.SEVERITY_WEIGHTS[triggered_rules[0]['severity']]
            confidence = min(0.5 + (max_severity / 4) * 0.5, 1.0)
        else:
            confidence = 0.0
        
        return {
            'layer': 'rule_engine',
            'triggered': len(triggered_rules) > 0,
            'confidence': confidence,
            'matches': triggered_rules,
            'categories': list(set(r['category'] for r in triggered_rules)),
            'details': {
                'num_rules_triggered': len(triggered_rules),
                'total_severity_score': total_severity_score,
                'triggered_rules': [r['name'] for r in triggered_rules]
            }
        }
