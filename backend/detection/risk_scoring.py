"""
Layer 7: Risk Scoring Module
============================
Aggregates outputs from all detection layers into a final risk score.
"""

import json
import logging
from typing import List, Dict, Optional
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RiskThresholds:
    safe_max: int = 20          # Lowered from 30 → harder to be "SAFE"
    suspicious_max: int = 50    # Lowered from 60 → easier to be "MALICIOUS"
    
    def classify(self, score: int) -> str:
        if score <= self.safe_max:
            return 'SAFE'
        elif score <= self.suspicious_max:
            return 'SUSPICIOUS'
        else:
            return 'MALICIOUS'


class RiskScorer:
    """Calculates final risk score from all detection layers."""
    
    DEFAULT_WEIGHTS = {
        'keyword_detection': 40,   # Increased from 15 → keywords matter most
        'regex_detection': 20,     # Increased from 15
        'ngram_detection': 15,
        'semantic_similarity': 25,
        'ml_classifier': 20,
        'rule_engine': 15          # Increased from 10
    }
    
    CONFIDENCE_MULTIPLIERS = {'low': 0.6, 'medium': 0.85, 'high': 1.0}
    
    def __init__(
        self,
        weights: Optional[Dict[str, int]] = None,
        thresholds: Optional[RiskThresholds] = None
    ):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self.thresholds = thresholds or RiskThresholds()
        self.max_score = sum(self.weights.values())
        logger.info(f"RiskScorer initialized with max score: {self.max_score}")
    
    def _get_confidence_multiplier(self, confidence: float) -> float:
        if confidence < 0.4:
            return self.CONFIDENCE_MULTIPLIERS['low']
        elif confidence < 0.7:
            return self.CONFIDENCE_MULTIPLIERS['medium']
        else:
            return self.CONFIDENCE_MULTIPLIERS['high']
    
    def calculate_score(self, layer_results: List[Dict]) -> Dict:
        layer_scores = {}
        total_score = 0
        triggered_layers = []
        
        for result in layer_results:
            layer_name = result.get('layer')
            
            if layer_name not in self.weights:
                continue
            
            weight = self.weights[layer_name]
            
            if result.get('triggered', False):
                confidence = result.get('confidence', 0)
                multiplier = self._get_confidence_multiplier(confidence)
                
                layer_score = weight * multiplier * confidence
                layer_scores[layer_name] = {
                    'score': round(layer_score, 2),
                    'weight': weight,
                    'confidence': round(confidence, 3),
                    'multiplier': multiplier,
                    'triggered': True
                }
                
                total_score += layer_score
                triggered_layers.append(layer_name)
            else:
                layer_scores[layer_name] = {
                    'score': 0,
                    'weight': weight,
                    'confidence': 0,
                    'multiplier': 0,
                    'triggered': False
                }
        
        normalized_score = min(int((total_score / self.max_score) * 100), 100)
        adjusted_score = self._apply_adjustments(normalized_score, layer_results)
        classification = self.thresholds.classify(adjusted_score)
        overall_confidence = self._calculate_overall_confidence(layer_results)
        
        return {
            'risk_score': adjusted_score,
            'raw_score': round(total_score, 2),
            'max_possible_score': self.max_score,
            'classification': classification,
            'confidence': overall_confidence,
            'layer_breakdown': layer_scores,
            'triggered_layers': triggered_layers,
            'details': {
                'num_layers_triggered': len(triggered_layers),
                'score_percentage': round((adjusted_score / 100) * 100, 2),
                'thresholds': {
                    'safe_max': self.thresholds.safe_max,
                    'suspicious_max': self.thresholds.suspicious_max
                }
            }
        }
    
    def _apply_adjustments(self, score: int, layer_results: List[Dict]) -> int:
        adjusted = score

        # Bonus if multiple high-confidence layers triggered
        high_confidence_count = sum(
            1 for r in layer_results
            if r.get('triggered', False) and r.get('confidence', 0) > 0.8
        )
        if high_confidence_count >= 2:
            adjusted += 15

        # Bonus for critical regex patterns
        regex_result = self._get_layer_result(layer_results, 'regex_detection')
        if regex_result:
            matches = regex_result.get('matches', [])
            critical_patterns = ['reveal_system_prompt', 'system_prompt_leak']
            if any(m.get('name') in critical_patterns for m in matches):
                adjusted += 15

        # Bonus if hacking or malware category detected
        for result in layer_results:
            categories = result.get('categories', [])
            if any(cat in categories for cat in ['hacking', 'malware', 'illegal', 'violence']):
                adjusted += 20
                break

        # Reduce score only if single low-confidence trigger
        triggered = [r for r in layer_results if r.get('triggered', False)]
        if len(triggered) == 1 and triggered[0].get('confidence', 0) < 0.5:
            adjusted = int(adjusted * 0.8)  # Less aggressive reduction than before
        
        return min(adjusted, 100)
    
    def _calculate_overall_confidence(self, layer_results: List[Dict]) -> float:
        triggered_confidences = [
            r.get('confidence', 0) for r in layer_results if r.get('triggered', False)
        ]
        
        if triggered_confidences:
            return sum(triggered_confidences) / len(triggered_confidences)
        
        return 0.0
    
    def _get_layer_result(self, layers: List[Dict], layer_name: str) -> Optional[Dict]:
        for layer in layers:
            if layer.get('layer') == layer_name:
                return layer
        return None
    
    def get_classification(self, score: int) -> str:
        return self.thresholds.classify(score)


class DecisionEngine:
    """Makes final decision based on risk score and classification."""
    
    def __init__(self, risk_scorer: Optional[RiskScorer] = None):
        self.risk_scorer = risk_scorer or RiskScorer()
    
    def decide(self, layer_results: List[Dict]) -> Dict:
        risk_result = self.risk_scorer.calculate_score(layer_results)
        
        score = risk_result['risk_score']
        classification = risk_result['classification']
        
        decision_map = {'SAFE': 'ALLOW', 'SUSPICIOUS': 'WARN', 'MALICIOUS': 'BLOCK'}
        decision = decision_map[classification]
        
        if decision == 'ALLOW':
            reason = "No malicious indicators detected"
            action = "Proceed with request"
        elif decision == 'WARN':
            reason = "Suspicious patterns detected"
            action = "Log and proceed with caution"
        else:
            reason = "Malicious content detected"
            action = "Block request and log for review"
        
        return {
            'decision': decision,
            'risk_score': score,
            'classification': classification,
            'confidence': risk_result['confidence'],
            'reason': reason,
            'action': action,
            'layer_results': layer_results,
            'risk_details': risk_result,
            'should_block': decision == 'BLOCK',
            'should_log': decision in ['WARN', 'BLOCK']
        }