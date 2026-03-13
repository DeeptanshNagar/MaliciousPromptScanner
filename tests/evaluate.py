"""
MAPS Evaluation Script
======================
Evaluates the detection performance of MAPS using standard metrics.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import logging
from typing import Dict, List
from datetime import datetime

import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

from backend.core.scanner import MAPSScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MAPSEvaluator:
    def __init__(self, scanner: MAPSScanner = None):
        self.scanner = scanner or MAPSScanner()
        self.results = []
    
    def evaluate_dataset(
        self,
        test_df: pd.DataFrame,
        text_column: str = 'prompt',
        label_column: str = 'label',
        max_samples: int = None,
        save_predictions: bool = True
    ) -> Dict:
        logger.info(f"Evaluating on {len(test_df)} samples...")
        
        if max_samples and len(test_df) > max_samples:
            test_df = test_df.sample(n=max_samples, random_state=42)
        
        y_true = test_df[label_column].values
        predictions = []
        risk_scores = []
        
        for idx, row in test_df.iterrows():
            prompt = row[text_column]
            result = self.scanner.scan(prompt, detailed=False)
            
            pred = 1 if result['decision'] == 'BLOCK' else 0
            predictions.append(pred)
            risk_scores.append(result['risk_score'])
            
            self.results.append({
                'prompt': prompt,
                'true_label': row[label_column],
                'predicted_label': pred,
                'risk_score': result['risk_score'],
                'classification': result['classification'],
                'confidence': result['confidence'],
                'detectors_triggered': result['detectors_triggered']
            })
            
            if (idx + 1) % 100 == 0:
                logger.info(f"Processed {idx + 1}/{len(test_df)} samples")
        
        y_pred = np.array(predictions)
        y_scores = np.array(risk_scores)
        
        metrics = self._calculate_metrics(y_true, y_pred, y_scores)
        
        if save_predictions:
            self._save_predictions()
        
        return metrics
    
    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, y_scores: np.ndarray) -> Dict:
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        return {
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'specificity': round(specificity, 4),
            'fpr': round(fpr, 4),
            'fnr': round(fnr, 4),
            'confusion_matrix': {
                'true_negatives': int(tn),
                'false_positives': int(fp),
                'false_negatives': int(fn),
                'true_positives': int(tp)
            },
            'total_samples': len(y_true),
            'positive_samples': int(sum(y_true)),
            'negative_samples': int(len(y_true) - sum(y_true))
        }
    
    def _save_predictions(self):
        output_dir = Path(__file__).parent / "results"
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"predictions_{timestamp}.csv"
        
        df = pd.DataFrame(self.results)
        df.to_csv(output_file, index=False)
        
        logger.info(f"Saved predictions to {output_file}")
    
    def generate_report(self, metrics: Dict, output_dir: Path = None) -> str:
        report_lines = [
            "=" * 60,
            "MAPS Evaluation Report",
            "=" * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Dataset Statistics:",
            f"  Total Samples: {metrics['total_samples']}",
            f"  Positive (Malicious): {metrics['positive_samples']}",
            f"  Negative (Safe): {metrics['negative_samples']}",
            "",
            "Performance Metrics:",
            f"  Accuracy:  {metrics['accuracy']:.4f}",
            f"  Precision: {metrics['precision']:.4f}",
            f"  Recall:    {metrics['recall']:.4f}",
            f"  F1 Score:  {metrics['f1_score']:.4f}",
            "",
            "Additional Metrics:",
            f"  Specificity: {metrics['specificity']:.4f}",
            f"  FPR (False Positive Rate): {metrics['fpr']:.4f}",
            f"  FNR (False Negative Rate): {metrics['fnr']:.4f}",
            "",
            "Confusion Matrix:",
            f"  True Negatives:  {metrics['confusion_matrix']['true_negatives']}",
            f"  False Positives: {metrics['confusion_matrix']['false_positives']}",
            f"  False Negatives: {metrics['confusion_matrix']['false_negatives']}",
            f"  True Positives:  {metrics['confusion_matrix']['true_positives']}",
            "",
            "=" * 60
        ]
        
        report = '\n'.join(report_lines)
        
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = output_dir / f"evaluation_report_{timestamp}.txt"
            
            with open(report_file, 'w') as f:
                f.write(report)
            
            metrics_file = output_dir / f"metrics_{timestamp}.json"
            with open(metrics_file, 'w') as f:
                json.dump(metrics, f, indent=2)
            
            logger.info(f"Saved report to {report_file}")
        
        return report


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Evaluate MAPS performance')
    parser.add_argument('--dataset', type=str, default='datasets/processed/test.csv', help='Path to test dataset')
    parser.add_argument('--max-samples', type=int, default=None, help='Maximum samples to evaluate')
    parser.add_argument('--output-dir', type=str, default='tests/results', help='Output directory for results')
    
    args = parser.parse_args()
    
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        logger.error(f"Dataset not found: {dataset_path}")
        return
    
    test_df = pd.read_csv(dataset_path)
    logger.info(f"Loaded {len(test_df)} samples from {dataset_path}")
    
    evaluator = MAPSEvaluator()
    
    metrics = evaluator.evaluate_dataset(
        test_df,
        max_samples=args.max_samples,
        save_predictions=True
    )
    
    output_dir = Path(args.output_dir)
    report = evaluator.generate_report(metrics, output_dir)
    
    print(report)


if __name__ == "__main__":
    main()
