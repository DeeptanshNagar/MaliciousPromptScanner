"""
MAPS Model Training Script
==========================
Trains the machine learning classifier for prompt injection detection.

Usage:
    python train_models.py --dataset datasets/processed/train.csv
"""

import argparse
import logging
from pathlib import Path

import pandas as pd

from backend.core.scanner import MAPSScanner
from backend.detection.ml_classifier import MLClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def train_ml_classifier(
    train_path: Path,
    val_path: Path = None,
    model_type: str = 'logistic_regression',
    save_dir: Path = None
):
    """
    Train the ML classifier.
    
    Args:
        train_path: Path to training dataset
        val_path: Path to validation dataset (optional)
        model_type: Type of model ('logistic_regression' or 'random_forest')
        save_dir: Directory to save trained models
    """
    logger.info("=" * 60)
    logger.info("MAPS Model Training")
    logger.info("=" * 60)
    
    # Load datasets
    logger.info(f"Loading training data from {train_path}")
    train_df = pd.read_csv(train_path)
    
    val_df = None
    if val_path and val_path.exists():
        logger.info(f"Loading validation data from {val_path}")
        val_df = pd.read_csv(val_path)
    
    logger.info(f"Training samples: {len(train_df)}")
    if val_df is not None:
        logger.info(f"Validation samples: {len(val_df)}")
    
    # Check class distribution
    class_dist = train_df['label'].value_counts()
    logger.info(f"Class distribution - Safe: {class_dist.get(0, 0)}, Malicious: {class_dist.get(1, 0)}")
    
    # Initialize scanner and train
    scanner = MAPSScanner()
    
    logger.info(f"\nTraining {model_type} classifier...")
    metrics = scanner.train_ml_classifier(train_df, val_df, model_type)
    
    # Print metrics
    logger.info("\nTraining Metrics:")
    for key, value in metrics.items():
        if isinstance(value, float):
            logger.info(f"  {key}: {value:.4f}")
        else:
            logger.info(f"  {key}: {value}")
    
    # Save models
    if save_dir:
        save_dir = Path(save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        scanner.save_models(save_dir)
        logger.info(f"\nModels saved to {save_dir}")
    
    logger.info("\nTraining complete!")
    return scanner, metrics


def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description='Train MAPS models')
    parser.add_argument(
        '--train',
        type=str,
        default='datasets/processed/train.csv',
        help='Path to training dataset'
    )
    parser.add_argument(
        '--val',
        type=str,
        default='datasets/processed/validation.csv',
        help='Path to validation dataset'
    )
    parser.add_argument(
        '--model-type',
        type=str,
        default='logistic_regression',
        choices=['logistic_regression', 'random_forest'],
        help='Type of ML model'
    )
    parser.add_argument(
        '--save-dir',
        type=str,
        default='models',
        help='Directory to save trained models'
    )
    
    args = parser.parse_args()
    
    train_path = Path(args.train)
    val_path = Path(args.val)
    save_dir = Path(args.save_dir)
    
    if not train_path.exists():
        logger.error(f"Training dataset not found: {train_path}")
        logger.info("Please run dataset processing first:")
        logger.info("  python datasets/download_and_process.py")
        return
    
    train_ml_classifier(
        train_path=train_path,
        val_path=val_path if val_path.exists() else None,
        model_type=args.model_type,
        save_dir=save_dir
    )


if __name__ == "__main__":
    main()
