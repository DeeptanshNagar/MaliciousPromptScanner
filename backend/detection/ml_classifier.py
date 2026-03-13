"""
Layer 5: Machine Learning Classifier Module
===========================================
Trains and uses ML models to classify prompts as safe or malicious.
"""

import json
import pickle
import logging
from typing import List, Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class MLClassifier:
    """Machine learning classifier for prompt injection detection."""
    
    MODEL_TYPES = ['logistic_regression', 'random_forest']
    
    def __init__(
        self,
        model_type: str = 'logistic_regression',
        model_path: Optional[Path] = None,
        vectorizer_path: Optional[Path] = None,
        max_features: int = 10000,
        ngram_range: Tuple[int, int] = (1, 3)
    ):
        if model_type not in self.MODEL_TYPES:
            raise ValueError(f"Model type must be one of {self.MODEL_TYPES}")
        
        self.model_type = model_type
        self.max_features = max_features
        self.ngram_range = ngram_range
        
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        self.sklearn_available = False
        
        # Check if sklearn is available
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            from sklearn.ensemble import RandomForestClassifier
            self.sklearn_available = True
        except ImportError:
            logger.warning("scikit-learn not available, ML classifier disabled")
        
        if model_path and vectorizer_path and self.sklearn_available:
            self.load_model(model_path, vectorizer_path)
    
    def _create_vectorizer(self):
        if not self.sklearn_available:
            return None
        from sklearn.feature_extraction.text import TfidfVectorizer
        return TfidfVectorizer(
            max_features=self.max_features,
            ngram_range=self.ngram_range,
            min_df=2,
            max_df=0.95,
            stop_words='english',
            lowercase=True,
            strip_accents='unicode'
        )
    
    def _create_model(self):
        if not self.sklearn_available:
            return None
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        
        if self.model_type == 'logistic_regression':
            return LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
        elif self.model_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
    
    def train(self, train_df, val_df=None, text_column: str = 'prompt', label_column: str = 'label') -> Dict:
        if not self.sklearn_available:
            logger.warning("scikit-learn not available, cannot train")
            return {'status': 'skipped', 'reason': 'sklearn_not_available'}
        
        logger.info(f"Training {self.model_type} classifier...")
        
        self.vectorizer = self._create_vectorizer()
        X_train = self.vectorizer.fit_transform(train_df[text_column])
        y_train = train_df[label_column].values
        
        logger.info(f"Training data shape: {X_train.shape}")
        
        self.model = self._create_model()
        self.model.fit(X_train, y_train)
        
        self.is_trained = True
        
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        train_preds = self.model.predict(X_train)
        
        metrics = {
            'train_accuracy': accuracy_score(y_train, train_preds),
            'train_precision': precision_score(y_train, train_preds, zero_division=0),
            'train_recall': recall_score(y_train, train_preds, zero_division=0),
            'train_f1': f1_score(y_train, train_preds, zero_division=0),
        }
        
        if val_df is not None:
            val_metrics = self.evaluate(val_df, text_column, label_column)
            metrics.update({f'val_{k}': v for k, v in val_metrics.items()})
        
        logger.info("Training complete!")
        return metrics
    
    def evaluate(self, test_df, text_column: str = 'prompt', label_column: str = 'label') -> Dict:
        if not self.is_trained or not self.sklearn_available:
            return {'status': 'not_trained'}
        
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        X_test = self.vectorizer.transform(test_df[text_column])
        y_test = test_df[label_column].values
        
        predictions = self.model.predict(X_test)
        
        return {
            'accuracy': accuracy_score(y_test, predictions),
            'precision': precision_score(y_test, predictions, zero_division=0),
            'recall': recall_score(y_test, predictions, zero_division=0),
            'f1': f1_score(y_test, predictions, zero_division=0),
        }
    
    def predict(self, prompt: str) -> Dict:
        if not self.is_trained or not self.sklearn_available:
            return {
                'layer': 'ml_classifier',
                'triggered': False,
                'confidence': 0.0,
                'probability': 0.5,
                'prediction': 0,
                'matches': [],
                'categories': [],
                'details': {'status': 'untrained'}
            }
        
        X = self.vectorizer.transform([prompt])
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0, 1]
        
        confidence = abs(probability - 0.5) * 2
        
        return {
            'layer': 'ml_classifier',
            'triggered': prediction == 1,
            'confidence': confidence,
            'probability': float(probability),
            'prediction': int(prediction),
            'matches': [],
            'categories': ['ml_detected'] if prediction == 1 else [],
            'details': {
                'model_type': self.model_type,
                'probability_malicious': round(probability, 4),
                'probability_safe': round(1 - probability, 4)
            }
        }
    
    def save_model(self, model_path: Path, vectorizer_path: Path):
        if not self.is_trained or not self.sklearn_available:
            return
        
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(self.vectorizer, f)
        
        metadata = {
            'model_type': self.model_type,
            'max_features': self.max_features,
            'ngram_range': self.ngram_range,
            'is_trained': self.is_trained
        }
        metadata_path = model_path.parent / 'ml_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Saved model to {model_path}")
    
    def load_model(self, model_path: Path, vectorizer_path: Path):
        if not self.sklearn_available:
            return
        
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        with open(vectorizer_path, 'rb') as f:
            self.vectorizer = pickle.load(f)
        
        metadata_path = model_path.parent / 'ml_metadata.json'
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            self.model_type = metadata['model_type']
            self.max_features = metadata['max_features']
            self.ngram_range = tuple(metadata['ngram_range'])
        
        self.is_trained = True
        logger.info(f"Loaded model from {model_path}")
