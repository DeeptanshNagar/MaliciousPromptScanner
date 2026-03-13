"""
MAPS Dataset Processing Pipeline
================================
Downloads and processes public prompt injection datasets.
"""

import os
import json
import logging
from typing import Dict, List, Tuple
from pathlib import Path

import pandas as pd
import numpy as np
from datasets import load_dataset
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RAW_DIR = Path(__file__).parent / "raw"
PROCESSED_DIR = Path(__file__).parent / "processed"
RAW_DIR.mkdir(exist_ok=True)
PROCESSED_DIR.mkdir(exist_ok=True)


class DatasetProcessor:
    def __init__(self):
        self.datasets = {}
        self.combined_df = None
    
    def download_open_prompt_injection(self) -> pd.DataFrame:
        logger.info("Downloading Open Prompt Injection dataset...")
        
        try:
            dataset = load_dataset("guychuk/open-prompt-injection", split="train")
            df = pd.DataFrame(dataset)
            
            processed_rows = []
            for _, row in df.iterrows():
                if row['attack_type'] == 'naive':
                    processed_rows.append({
                        'prompt': row['normal_input'],
                        'label': 0,
                        'attack_type': 'benign',
                        'source_dataset': 'open_prompt_injection'
                    })
                else:
                    processed_rows.append({
                        'prompt': row['attack_input'],
                        'label': 1,
                        'attack_type': row['attack_type'],
                        'source_dataset': 'open_prompt_injection'
                    })
            
            result_df = pd.DataFrame(processed_rows)
            logger.info(f"Open Prompt Injection: {len(result_df)} samples")
            return result_df
            
        except Exception as e:
            logger.error(f"Error downloading Open Prompt Injection: {e}")
            return pd.DataFrame()
    
    def download_shieldlm_dataset(self) -> pd.DataFrame:
        logger.info("Downloading ShieldLM Prompt Injection dataset...")
        
        try:
            train = load_dataset("dmilush/shieldlm-prompt-injection", split="train")
            validation = load_dataset("dmilush/shieldlm-prompt-injection", split="validation")
            test = load_dataset("dmilush/shieldlm-prompt-injection", split="test")
            
            all_data = []
            for split in [train, validation, test]:
                all_data.extend([dict(item) for item in split])
            
            df = pd.DataFrame(all_data)
            
            processed_rows = []
            for _, row in df.iterrows():
                attack_type = row.get('label_category', 'benign')
                if attack_type is None or attack_type == 'benign':
                    attack_type = 'benign'
                    label = 0
                else:
                    label = 1
                
                processed_rows.append({
                    'prompt': row['text'],
                    'label': label,
                    'attack_type': attack_type,
                    'source_dataset': 'shieldlm'
                })
            
            result_df = pd.DataFrame(processed_rows)
            logger.info(f"ShieldLM: {len(result_df)} samples")
            return result_df
            
        except Exception as e:
            logger.error(f"Error downloading ShieldLM: {e}")
            return pd.DataFrame()
    
    def download_jailbreakhub_dataset(self) -> pd.DataFrame:
        logger.info("Downloading JailbreakHub dataset...")
        
        try:
            jailbreak_2023_05 = load_dataset("TrustAIRLab/in-the-wild-jailbreak-prompts", "jailbreak_2023_05_07", split="train")
            jailbreak_2023_12 = load_dataset("TrustAIRLab/in-the-wild-jailbreak-prompts", "jailbreak_2023_12_25", split="train")
            regular_2023_05 = load_dataset("TrustAIRLab/in-the-wild-jailbreak-prompts", "regular_2023_05_07", split="train")
            regular_2023_12 = load_dataset("TrustAIRLab/in-the-wild-jailbreak-prompts", "regular_2023_12_25", split="train")
            
            processed_rows = []
            
            for split in [jailbreak_2023_05, jailbreak_2023_12]:
                for item in split:
                    processed_rows.append({
                        'prompt': item['prompt'],
                        'label': 1,
                        'attack_type': 'jailbreak',
                        'source_dataset': 'jailbreakhub'
                    })
            
            for split in [regular_2023_05, regular_2023_12]:
                for item in split:
                    processed_rows.append({
                        'prompt': item['prompt'],
                        'label': 0,
                        'attack_type': 'benign',
                        'source_dataset': 'jailbreakhub'
                    })
            
            result_df = pd.DataFrame(processed_rows)
            logger.info(f"JailbreakHub: {len(result_df)} samples")
            return result_df
            
        except Exception as e:
            logger.error(f"Error downloading JailbreakHub: {e}")
            return pd.DataFrame()
    
    def clean_and_normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        logger.info("Cleaning and normalizing dataset...")
        
        initial_len = len(df)
        df = df.drop_duplicates(subset=['prompt'])
        logger.info(f"Removed {initial_len - len(df)} duplicate prompts")
        
        df = df[df['prompt'].notna()]
        df = df[df['prompt'].str.strip() != '']
        df['prompt'] = df['prompt'].str.strip()
        df['prompt'] = df['prompt'].str[:10000]
        
        attack_type_mapping = {
            'naive': 'benign',
            'none': 'benign',
            'None': 'benign',
            'null': 'benign',
            'direct_injection': 'direct_injection',
            'indirect_injection': 'indirect_injection',
            'jailbreak': 'jailbreak',
            'ignore_previous': 'instruction_override',
        }
        
        df['attack_type'] = df['attack_type'].map(lambda x: attack_type_mapping.get(x, x)).fillna('unknown')
        
        logger.info(f"Final dataset size: {len(df)}")
        return df.reset_index(drop=True)
    
    def create_splits(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        logger.info("Creating train/validation/test splits...")
        
        train_df, temp_df = train_test_split(df, test_size=0.3, random_state=42, stratify=df['label'])
        val_df, test_df = train_test_split(temp_df, test_size=0.5, random_state=42, stratify=temp_df['label'])
        
        logger.info(f"Train: {len(train_df)}, Validation: {len(val_df)}, Test: {len(test_df)}")
        
        return train_df, val_df, test_df
    
    def process_all(self):
        logger.info("=" * 60)
        logger.info("MAPS Dataset Processing Pipeline")
        logger.info("=" * 60)
        
        datasets_list = []
        
        open_pi = self.download_open_prompt_injection()
        if not open_pi.empty:
            datasets_list.append(open_pi)
        
        shieldlm = self.download_shieldlm_dataset()
        if not shieldlm.empty:
            datasets_list.append(shieldlm)
        
        jailbreakhub = self.download_jailbreakhub_dataset()
        if not jailbreakhub.empty:
            datasets_list.append(jailbreakhub)
        
        if not datasets_list:
            logger.error("No datasets were successfully downloaded!")
            return
        
        logger.info("\nCombining datasets...")
        combined = pd.concat(datasets_list, ignore_index=True)
        logger.info(f"Combined dataset: {len(combined)} samples")
        
        combined = self.clean_and_normalize(combined)
        train_df, val_df, test_df = self.create_splits(combined)
        
        logger.info("\nSaving datasets...")
        
        combined_path = PROCESSED_DIR / "full_dataset.csv"
        combined.to_csv(combined_path, index=False)
        logger.info(f"Saved full dataset to {combined_path}")
        
        train_df.to_csv(PROCESSED_DIR / "train.csv", index=False)
        val_df.to_csv(PROCESSED_DIR / "validation.csv", index=False)
        test_df.to_csv(PROCESSED_DIR / "test.csv", index=False)
        
        stats = {
            'total_samples': len(combined),
            'benign_samples': int((combined['label'] == 0).sum()),
            'malicious_samples': int((combined['label'] == 1).sum()),
            'train_samples': len(train_df),
            'validation_samples': len(val_df),
            'test_samples': len(test_df),
            'attack_types': combined['attack_type'].value_counts().to_dict()
        }
        
        stats_path = PROCESSED_DIR / "statistics.json"
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2)
        
        logger.info("\n" + "=" * 60)
        logger.info("Dataset Processing Complete!")
        logger.info("=" * 60)
        logger.info(f"Total samples: {stats['total_samples']}")
        logger.info(f"  Benign: {stats['benign_samples']}")
        logger.info(f"  Malicious: {stats['malicious_samples']}")
        
        self.combined_df = combined
        return combined


def main():
    processor = DatasetProcessor()
    processor.process_all()


if __name__ == "__main__":
    main()
