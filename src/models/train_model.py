"""
Model Training for Phishing URL Detection
Trains and evaluates multiple ML models
"""

import pandas as pd
import numpy as np
import os
import joblib
from datetime import datetime

# Scikit-learn
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, roc_curve
)

# For visualization
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

# XGBoost (optional)
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠️ XGBoost not available. Install with: pip install xgboost")


class PhishingModelTrainer:
    """Train and evaluate phishing detection models"""
    
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None
        self.scaler = StandardScaler()
        
    def load_data(self, file_path):
        """Load processed features dataset"""
        print(f"📂 Loading data from {file_path}...")
        
        df = pd.read_csv(file_path)
        print(f"   ✓ Loaded {len(df)} samples")
        
        # Separate features and labels
        if 'label' not in df.columns:
            raise ValueError("Dataset must have 'label' column!")
        
        # Get feature columns (exclude 'url' and 'label')
        feature_cols = [c for c in df.columns if c not in ['url', 'label']]
        
        X = df[feature_cols].values
        y = df['label'].values
        
        print(f"   ✓ Features: {len(feature_cols)}")
        print(f"   ✓ Class distribution: Benign={np.sum(y==0)}, Phishing={np.sum(y==1)}")
        
        return X, y, feature_cols
    
    def prepare_data(self, X, y, test_size=0.2):
        """Split and scale data"""
        print(f"\n🔀 Splitting data (test_size={test_size})...")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=test_size, 
            random_state=self.random_state,
            stratify=y
        )
        
        print(f"   ✓ Train size: {len(X_train)}")
        print(f"   ✓ Test size: {len(X_test)}")
        
        # Scale features
        print("\n📏 Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def initialize_models(self):
        """Initialize all models to train"""
        print("\n🤖 Initializing models...")
        
        self.models = {
            'Logistic Regression': LogisticRegression(
                random_state=self.random_state,
                max_iter=1000,
                class_weight='balanced'
            ),
            'Decision Tree': DecisionTreeClassifier(
                random_state=self.random_state,
                max_depth=10,
                class_weight='balanced'
            ),
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                random_state=self.random_state,
                class_weight='balanced',
                n_jobs=-1
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=100,
                random_state=self.random_state,
                max_depth=5
            )
        }
        
        # Add XGBoost if available
        if XGBOOST_AVAILABLE:
            scale_pos_weight = 1  # Adjust based on class imbalance
            self.models['XGBoost'] = xgb.XGBClassifier(
                n_estimators=100,
                random_state=self.random_state,
                scale_pos_weight=scale_pos_weight,
                use_label_encoder=False,
                eval_metric='logloss'
            )
        
        print(f"   ✓ Initialized {len(self.models)} models")
        for name in self.models.keys():
            print(f"      - {name}")
    
    def train_and_evaluate(self, X_train, X_test, y_train, y_test):
        """Train all models and evaluate"""
        print("\n" + "="*60)
        print("🎯 TRAINING MODELS")
        print("="*60)
        
        for name, model in self.models.items():
            print(f"\n🔧 Training {name}...")
            
            # Train
            model.fit(X_train, y_train)
            
            # Predict
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, zero_division=0),
                'recall': recall_score(y_test, y_pred, zero_division=0),
                'f1': f1_score(y_test, y_pred, zero_division=0),
            }
            
            if y_pred_proba is not None:
                metrics['roc_auc'] = roc_auc_score(y_test, y_pred_proba)
            
            # Store results
            self.results[name] = {
                'model': model,
                'metrics': metrics,
                'predictions': y_pred,
                'probabilities': y_pred_proba,
                'confusion_matrix': confusion_matrix(y_test, y_pred)
            }
            
            # Print metrics
            print(f"   ✓ Accuracy:  {metrics['accuracy']:.4f}")
            print(f"   ✓ Precision: {metrics['precision']:.4f}")
            print(f"   ✓ Recall:    {metrics['recall']:.4f}")
            print(f"   ✓ F1-Score:  {metrics['f1']:.4f}")
            if 'roc_auc' in metrics:
                print(f"   ✓ ROC-AUC:   {metrics['roc_auc']:.4f}")
    
    def compare_models(self):
        """Compare all trained models"""
        print("\n" + "="*60)
        print("📊 MODEL COMPARISON")
        print("="*60)
        
        # Create comparison DataFrame
        comparison_data = []
        for name, result in self.results.items():
            metrics = result['metrics']
            comparison_data.append({
                'Model': name,
                'Accuracy': metrics['accuracy'],
                'Precision': metrics['precision'],
                'Recall': metrics['recall'],
                'F1-Score': metrics['f1'],
                'ROC-AUC': metrics.get('roc_auc', 0)
            })
        
        df_comparison = pd.DataFrame(comparison_data)
        df_comparison = df_comparison.sort_values('F1-Score', ascending=False)
        
        print("\n")
        print(df_comparison.to_string(index=False))
        
        # Find best model (by F1-score)
        self.best_model_name = df_comparison.iloc[0]['Model']
        self.best_model = self.results[self.best_model_name]['model']
        
        print(f"\n🏆 Best Model: {self.best_model_name}")
        print(f"   F1-Score: {df_comparison.iloc[0]['F1-Score']:.4f}")
        
        return df_comparison
    
    def plot_confusion_matrices(self, save_dir='reports/figures'):
        """Plot confusion matrices for all models"""
        os.makedirs(save_dir, exist_ok=True)
        
        n_models = len(self.results)
        n_cols = 3
        n_rows = (n_models + n_cols - 1) // n_cols
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 5*n_rows))
        
        if n_rows == 1:
            axes = axes.reshape(1, -1)
        
        axes = axes.ravel()
        
        for idx, (name, result) in enumerate(self.results.items()):
            if idx >= len(axes):
                break
            
            cm = result['confusion_matrix']
            
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[idx])
            axes[idx].set_title(f'{name}\nAccuracy: {result["metrics"]["accuracy"]:.3f}')
            axes[idx].set_ylabel('True Label')
            axes[idx].set_xlabel('Predicted Label')
            axes[idx].set_xticklabels(['Benign', 'Phishing'])
            axes[idx].set_yticklabels(['Benign', 'Phishing'])
        
        # Hide unused subplots
        for idx in range(len(self.results), len(axes)):
            axes[idx].axis('off')
        
        plt.tight_layout()
        
        save_path = os.path.join(save_dir, 'confusion_matrices.png')
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"\n📊 Confusion matrices saved to: {save_path}")
        plt.close()
    
    def plot_roc_curves(self, y_test, save_dir='reports/figures'):
        """Plot ROC curves for all models"""
        os.makedirs(save_dir, exist_ok=True)
        
        plt.figure(figsize=(10, 8))
        
        for name, result in self.results.items():
            if result['probabilities'] is not None:
                fpr, tpr, _ = roc_curve(y_test, result['probabilities'])
                auc = result['metrics'].get('roc_auc', 0)
                plt.plot(fpr, tpr, label=f'{name} (AUC = {auc:.3f})', linewidth=2)
        
        plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate', fontsize=12)
        plt.ylabel('True Positive Rate', fontsize=12)
        plt.title('ROC Curves - Model Comparison', fontsize=14, fontweight='bold')
        plt.legend(loc="lower right")
        plt.grid(alpha=0.3)
        
        save_path = os.path.join(save_dir, 'roc_curves.png')
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"📊 ROC curves saved to: {save_path}")
        plt.close()
    
    def save_best_model(self, save_dir='models/saved'):
        """Save the best model and scaler"""
        os.makedirs(save_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save model
        model_path = os.path.join(save_dir, f'best_model_{timestamp}.pkl')
        joblib.dump(self.best_model, model_path)
        print(f"\n💾 Best model ({self.best_model_name}) saved to: {model_path}")
        
        # Save scaler
        scaler_path = os.path.join(save_dir, f'scaler_{timestamp}.pkl')
        joblib.dump(self.scaler, scaler_path)
        print(f"💾 Scaler saved to: {scaler_path}")
        
        return model_path, scaler_path
    
    def feature_importance(self, feature_names, top_n=20, save_dir='reports/figures'):
        """Display feature importance for tree-based models"""
        print("\n" + "="*60)
        print("🎯 FEATURE IMPORTANCE")
        print("="*60)
        
        # Check if best model has feature_importances_
        if hasattr(self.best_model, 'feature_importances_'):
            importances = self.best_model.feature_importances_
            
            # Create DataFrame
            feature_imp = pd.DataFrame({
                'Feature': feature_names,
                'Importance': importances
            }).sort_values('Importance', ascending=False)
            
            print(f"\nTop {top_n} Most Important Features:")
            print(feature_imp.head(top_n).to_string(index=False))
            
            # Plot
            os.makedirs(save_dir, exist_ok=True)
            plt.figure(figsize=(10, 8))
            top_features = feature_imp.head(top_n)
            plt.barh(range(len(top_features)), top_features['Importance'])
            plt.yticks(range(len(top_features)), top_features['Feature'])
            plt.xlabel('Importance')
            plt.title(f'Top {top_n} Feature Importances - {self.best_model_name}')
            plt.gca().invert_yaxis()
            plt.tight_layout()
            
            save_path = os.path.join(save_dir, 'feature_importance.png')
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"\n📊 Feature importance plot saved to: {save_path}")
            plt.close()
        else:
            print(f"\n⚠️ {self.best_model_name} doesn't support feature importance")


def main():
    """Main training pipeline"""
    print("="*60)
    print("🎯 PHISHING URL DETECTION - MODEL TRAINING")
    print("="*60)
    
    # Initialize trainer
    trainer = PhishingModelTrainer(random_state=42)
    
    # Find processed data files
    data_dir = "data/processed"
    
    if not os.path.exists(data_dir):
        print(f"❌ Directory not found: {data_dir}")
        print("   Please run build_features.py first!")
        return
    
    csv_files = [f for f in os.listdir(data_dir) if f.endswith('.csv')]
    
    if not csv_files:
        print("❌ No processed data found!")
        print("   Please run build_features.py first!")
        return
    
    print(f"\n📁 Found {len(csv_files)} processed file(s):")
    for i, file in enumerate(csv_files, 1):
        print(f"   {i}. {file}")
    
    # Select file
    if len(csv_files) == 1:
        selected_file = csv_files[0]
        print(f"\n✓ Using: {selected_file}")
    else:
        choice = input("\n👉 Enter file number: ").strip()
        try:
            selected_file = csv_files[int(choice) - 1]
        except:
            print("❌ Invalid choice")
            return
    
    # Load and prepare data
    file_path = os.path.join(data_dir, selected_file)
    
    try:
        X, y, feature_names = trainer.load_data(file_path)
        X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
    except Exception as e:
        print(f"❌ Error loading/preparing data: {e}")
        return
    
    # Initialize and train models
    trainer.initialize_models()
    trainer.train_and_evaluate(X_train, X_test, y_train, y_test)
    
    # Compare and select best model
    comparison_df = trainer.compare_models()
    
    # Visualizations
    try:
        trainer.plot_confusion_matrices()
        trainer.plot_roc_curves(y_test)
        trainer.feature_importance(feature_names)
    except Exception as e:
        print(f"⚠️ Warning: Could not create some visualizations: {e}")
    
    # Save best model
    trainer.save_best_model()
    
    print("\n" + "="*60)
    print("✅ MODEL TRAINING COMPLETE!")
    print("="*60)
    print("\n📍 Next steps:")
    print("   1. Review results in reports/figures/")
    print("   2. Test prediction: python predict_url.py <url>")
    print("   3. Build web app: python app/app.py")


if __name__ == "__main__":
    main()