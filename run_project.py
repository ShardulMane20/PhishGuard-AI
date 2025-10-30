"""
Quick start script to run the entire pipeline
"""

import os
import sys
import subprocess

def verify_project_structure():
    """Verify that necessary directories exist"""
    required_dirs = [
        'data/raw',
        'data/processed',
        'models/saved',
        'reports/figures',
        'src/data',
        'src/features',
        'src/models',
    ]
    
    missing_dirs = []
    for directory in required_dirs:
        if not os.path.exists(directory):
            missing_dirs.append(directory)
    
    if missing_dirs:
        print("⚠️  Warning: Some directories are missing:")
        for d in missing_dirs:
            print(f"   - {d}")
        response = input("\nCreate missing directories? (y/n): ")
        if response.lower() == 'y':
            for d in missing_dirs:
                os.makedirs(d, exist_ok=True)
                print(f"   ✓ Created: {d}")
        else:
            print("❌ Cannot proceed without proper structure")
            sys.exit(1)
    else:
        print("✓ Project structure verified!")

def run_command(command, description):
    """Run a command and handle errors"""
    print("\n" + "="*70)
    print(f"▶️  {description}")
    print("="*70)
    
    result = subprocess.run(command, shell=True)
    
    if result.returncode != 0:
        print(f"\n❌ Error running: {description}")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    return result.returncode == 0

def cleanup_temp_files():
    """Remove temporary script files"""
    temp_files = ['_temp_collect.py', '_temp_extract.py', '_temp_train.py']
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass

def main():
    print("="*70)
    print("🚀 PHISHING URL DETECTION - FULL PIPELINE")
    print("="*70)
    
    print("\nThis script will:")
    print("  1. Verify project structure")
    print("  2. Collect sample data")
    print("  3. Extract features")
    print("  4. Train models")
    print("  5. Test prediction")
    
    response = input("\nProceed? (y/n): ")
    if response.lower() != 'y':
        print("Cancelled.")
        return
    
    try:
        # 1. Verify structure
        print("\n" + "="*70)
        print("▶️  Verifying project structure")
        print("="*70)
        verify_project_structure()
        
        # 2. Collect data (using option 1 for sample dataset)
        print("\n" + "="*70)
        print("▶️  Collecting sample data")
        print("="*70)
        print("   Creating sample dataset...")
        
        collect_script = """
import sys
sys.path.insert(0, 'src/data')
from collect_data import URLDataCollector

collector = URLDataCollector()
collector.create_sample_dataset()
collector.generate_summary_report()
"""
        
        with open('_temp_collect.py', 'w', encoding='utf-8') as f:
            f.write(collect_script)
        
        run_command("python _temp_collect.py", "Collecting data")
        
        # 3. Extract features (auto-select first file)
        print("\n" + "="*70)
        print("▶️  Extracting features")
        print("="*70)
        
        extract_script = """
import sys
import os
sys.path.insert(0, 'src/features')
from build_features import URLFeatureExtractor
import pandas as pd

extractor = URLFeatureExtractor()
input_dir = "data/raw"
output_dir = "data/processed"

csv_files = [f for f in os.listdir(input_dir) if f.endswith('.csv')]
if csv_files:
    selected_file = csv_files[0]
    input_path = os.path.join(input_dir, selected_file)
    print(f"   Loading: {input_path}")
    df = pd.read_csv(input_path)
    features_df = extractor.process_dataframe(df)
    output_path = os.path.join(output_dir, selected_file.replace('.csv', '_features.csv'))
    features_df.to_csv(output_path, index=False)
    print(f"\\n   Features saved to: {output_path}")
else:
    print("   No CSV files found in data/raw/")
"""
        
        with open('_temp_extract.py', 'w', encoding='utf-8') as f:
            f.write(extract_script)
        
        run_command("python _temp_extract.py", "Extracting features")
        
        # 4. Train models
        print("\n" + "="*70)
        print("▶️  Training models")
        print("="*70)
        
        train_script = """
import sys
import os
sys.path.insert(0, 'src/models')
from train_model import PhishingModelTrainer

trainer = PhishingModelTrainer(random_state=42)
data_dir = "data/processed"
csv_files = [f for f in os.listdir(data_dir) if f.endswith('.csv')]

if csv_files:
    file_path = os.path.join(data_dir, csv_files[0])
    X, y, feature_names = trainer.load_data(file_path)
    X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
    trainer.initialize_models()
    trainer.train_and_evaluate(X_train, X_test, y_train, y_test)
    trainer.compare_models()
    try:
        trainer.plot_confusion_matrices()
        trainer.plot_roc_curves(y_test)
        trainer.feature_importance(feature_names)
    except Exception as e:
        print(f"Warning: Could not create visualizations: {e}")
    trainer.save_best_model()
    print("\\nTraining complete!")
else:
    print("No CSV files found in data/processed/")
"""
        
        with open('_temp_train.py', 'w', encoding='utf-8') as f:
            f.write(train_script)
        
        run_command("python _temp_train.py", "Training models")
        
        # 5. Test prediction
        print("\n" + "="*70)
        print("▶️  Testing prediction")
        print("="*70)
        
        test_urls = [
            "https://www.google.com",
            "http://secure-paypal-verify.tk",
            "https://192.168.1.1/banking"
        ]
        
        for url in test_urls:
            print(f"\n   Testing: {url}")
            run_command(f'python predict_url.py "{url}"', f"Predicting: {url}")
        
        print("\n" + "="*70)
        print("✅ PIPELINE COMPLETE!")
        print("="*70)
        print("\n📊 Results:")
        print("   - Data: data/raw/")
        print("   - Features: data/processed/")
        print("   - Models: models/saved/")
        print("   - Figures: reports/figures/")
        print("\n📍 Test any URL:")
        print("   python predict_url.py <your_url>")
        print("\n💡 Tips:")
        print("   - Test batch URLs: python predict_url.py --file urls.txt")
        print("   - View training plots: check reports/figures/")
        print("   - Retrain with new data: python src/models/train_model.py")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Pipeline interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup temporary files
        print("\n🧹 Cleaning up temporary files...")
        cleanup_temp_files()

if __name__ == "__main__":
    main()