"""
Command Line Interface for Phishing URL Prediction
Quick tool to test URLs from terminal
"""

import sys
import os
import joblib
import pandas as pd
from pathlib import Path

# Add src to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir / 'src'))

try:
    from features.build_features import URLFeatureExtractor
except ImportError:
    print("❌ Error: Could not import URLFeatureExtractor")
    print("   Make sure the src/features/build_features.py file exists")
    sys.exit(1)


class URLPredictor:
    """Simple CLI predictor for URLs"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.extractor = URLFeatureExtractor()
        self.feature_names = None
        self.load_model()
    
    def load_model(self):
        """Load the trained model and scaler"""
        model_dir = Path(__file__).parent / 'models' / 'saved'
        
        if not model_dir.exists():
            raise FileNotFoundError(
                f"Models directory not found at: {model_dir}\n"
                "Please train the model first by running:\n"
                "  python src/models/train_model.py"
            )
        
        # Find latest model and scaler
        model_files = list(model_dir.glob('best_model_*.pkl'))
        scaler_files = list(model_dir.glob('scaler_*.pkl'))
        
        if not model_files or not scaler_files:
            raise FileNotFoundError(
                "Model or scaler not found!\n"
                "Please train the model first by running:\n"
                "  python src/models/train_model.py"
            )
        
        # Load latest
        latest_model = sorted(model_files)[-1]
        latest_scaler = sorted(scaler_files)[-1]
        
        print(f"📦 Loading model: {latest_model.name}")
        print(f"📦 Loading scaler: {latest_scaler.name}")
        
        self.model = joblib.load(latest_model)
        self.scaler = joblib.load(latest_scaler)
        
        # Get feature names from a dummy extraction
        dummy_features = self.extractor.extract_all_features("https://example.com")
        self.feature_names = list(dummy_features.keys())
        
        print("✓ Model loaded successfully!\n")
    
    def predict(self, url):
        """Predict a single URL"""
        try:
            # Extract features
            features_dict = self.extractor.extract_all_features(url)
            
            # Ensure features are in the correct order
            features_ordered = [features_dict.get(name, 0) for name in self.feature_names]
            
            # Convert to array
            X = np.array([features_ordered])
            
            # Scale
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X_scaled)[0]
            
            # Get probabilities if available
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(X_scaled)[0]
            else:
                # For models without predict_proba, use binary prediction
                probabilities = [1-prediction, prediction]
            
            return {
                'prediction': int(prediction),
                'benign_prob': float(probabilities[0]),
                'phishing_prob': float(probabilities[1]),
                'features': features_dict
            }
            
        except Exception as e:
            import traceback
            return {'error': f"{str(e)}\n{traceback.format_exc()}"}
    
    def print_result(self, url, result):
        """Print prediction result in a formatted way"""
        print("="*70)
        print(f"🔍 URL: {url}")
        print("="*70)
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            return
        
        prediction = result['prediction']
        phishing_prob = result['phishing_prob']
        benign_prob = result['benign_prob']
        
        # Print prediction
        if prediction == 1:
            print("⚠️  PREDICTION: PHISHING")
            print(f"🎯 Confidence: {phishing_prob*100:.2f}%")
            print("⚠️  WARNING: This URL appears to be malicious!")
        else:
            print("✅ PREDICTION: BENIGN")
            print(f"🎯 Confidence: {benign_prob*100:.2f}%")
            print("✓  This URL appears to be safe")
        
        print("\n📊 Probabilities:")
        print(f"   Benign:   {benign_prob*100:.2f}%")
        print(f"   Phishing: {phishing_prob*100:.2f}%")
        
        # Print key features
        features = result['features']
        print("\n🔎 Key Features Detected:")
        
        suspicious_indicators = []
        safe_indicators = []
        
        # Check suspicious features
        if features.get('has_ip', 0) == 1:
            suspicious_indicators.append("IP address in URL")
        
        if features.get('suspicious_keywords_count', 0) > 0:
            suspicious_indicators.append(f"Suspicious keywords ({features['suspicious_keywords_count']})")
        
        if features.get('url_length', 0) > 75:
            suspicious_indicators.append(f"Long URL ({features['url_length']} chars)")
        
        if features.get('subdomain_count', 0) > 3:
            suspicious_indicators.append(f"Many subdomains ({features['subdomain_count']})")
        
        if features.get('suspicious_tld', 0) == 1:
            suspicious_indicators.append("Suspicious TLD")
        
        if features.get('count_at', 0) > 0:
            suspicious_indicators.append("Contains @ symbol")
        
        # Check safe features
        if features.get('has_https', 0) == 1:
            safe_indicators.append("HTTPS enabled")
        else:
            suspicious_indicators.append("No HTTPS")
        
        if features.get('domain_has_hyphen', 0) == 0:
            safe_indicators.append("No hyphens in domain")
        
        # Print indicators
        if suspicious_indicators:
            print("\n   ⚠️  Suspicious Indicators:")
            for indicator in suspicious_indicators:
                print(f"      • {indicator}")
        
        if safe_indicators:
            print("\n   ✓  Safe Indicators:")
            for indicator in safe_indicators:
                print(f"      • {indicator}")
        
        print("\n" + "="*70)
    
    def batch_predict(self, urls):
        """Predict multiple URLs"""
        results = []
        
        print(f"\n🔄 Processing {len(urls)} URLs...\n")
        
        for i, url in enumerate(urls, 1):
            print(f"[{i}/{len(urls)}] Analyzing: {url[:50]}...")
            result = self.predict(url)
            results.append((url, result))
        
        return results
    
    def print_batch_results(self, results):
        """Print batch results summary"""
        print("\n" + "="*70)
        print("📊 BATCH PREDICTION SUMMARY")
        print("="*70)
        
        phishing_count = 0
        benign_count = 0
        error_count = 0
        
        print("\n{:<50} {:<15} {:<10}".format("URL", "Prediction", "Confidence"))
        print("-"*70)
        
        for url, result in results:
            if 'error' in result:
                print(f"{url[:47]:<50} {'ERROR':<15} {'-':<10}")
                error_count += 1
            else:
                pred = "PHISHING" if result['prediction'] == 1 else "BENIGN"
                conf = result['phishing_prob'] if result['prediction'] == 1 else result['benign_prob']
                
                # Icon
                icon = "⚠️ " if result['prediction'] == 1 else "✅"
                
                print(f"{icon} {url[:45]:<48} {pred:<15} {conf*100:.1f}%")
                
                if result['prediction'] == 1:
                    phishing_count += 1
                else:
                    benign_count += 1
        
        print("\n" + "="*70)
        print(f"Total URLs: {len(results)}")
        print(f"✅ Benign: {benign_count}")
        print(f"⚠️  Phishing: {phishing_count}")
        if error_count > 0:
            print(f"❌ Errors: {error_count}")
        print("="*70)


# Import numpy here
import numpy as np


def main():
    """Main CLI interface"""
    print("="*70)
    print("🛡️  PHISHING URL DETECTOR - Command Line Tool")
    print("="*70)
    
    # Check for arguments
    if len(sys.argv) < 2:
        print("\n📋 Usage:")
        print("   Single URL:  python predict_url.py <url>")
        print("   Batch file:  python predict_url.py --file <filepath>")
        print("\n📝 Examples:")
        print("   python predict_url.py https://google.com")
        print("   python predict_url.py http://secure-bank-login.tk")
        print("   python predict_url.py --file urls.txt")
        print("\n💡 The file should contain one URL per line")
        return
    
    try:
        # Initialize predictor
        predictor = URLPredictor()
        
        # Check if batch mode
        if sys.argv[1] in ['--file', '-f']:
            if len(sys.argv) < 3:
                print("❌ Error: Please provide filepath")
                return
            
            filepath = sys.argv[2]
            
            if not os.path.exists(filepath):
                print(f"❌ Error: File not found: {filepath}")
                return
            
            # Read URLs from file
            with open(filepath, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                print("❌ Error: No URLs found in file")
                return
            
            # Batch predict
            results = predictor.batch_predict(urls)
            predictor.print_batch_results(results)
            
        else:
            # Single URL mode
            url = sys.argv[1]
            
            # Add http:// if no protocol
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Predict
            result = predictor.predict(url)
            predictor.print_result(url, result)
        
        print("\n✅ Analysis complete!")
        
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
    
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()