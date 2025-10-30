"""
Flask Web Application for Phishing URL Detection
Provides REST API and serves frontend
"""

import sys
import os
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
from src.features.build_features import URLFeatureExtractor

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

class PhishingDetector:
    """Main detector class"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.extractor = URLFeatureExtractor()
        self.load_model()
    
    def load_model(self):
        """Load trained model and scaler"""
        model_dir = Path(__file__).parent.parent / 'models' / 'saved'
        
        if not model_dir.exists():
            raise FileNotFoundError("Models directory not found!")
        
        # Find latest model and scaler
        model_files = list(model_dir.glob('best_model_*.pkl'))
        scaler_files = list(model_dir.glob('scaler_*.pkl'))
        
        if not model_files or not scaler_files:
            raise FileNotFoundError("Model files not found!")
        
        latest_model = sorted(model_files)[-1]
        latest_scaler = sorted(scaler_files)[-1]
        
        self.model = joblib.load(latest_model)
        self.scaler = joblib.load(latest_scaler)
        
        print(f"✓ Loaded model: {latest_model.name}")
        print(f"✓ Loaded scaler: {latest_scaler.name}")
    
    def analyze_url(self, url):
        """Analyze a single URL"""
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Extract features
            features_dict = self.extractor.extract_all_features(url)
            
            # Convert to array
            X = pd.DataFrame([features_dict]).values
            
            # Scale
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            # Analyze features for insights
            insights = self._generate_insights(features_dict)
            
            return {
                'success': True,
                'url': url,
                'prediction': int(prediction),
                'prediction_label': 'Phishing' if prediction == 1 else 'Benign',
                'confidence': float(probabilities[prediction]) * 100,
                'probabilities': {
                    'benign': float(probabilities[0]) * 100,
                    'phishing': float(probabilities[1]) * 100
                },
                'risk_level': self._get_risk_level(probabilities[1]),
                'insights': insights,
                'features': features_dict,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'url': url
            }
    
    def _get_risk_level(self, phishing_prob):
        """Determine risk level based on probability"""
        if phishing_prob >= 0.8:
            return {'level': 'critical', 'label': 'Critical', 'color': '#dc3545'}
        elif phishing_prob >= 0.6:
            return {'level': 'high', 'label': 'High', 'color': '#fd7e14'}
        elif phishing_prob >= 0.4:
            return {'level': 'medium', 'label': 'Medium', 'color': '#ffc107'}
        elif phishing_prob >= 0.2:
            return {'level': 'low', 'label': 'Low', 'color': '#20c997'}
        else:
            return {'level': 'safe', 'label': 'Safe', 'color': '#28a745'}
    
    def _generate_insights(self, features):
        """Generate human-readable insights from features"""
        insights = {
            'suspicious': [],
            'safe': [],
            'neutral': []
        }
        
        # Check suspicious indicators
        if features.get('has_ip', 0) == 1:
            insights['suspicious'].append({
                'text': 'URL contains IP address instead of domain name',
                'severity': 'high'
            })
        
        if features.get('suspicious_keywords_count', 0) > 0:
            insights['suspicious'].append({
                'text': f"Contains {features['suspicious_keywords_count']} suspicious keyword(s)",
                'severity': 'medium'
            })
        
        if features.get('url_length', 0) > 75:
            insights['suspicious'].append({
                'text': f"Unusually long URL ({features['url_length']} characters)",
                'severity': 'medium'
            })
        
        if features.get('subdomain_count', 0) > 3:
            insights['suspicious'].append({
                'text': f"Multiple subdomains detected ({features['subdomain_count']})",
                'severity': 'medium'
            })
        
        if features.get('suspicious_tld', 0) == 1:
            insights['suspicious'].append({
                'text': 'Suspicious top-level domain (TLD)',
                'severity': 'high'
            })
        
        if features.get('count_at', 0) > 0:
            insights['suspicious'].append({
                'text': 'Contains @ symbol (possible obfuscation)',
                'severity': 'high'
            })
        
        if features.get('has_https', 0) == 0:
            insights['suspicious'].append({
                'text': 'No HTTPS encryption',
                'severity': 'low'
            })
        
        # Check safe indicators
        if features.get('has_https', 0) == 1:
            insights['safe'].append({
                'text': 'HTTPS encryption enabled',
                'icon': 'lock'
            })
        
        if features.get('domain_has_hyphen', 0) == 0:
            insights['safe'].append({
                'text': 'No hyphens in domain',
                'icon': 'check'
            })
        
        if features.get('url_length', 0) < 50:
            insights['safe'].append({
                'text': 'Reasonable URL length',
                'icon': 'check'
            })
        
        # Neutral info
        insights['neutral'].append({
            'text': f"URL length: {features.get('url_length', 0)} characters"
        })
        
        insights['neutral'].append({
            'text': f"Domain length: {features.get('domain_length', 0)} characters"
        })
        
        return insights

# Initialize detector
try:
    detector = PhishingDetector()
    print("✅ Phishing detector initialized successfully!")
except Exception as e:
    print(f"❌ Error initializing detector: {e}")
    detector = None

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/batch')
def batch():
    """Batch checking page"""
    return render_template('batch.html')

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/api/check', methods=['POST'])
def check_url():
    """API endpoint to check a single URL"""
    if detector is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 500
    
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'success': False,
            'error': 'No URL provided'
        }), 400
    
    url = data['url'].strip()
    
    if not url:
        return jsonify({
            'success': False,
            'error': 'Empty URL'
        }), 400
    
    result = detector.analyze_url(url)
    return jsonify(result)

@app.route('/api/check-batch', methods=['POST'])
def check_batch():
    """API endpoint to check multiple URLs"""
    if detector is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 500
    
    data = request.get_json()
    
    if not data or 'urls' not in data:
        return jsonify({
            'success': False,
            'error': 'No URLs provided'
        }), 400
    
    urls = data['urls']
    
    if not isinstance(urls, list):
        return jsonify({
            'success': False,
            'error': 'URLs must be a list'
        }), 400
    
    if len(urls) > 100:
        return jsonify({
            'success': False,
            'error': 'Maximum 100 URLs allowed'
        }), 400
    
    results = []
    for url in urls:
        url = url.strip()
        if url:
            result = detector.analyze_url(url)
            results.append(result)
    
    # Calculate summary
    summary = {
        'total': len(results),
        'benign': sum(1 for r in results if r.get('prediction') == 0),
        'phishing': sum(1 for r in results if r.get('prediction') == 1),
        'errors': sum(1 for r in results if not r.get('success', True))
    }
    
    return jsonify({
        'success': True,
        'results': results,
        'summary': summary
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get model statistics"""
    if detector is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 500
    
    return jsonify({
        'success': True,
        'model_type': type(detector.model).__name__,
        'features_count': len(detector.extractor.get_feature_names()),
        'status': 'online'
    })

@app.errorhandler(413)
def too_large(e):
    return jsonify({
        'success': False,
        'error': 'File too large (max 16MB)'
    }), 413

@app.errorhandler(404)
def not_found(e):
    return render_template('index.html'), 404

if __name__ == '__main__':
    print("="*60)
    print("🛡️  PHISHING URL DETECTOR - Web Application")
    print("="*60)
    print("\n🌐 Starting server...")
    print("📍 Open your browser and navigate to:")
    print("   👉 http://localhost:5000")
    print("\n⌨️  Press Ctrl+C to stop the server")
    print("="*60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)