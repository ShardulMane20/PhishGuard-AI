"""
Feature Engineering for Phishing URL Detection
Extracts lexical, domain, and network features from URLs
"""

import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import tldextract
import os

class URLFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'submit', 'account', 'banking', 'secure',
            'update', 'verify', 'confirm', 'password', 'credential',
            'ebay', 'paypal', 'amazon', 'netflix', 'microsoft', 'apple'
        ]
    
    def extract_all_features(self, url):
        """
        Extract all features from a single URL
        Returns a dictionary of features
        """
        features = {}
        
        # Lexical features
        features.update(self._lexical_features(url))
        
        # Domain features
        features.update(self._domain_features(url))
        
        # Network features
        features.update(self._network_features(url))
        
        return features
    
    def _lexical_features(self, url):
        """Extract lexical features from URL string"""
        features = {}
        
        # Basic length and character counts
        features['url_length'] = len(url)
        features['hostname_length'] = len(urlparse(url).netloc)
        
        # Character counts
        features['count_dot'] = url.count('.')
        features['count_slash'] = url.count('/')
        features['count_dash'] = url.count('-')
        features['count_at'] = url.count('@')
        features['count_question'] = url.count('?')
        features['count_ampersand'] = url.count('&')
        features['count_equal'] = url.count('=')
        features['count_underscore'] = url.count('_')
        features['count_tilde'] = url.count('~')
        features['count_percent'] = url.count('%')
        
        # Digit and letter counts
        features['count_digits'] = sum(c.isdigit() for c in url)
        features['count_letters'] = sum(c.isalpha() for c in url)
        
        # Ratios
        if features['url_length'] > 0:
            features['ratio_digits'] = features['count_digits'] / features['url_length']
            features['ratio_letters'] = features['count_letters'] / features['url_length']
        else:
            features['ratio_digits'] = 0
            features['ratio_letters'] = 0
        
        # Protocol features
        features['has_https'] = 1 if url.startswith('https://') else 0
        features['has_http'] = 1 if url.startswith('http://') else 0
        
        # Check for IP address instead of domain name
        ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        # Suspicious keywords
        url_lower = url.lower()
        features['suspicious_keywords_count'] = sum(
            1 for keyword in self.suspicious_keywords if keyword in url_lower
        )
        
        # Check for URL shortening services
        shortening_services = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly']
        features['is_shortened'] = 1 if any(service in url_lower for service in shortening_services) else 0
        
        # Check for excessive special characters (potential obfuscation)
        special_chars = sum(1 for c in url if not c.isalnum() and c not in [':', '/', '.', '-'])
        features['special_char_count'] = special_chars
        
        return features
    
    def _domain_features(self, url):
        """Extract domain-based features"""
        features = {}
        
        try:
            # Parse domain using tldextract
            extracted = tldextract.extract(url)
            
            # Domain components
            features['domain_length'] = len(extracted.domain)
            features['subdomain_length'] = len(extracted.subdomain)
            features['tld_length'] = len(extracted.suffix)
            
            # Count subdomains
            if extracted.subdomain:
                features['subdomain_count'] = len(extracted.subdomain.split('.'))
            else:
                features['subdomain_count'] = 0
            
            # Check for suspicious TLDs
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work']
            features['suspicious_tld'] = 1 if extracted.suffix.lower() in suspicious_tlds else 0
            
            # Domain contains digits
            features['domain_has_digits'] = 1 if any(c.isdigit() for c in extracted.domain) else 0
            
            # Domain contains hyphens
            features['domain_has_hyphen'] = 1 if '-' in extracted.domain else 0
            
        except Exception as e:
            # If parsing fails, set default values
            features['domain_length'] = 0
            features['subdomain_length'] = 0
            features['tld_length'] = 0
            features['subdomain_count'] = 0
            features['suspicious_tld'] = 0
            features['domain_has_digits'] = 0
            features['domain_has_hyphen'] = 0
        
        return features
    
    def _network_features(self, url):
        """Extract network and path-based features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            
            # Path features
            path = parsed.path
            features['path_length'] = len(path)
            features['path_depth'] = len([p for p in path.split('/') if p])
            
            # Query parameters
            query = parsed.query
            features['query_length'] = len(query)
            features['param_count'] = len(query.split('&')) if query else 0
            
            # Fragment
            features['has_fragment'] = 1 if parsed.fragment else 0
            
            # Port (non-standard ports are suspicious)
            if parsed.port:
                features['has_port'] = 1
                features['is_standard_port'] = 1 if parsed.port in [80, 443] else 0
            else:
                features['has_port'] = 0
                features['is_standard_port'] = 1
            
        except Exception as e:
            features['path_length'] = 0
            features['path_depth'] = 0
            features['query_length'] = 0
            features['param_count'] = 0
            features['has_fragment'] = 0
            features['has_port'] = 0
            features['is_standard_port'] = 1
        
        return features
    
    def process_dataframe(self, df, url_column='url'):
        """
        Process a DataFrame of URLs and extract features for all
        
        Args:
            df: DataFrame with URLs
            url_column: Name of the column containing URLs
        
        Returns:
            DataFrame with extracted features
        """
        print(f"🔧 Extracting features from {len(df)} URLs...")
        
        features_list = []
        
        for idx, url in enumerate(df[url_column]):
            if idx % 100 == 0:
                print(f"   Progress: {idx}/{len(df)} ({idx/len(df)*100:.1f}%)", end='\r')
            
            try:
                features = self.extract_all_features(url)
                features['url'] = url  # Keep original URL
                
                # Add label if exists
                if 'label' in df.columns:
                    features['label'] = df.loc[idx, 'label']
                
                features_list.append(features)
                
            except Exception as e:
                print(f"\n   ⚠️ Error processing URL {idx}: {e}")
                continue
        
        print(f"\n   ✓ Feature extraction complete!")
        
        # Create DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Reorder columns: move 'url' and 'label' to the end
        cols = [c for c in features_df.columns if c not in ['url', 'label']]
        if 'label' in features_df.columns:
            cols = cols + ['label', 'url']
        else:
            cols = cols + ['url']
        
        features_df = features_df[cols]
        
        return features_df
    
    def get_feature_names(self):
        """Return list of all feature names"""
        dummy_features = self.extract_all_features("https://example.com")
        return [k for k in dummy_features.keys()]
    
    def print_feature_summary(self, features_df):
        """Print summary statistics of extracted features"""
        print("\n" + "="*60)
        print("📊 FEATURE SUMMARY")
        print("="*60)
        
        # Exclude non-numeric columns
        numeric_cols = features_df.select_dtypes(include=[np.number]).columns
        numeric_cols = [c for c in numeric_cols if c != 'label']
        
        print(f"\nTotal features: {len(numeric_cols)}")
        print(f"Total URLs processed: {len(features_df)}")
        
        if 'label' in features_df.columns:
            print(f"\nClass distribution:")
            print(f"   Benign (0): {(features_df['label']==0).sum()}")
            print(f"   Phishing (1): {(features_df['label']==1).sum()}")
        
        print(f"\nFeature statistics:")
        print(features_df[numeric_cols].describe().T[['mean', 'std', 'min', 'max']])


def main():
    """Main execution for feature extraction"""
    print("="*60)
    print("🎯 FEATURE EXTRACTION FOR PHISHING DETECTION")
    print("="*60)
    
    # Initialize extractor
    extractor = URLFeatureExtractor()
    
    # Input/output paths - FIXED
    input_dir = "data/raw"
    output_dir = "data/processed"
    os.makedirs(output_dir, exist_ok=True)
    
    # Check if input directory exists
    if not os.path.exists(input_dir):
        print(f"❌ Directory not found: {input_dir}")
        print("   Please run collect_data.py first!")
        return
    
    # Find CSV files in raw data directory
    csv_files = [f for f in os.listdir(input_dir) if f.endswith('.csv')]
    
    if not csv_files:
        print("❌ No CSV files found in data/raw/")
        print("   Please run collect_data.py first!")
        return
    
    print(f"\n📁 Found {len(csv_files)} data file(s):")
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
    
    # Load data
    input_path = os.path.join(input_dir, selected_file)
    print(f"\n📂 Loading data from {input_path}...")
    
    try:
        df = pd.read_csv(input_path)
        print(f"   ✓ Loaded {len(df)} URLs")
    except Exception as e:
        print(f"   ❌ Error loading file: {e}")
        return
    
    # Extract features
    features_df = extractor.process_dataframe(df)
    
    # Print summary
    extractor.print_feature_summary(features_df)
    
    # Save processed data
    output_filename = selected_file.replace('.csv', '_features.csv')
    output_path = os.path.join(output_dir, output_filename)
    
    features_df.to_csv(output_path, index=False)
    print(f"\n💾 Saved features to: {output_path}")
    
    print("\n" + "="*60)
    print("✅ Feature extraction complete!")
    print("="*60)
    print("\n📍 Next steps:")
    print("   1. Review features in data/processed/")
    print("   2. Run model training: python src/models/train_model.py")


if __name__ == "__main__":
    main()