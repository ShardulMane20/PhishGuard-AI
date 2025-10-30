"""
Data Collection Script for Phishing URL Detection
Downloads phishing and benign URLs from various sources
"""

import pandas as pd
import requests
import os
from datetime import datetime
import time

class URLDataCollector:
    def __init__(self, output_dir="data/raw"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def download_kaggle_dataset(self):
        """
        Download from Kaggle - Phishing URL Dataset
        You'll need Kaggle API setup for this
        """
        print("📥 Downloading Kaggle dataset...")
        print("   Note: This requires Kaggle API setup")
        print("   1. Go to kaggle.com/settings")
        print("   2. Create API token")
        print("   3. Place kaggle.json in ~/.kaggle/")
        print("\n   Run: kaggle datasets download -d shashwatwork/phishing-dataset-for-machine-learning")
        print("   Alternative: Download manually from:")
        print("   https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning")
        
    def download_phishtank(self, save_path=None):
        """
        Download recent phishing URLs from PhishTank
        Note: This gets online verified phishing URLs
        """
        if save_path is None:
            save_path = os.path.join(self.output_dir, "phishtank_urls.csv")
        
        print("\n📥 Downloading from PhishTank...")
        try:
            # PhishTank verified phishing feed
            url = "http://data.phishtank.com/data/online-valid.csv"
            
            print("   Fetching data...")
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                
                # Load and preview
                df = pd.read_csv(save_path)
                print(f"   ✓ Downloaded {len(df)} phishing URLs")
                print(f"   ✓ Saved to: {save_path}")
                
                # Preview
                print("\n   Preview:")
                print(df.head())
                return df
            else:
                print(f"   ✗ Failed: Status code {response.status_code}")
                return None
                
        except Exception as e:
            print(f"   ✗ Error: {e}")
            print("   Note: PhishTank may require registration for bulk downloads")
            return None
    
    def create_sample_dataset(self):
        """
        Create a sample dataset for quick testing
        This is useful when you can't download real data immediately
        """
        print("\n📝 Creating sample dataset for testing...")
        
        # Sample phishing URLs (examples - not real)
        phishing_urls = [
            "http://secure-paypal-verify.com/login",
            "https://192.168.1.1/banking",
            "http://www.bankofamerica-secure.tk/signin",
            "http://apple-id-verify.info/account/update",
            "https://www.amazon-account-verify.net/ap/signin",
            "http://netflix.com.secure-login.tk",
            "http://www.paypal.com-secure.ml",
            "https://microsoft-account-verify.info",
            "http://google-account-security.tk",
            "http://facebook-security-check.ga",
        ] * 50  # Repeat to get 500 samples
        
        # Sample benign URLs
        benign_urls = [
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.amazon.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.youtube.com",
            "https://www.wikipedia.org",
            "https://www.reddit.com",
            "https://www.twitter.com",
            "https://www.linkedin.com",
        ] * 50  # Repeat to get 500 samples
        
        # Create DataFrames
        df_phishing = pd.DataFrame({
            'url': phishing_urls,
            'label': 1  # 1 = phishing
        })
        
        df_benign = pd.DataFrame({
            'url': benign_urls,
            'label': 0  # 0 = benign
        })
        
        # Combine
        df_combined = pd.concat([df_phishing, df_benign], ignore_index=True)
        df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
        
        # Save
        output_path = os.path.join(self.output_dir, "sample_urls.csv")
        df_combined.to_csv(output_path, index=False)
        
        print(f"   ✓ Created {len(df_combined)} sample URLs")
        print(f"   ✓ Phishing: {len(df_phishing)}, Benign: {len(df_benign)}")
        print(f"   ✓ Saved to: {output_path}")
        
        return df_combined
    
    def download_alexa_top_sites(self):
        """
        Get benign URLs from common legitimate sites
        """
        print("\n📥 Creating benign URL list...")
        
        # Top legitimate websites
        benign_domains = [
            "google.com", "youtube.com", "facebook.com", "twitter.com",
            "instagram.com", "linkedin.com", "wikipedia.org", "amazon.com",
            "ebay.com", "reddit.com", "netflix.com", "microsoft.com",
            "apple.com", "github.com", "stackoverflow.com", "medium.com",
            "dropbox.com", "zoom.us", "slack.com", "adobe.com",
        ]
        
        benign_urls = []
        for domain in benign_domains:
            benign_urls.extend([
                f"https://www.{domain}",
                f"https://{domain}",
                f"https://www.{domain}/about",
                f"https://www.{domain}/contact",
                f"https://www.{domain}/help",
            ])
        
        df_benign = pd.DataFrame({
            'url': benign_urls,
            'label': 0
        })
        
        output_path = os.path.join(self.output_dir, "benign_urls.csv")
        df_benign.to_csv(output_path, index=False)
        
        print(f"   ✓ Created {len(df_benign)} benign URLs")
        print(f"   ✓ Saved to: {output_path}")
        
        return df_benign
    
    def load_custom_dataset(self, file_path):
        """
        Load a custom dataset if you've downloaded one manually
        """
        print(f"\n📂 Loading custom dataset from {file_path}...")
        try:
            df = pd.read_csv(file_path)
            print(f"   ✓ Loaded {len(df)} URLs")
            print(f"\n   Columns: {df.columns.tolist()}")
            print(f"\n   Preview:")
            print(df.head())
            return df
        except Exception as e:
            print(f"   ✗ Error: {e}")
            return None
    
    def generate_summary_report(self):
        """
        Generate a summary of downloaded data
        """
        print("\n" + "="*60)
        print("📊 DATA COLLECTION SUMMARY")
        print("="*60)
        
        if not os.path.exists(self.output_dir):
            print("   No data directory found!")
            return
            
        files = os.listdir(self.output_dir)
        csv_files = [f for f in files if f.endswith('.csv')]
        
        if not csv_files:
            print("   No data files found!")
            return
        
        for file in csv_files:
            file_path = os.path.join(self.output_dir, file)
            df = pd.read_csv(file_path)
            
            print(f"\n📁 {file}")
            print(f"   Rows: {len(df)}")
            print(f"   Columns: {df.columns.tolist()}")
            
            if 'label' in df.columns:
                print(f"   Distribution:")
                print(f"      - Benign (0): {(df['label']==0).sum()}")
                print(f"      - Phishing (1): {(df['label']==1).sum()}")

def main():
    """Main execution"""
    print("="*60)
    print("🎯 PHISHING URL DATA COLLECTION")
    print("="*60)
    
    collector = URLDataCollector()
    
    print("\n📋 Available options:")
    print("   1. Create sample dataset (for quick testing)")
    print("   2. Download from PhishTank")
    print("   3. Create benign URLs list")
    print("   4. Load custom dataset")
    print("   5. Download instructions for Kaggle")
    
    choice = input("\n👉 Enter choice (1-5): ").strip()
    
    if choice == "1":
        collector.create_sample_dataset()
    elif choice == "2":
        collector.download_phishtank()
    elif choice == "3":
        collector.download_alexa_top_sites()
    elif choice == "4":
        path = input("Enter file path: ").strip()
        collector.load_custom_dataset(path)
    elif choice == "5":
        collector.download_kaggle_dataset()
    else:
        print("❌ Invalid choice")
        return
    
    # Generate summary
    collector.generate_summary_report()
    
    print("\n" + "="*60)
    print("✅ Data collection complete!")
    print("="*60)
    print("\n📍 Next steps:")
    print("   1. Review downloaded data in data/raw/")
    print("   2. Run feature extraction: python src/features/build_features.py")

if __name__ == "__main__":
    main()