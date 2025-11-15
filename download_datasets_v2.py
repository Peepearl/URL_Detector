"""
Enhanced script to download and process phishing datasets from multiple sources
"""

import os
import pandas as pd
import requests
import json
from pathlib import Path
import zipfile
import gzip
from urllib.parse import urlparse
import time

DATA_DIR = "data"
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")

os.makedirs(RAW_DATA_DIR, exist_ok=True)
os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

def download_file(url, output_path, description=""):
    """Download a file from URL."""
    print(f"Downloading {description}...")
    print(f"  URL: {url}")
    
    try:
        response = requests.get(url, stream=True, timeout=60, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r  Progress: {percent:.1f}%", end='', flush=True)
        
        print(f"\n  ✓ Downloaded successfully")
        return True
    except Exception as e:
        print(f"\n  ✗ Download failed: {str(e)}")
        return False

def download_huggingface_alternative():
    """Try alternative methods to get Hugging Face dataset"""
    print("\n" + "="*60)
    print("Hugging Face Dataset (Alternative Method)")
    print("="*60)
    
    # Try direct API access
    try:
        from huggingface_hub import hf_hub_download
        print("Attempting to download via Hugging Face Hub...")
        
        # Try to download the dataset files directly
        repo_id = "ealvaradob/phishing-dataset"
        
        # List files in the repo
        from huggingface_hub import list_repo_files
        files = list_repo_files(repo_id)
        print(f"Found {len(files)} files in repository")
        
        # Download CSV or JSON files
        for file in files:
            if file.endswith(('.csv', '.json', '.parquet')):
                try:
                    local_path = hf_hub_download(repo_id=repo_id, filename=file, local_dir=RAW_DATA_DIR)
                    print(f"✓ Downloaded {file}")
                    return local_path
                except Exception as e:
                    print(f"  Could not download {file}: {str(e)}")
        
    except ImportError:
        print("⚠️  huggingface_hub not installed. Install with: pip install huggingface_hub")
    except Exception as e:
        print(f"✗ Error: {str(e)}")
    
    return None

def get_legitimate_urls():
    """Get legitimate URLs from common sources"""
    print("\n" + "="*60)
    print("Collecting Legitimate URLs")
    print("="*60)
    
    # List of legitimate URLs from top websites
    legitimate_urls = [
        # Tech companies
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.wikipedia.org",
        "https://www.youtube.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.reddit.com",
        "https://www.instagram.com",
        "https://www.pinterest.com",
        "https://www.tumblr.com",
        "https://www.medium.com",
        "https://www.quora.com",
        "https://www.discord.com",
        # News
        "https://www.bbc.com",
        "https://www.cnn.com",
        "https://www.reuters.com",
        "https://www.theguardian.com",
        "https://www.nytimes.com",
        # E-commerce
        "https://www.ebay.com",
        "https://www.alibaba.com",
        "https://www.shopify.com",
        "https://www.etsy.com",
        # Education
        "https://www.coursera.org",
        "https://www.edx.org",
        "https://www.khanacademy.org",
        "https://www.udemy.com",
        # Development
        "https://www.python.org",
        "https://www.nodejs.org",
        "https://www.docker.com",
        "https://www.kubernetes.io",
        "https://www.apache.org",
        "https://www.mozilla.org",
        "https://www.ubuntu.com",
        "https://www.debian.org",
        # Cloud services
        "https://www.aws.amazon.com",
        "https://www.cloud.google.com",
        "https://www.azure.microsoft.com",
        "https://www.digitalocean.com",
        "https://www.heroku.com",
    ]
    
    # Add variations
    variations = []
    for url in legitimate_urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Add www and non-www versions
        if domain.startswith('www.'):
            variations.append(url.replace('www.', ''))
        else:
            variations.append(url.replace(domain, f'www.{domain}'))
        
        # Add common paths
        variations.append(f"{url}/about")
        variations.append(f"{url}/contact")
        variations.append(f"{url}/help")
        variations.append(f"{url}/login")
    
    all_legitimate = legitimate_urls + variations
    
    # Save to CSV
    df = pd.DataFrame({
        'url': all_legitimate,
        'label': [0] * len(all_legitimate)
    })
    
    output_path = os.path.join(RAW_DATA_DIR, "legitimate_urls.csv")
    df.to_csv(output_path, index=False)
    print(f"✓ Created {len(df)} legitimate URLs")
    return output_path

def download_openphish():
    """Download from OpenPhish"""
    print("\n" + "="*60)
    print("OpenPhish Dataset")
    print("="*60)
    
    url = "https://openphish.com/feed.txt"
    output_path = os.path.join(RAW_DATA_DIR, "openphish.txt")
    
    if download_file(url, output_path, "OpenPhish feed"):
        phish_data = []
        try:
            with open(output_path, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and (url.startswith('http') or url.startswith('https')):
                        phish_data.append({'url': url, 'label': 1})
            
            if phish_data:
                df = pd.DataFrame(phish_data)
                csv_path = os.path.join(RAW_DATA_DIR, "openphish.csv")
                df.to_csv(csv_path, index=False)
                print(f"✓ Processed {len(df)} phishing URLs from OpenPhish")
                return csv_path
        except Exception as e:
            print(f"✗ Error processing OpenPhish data: {str(e)}")
    
    return None

def download_phishstats():
    """Download from PhishStats (alternative source)"""
    print("\n" + "="*60)
    print("PhishStats Dataset")
    print("="*60)
    
    # PhishStats API endpoint
    url = "https://phishstats.info:2096/api/phishing?_where=(verified,eq,true)&_sort=-id&_size=1000"
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            
            phish_data = []
            for item in data:
                url = item.get('url', '')
                if url:
                    phish_data.append({'url': url, 'label': 1})
            
            if phish_data:
                df = pd.DataFrame(phish_data)
                output_path = os.path.join(RAW_DATA_DIR, "phishstats.csv")
                df.to_csv(output_path, index=False)
                print(f"✓ Processed {len(df)} phishing URLs from PhishStats")
                return output_path
    except Exception as e:
        print(f"⚠️  Could not download from PhishStats: {str(e)}")
    
    return None

def combine_datasets():
    """Combine all downloaded datasets into one training dataset"""
    print("\n" + "="*60)
    print("Combining Datasets")
    print("="*60)
    
    all_data = []
    dataset_files = []
    
    # Find all CSV files in raw data directory
    for file in os.listdir(RAW_DATA_DIR):
        if file.endswith('.csv'):
            file_path = os.path.join(RAW_DATA_DIR, file)
            try:
                df = pd.read_csv(file_path)
                if 'url' in df.columns and 'label' in df.columns:
                    dataset_files.append(file)
                    all_data.append(df)
                    print(f"✓ Loaded {file}: {len(df)} samples")
            except Exception as e:
                print(f"✗ Could not load {file}: {str(e)}")
    
    if not all_data:
        print("⚠️  No datasets found to combine")
        return None
    
    # Combine all datasets
    combined_df = pd.concat(all_data, ignore_index=True)
    
    # Remove duplicates
    initial_count = len(combined_df)
    combined_df = combined_df.drop_duplicates(subset=['url'])
    removed = initial_count - len(combined_df)
    
    if removed > 0:
        print(f"  Removed {removed} duplicate URLs")
    
    # Validate URLs
    print("\nValidating URLs...")
    valid_urls = []
    for url in combined_df['url']:
        try:
            url_str = str(url).strip()
            if not url_str or url_str.lower() == 'nan':
                valid_urls.append(False)
                continue
            parsed = urlparse(url_str)
            if parsed.netloc or (parsed.scheme and parsed.path):
                valid_urls.append(True)
            else:
                valid_urls.append(False)
        except:
            valid_urls.append(False)
    
    combined_df = combined_df[valid_urls]
    
    # Balance dataset if needed
    safe_count = len(combined_df[combined_df['label'] == 0])
    phish_count = len(combined_df[combined_df['label'] == 1])
    
    print(f"\nDataset balance:")
    print(f"  Safe (0): {safe_count}")
    print(f"  Phishing (1): {phish_count}")
    
    # If imbalance is too large, sample to balance
    if safe_count > 0 and phish_count > 0:
        min_count = min(safe_count, phish_count)
        max_count = max(safe_count, phish_count)
        
        if max_count > min_count * 2:
            print(f"\n⚠️  Dataset is imbalanced. Sampling to balance...")
            safe_df = combined_df[combined_df['label'] == 0]
            phish_df = combined_df[combined_df['label'] == 1]
            
            if safe_count > phish_count:
                safe_df = safe_df.sample(n=phish_count, random_state=42)
            else:
                phish_df = phish_df.sample(n=safe_count, random_state=42)
            
            combined_df = pd.concat([safe_df, phish_df], ignore_index=True)
            combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
            print(f"  Balanced to {len(combined_df)} samples")
    
    # Save combined dataset
    output_path = os.path.join(PROCESSED_DATA_DIR, "combined_dataset.csv")
    combined_df.to_csv(output_path, index=False)
    
    print(f"\n✓ Combined dataset created: {output_path}")
    print(f"  Total samples: {len(combined_df)}")
    print(f"  Safe (0): {len(combined_df[combined_df['label'] == 0])}")
    print(f"  Phishing (1): {len(combined_df[combined_df['label'] == 1])}")
    print(f"  Sources: {', '.join(dataset_files)}")
    
    return output_path

def main():
    """Main function to download all datasets"""
    print("="*60)
    print("Enhanced Phishing Dataset Downloader")
    print("="*60)
    
    datasets_downloaded = []
    
    # 1. Get legitimate URLs
    legit_path = get_legitimate_urls()
    if legit_path:
        datasets_downloaded.append(legit_path)
    
    # 2. OpenPhish
    openphish_path = download_openphish()
    if openphish_path:
        datasets_downloaded.append(openphish_path)
    
    # 3. PhishStats
    phishstats_path = download_phishstats()
    if phishstats_path:
        datasets_downloaded.append(phishstats_path)
    
    # 4. Hugging Face (alternative method)
    hf_path = download_huggingface_alternative()
    if hf_path:
        datasets_downloaded.append(hf_path)
    
    # Combine all datasets
    if datasets_downloaded:
        combined_path = combine_datasets()
        
        if combined_path:
            print("\n" + "="*60)
            print("✅ Dataset Download Complete!")
            print("="*60)
            print(f"\nCombined dataset ready for training:")
            print(f"  {combined_path}")
            print(f"\nTo train the model with this dataset:")
            print(f"  python train_model.py --dataset {combined_path}")
        else:
            print("\n⚠️  Could not combine datasets")
    else:
        print("\n⚠️  No datasets were successfully downloaded")

if __name__ == "__main__":
    main()


