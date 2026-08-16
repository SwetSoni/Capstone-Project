"""
Dataset Download Script
Capstone Part 4 — Utility

Downloads the UCI Phishing Websites dataset for the ML threat detector.
If download fails, the threat_detector.py will generate a synthetic dataset.
"""

import os
import urllib.request


def download_dataset():
    """Download the phishing dataset from UCI ML Repository."""
    url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"
    output_path = os.path.join(os.path.dirname(__file__), "phishing_dataset.csv")

    if os.path.exists(output_path):
        print(f"Dataset already exists at: {output_path}")
        return

    print(f"Downloading dataset from: {url}")
    try:
        urllib.request.urlretrieve(url, output_path)
        print(f"Dataset saved to: {output_path}")
    except Exception as e:
        print(f"Download failed: {e}")
        print("The threat_detector.py script will generate a synthetic dataset instead.")


if __name__ == "__main__":
    download_dataset()
