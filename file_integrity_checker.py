import hashlib
import os
import json
import sys

# Function to calculate the hash of a file
def calculate_file_hash(filepath, hash_function="sha256"):
    hasher = hashlib.new(hash_function)
    try:
        with open(filepath, "rb") as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return None

# Function to load existing hashes from a file
def load_hashes(hash_file):
    if os.path.exists(hash_file):
        with open(hash_file, "r") as file:
            return json.load(file)
    return {}

# Function to save hashes to a file
def save_hashes(hash_file, hash_data):
    with open(hash_file, "w") as file:
        json.dump(hash_data, file, indent=4)

# Function to check for file integrity
def check_file_integrity(target_dir, hash_file="file_hashes.json", hash_function="sha256"):
    # Check if the target directory exists
    if not os.path.exists(target_dir):
        print(f"Error: Target directory '{target_dir}' does not exist.")
        sys.exit(1)

    # Load existing hashes
    existing_hashes = load_hashes(hash_file)
    
    # Dictionary to store new hashes
    new_hashes = {}
    
    # Walk through the directory and calculate hashes
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_file_hash(filepath, hash_function)
            if file_hash:
                new_hashes[filepath] = file_hash

                # Compare with existing hash
                if filepath in existing_hashes:
                    if existing_hashes[filepath] != file_hash:
                        print(f"[CHANGED] {filepath}")
                else:
                    print(f"[NEW] {filepath}")

    # Check for deleted files
    for filepath in existing_hashes:
        if filepath not in new_hashes:
            print(f"[DELETED] {filepath}")

    # Save the new hashes to the hash file
    save_hashes(hash_file, new_hashes)

# Main function for CLI usage
def main():
    import argparse

    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("target_dir", nargs="?", default=".", help="Target directory to monitor for file changes (default: current directory)")
    parser.add_argument("--hash-file", default="file_hashes.json", help="Path to store hash values")
    parser.add_argument("--hash-function", default="sha256", choices=hashlib.algorithms_available, help="Hashing algorithm to use")

    args = parser.parse_args()

    check_file_integrity(args.target_dir, args.hash_file, args.hash_function)

if __name__ == "__main__":
    main()
