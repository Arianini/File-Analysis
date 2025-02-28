import os
import subprocess
import json
import pandas as pd

# Path to ExifTool executable
EXIFTOOL_PATH = r"./tools/exiftool-13.19_64/exiftool.exe"  # Adjust this path if needed

def extract_metadata(directory, output_csv):
    """Extracts metadata from all files in a directory using ExifTool and saves it to a CSV file."""
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist.")
        return
    
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    
    if not files:
        print("No files found in the directory.")
        return
    
    metadata_list = []
    
    for file in files:
        file_metadata = {"File Name": os.path.basename(file)}
        try:
            result = subprocess.run([EXIFTOOL_PATH, "-json", file], capture_output=True, text=True)
            metadata = json.loads(result.stdout)[0] if result.stdout else {}
            file_metadata.update(metadata)
        except Exception as e:
            print(f"Error processing {file}: {e}")
        
        metadata_list.append(file_metadata)
    
    df = pd.DataFrame(metadata_list)
    df.fillna("NaN", inplace=True)  # Fill empty values with NaN
    df.to_csv(output_csv, index=False, encoding="utf-8")
    
    print(f"Metadata saved to {output_csv}")

if __name__ == "__main__":
    directory_path = "./RecoveredFiles"
    output_csv_file = "metadata.csv"
    extract_metadata(directory_path, output_csv_file)
