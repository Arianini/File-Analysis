import os
import hashlib
import csv

# Dictionary of known file signatures (Magic Numbers)
MAGIC_NUMBERS = {
    "FFD8FF": "JPEG Image",
    "89504E47": "PNG Image",
    "47494638": "GIF Image",
    "25504446": "PDF Document",
    "504B0304": "ZIP Archive",
    "4D5A": "Windows Executable (EXE, DLL)",
    "7F454C46": "ELF Executable",
    "D0CF11E0A1B11AE1": "Microsoft Office Pre-2007 (DOC, XLS, PPT)",
    "504B0304": "Microsoft Office 2007+ (DOCX, XLSX, PPTX, ODT)",
    "494433": "MP3 Audio",
    "1F8B08": "GZIP Compressed File",
    "CAFEBABE": "Java Class File",
    "2321": "Shell Script",
    "2E7368": "Bash Script",
    "EFBBBF23": "PowerShell Script (UTF-8 BOM)",
    "0000FEFF": "UTF-16 Text File",
    "EFBBBF": "UTF-8 Text File"
}

def calculate_sha256(file_path):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"

def find_magic_number_offset(file_path, scan_limit=1024):
    """Finds the first occurrence of a known magic number in the file and its offset, including ASCII representation."""
    try:
        with open(file_path, "rb") as f:
            content = f.read(scan_limit)  # Read the first 1KB of the file

        # Convert content into hex for easier searching
        hex_content = content.hex().upper()

        for magic_hex in MAGIC_NUMBERS.keys():
            index = hex_content.find(magic_hex)
            if index != -1:  # Magic number found
                offset = index // 2  # Convert hex index to byte offset
                magic_bytes = bytes.fromhex(magic_hex)
                ascii_representation = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in magic_bytes)
                return magic_hex, f"0x{offset:X}", ascii_representation

        return "Unknown", "N/A", "N/A"

    except Exception as e:
        return f"Error: {str(e)}", "Error", "Error"

def process_files(directory, output_csv):
    """Processes all files in the given directory and writes SHA256 hashes and file signatures to a CSV file."""
    data = []

    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist.")
        return

    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            sha256_hash = calculate_sha256(file_path)
            magic_number, offset, ascii_representation = find_magic_number_offset(file_path)
            data.append([file_name, sha256_hash, magic_number, offset, ascii_representation])

    with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["File Name", "SHA256 Hash", "Magic Number (Hex)", "Offset (Hex)", "ASCII Representation"])
        writer.writerows(data)

    print(f"SHA256 hashes and file signatures saved to {output_csv}")

if __name__ == "__main__":
    directory_path = "./RecoveredFiles"  # Change as needed
    output_csv_file = "after.csv"  # or any filename
    process_files(directory_path, output_csv_file)
