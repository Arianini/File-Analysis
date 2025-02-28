import hashlib
import os
import shutil
import zipfile
from datetime import datetime
import pefile 

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_DIRECTORY = os.path.join(SCRIPT_DIR, "File")  
RECOVERED_ROOT_DIR = os.path.join(SCRIPT_DIR, "RecoveredFiles")  
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
RECOVERED_DIRECTORY = os.path.join(RECOVERED_ROOT_DIR, f"Recovery_{TIMESTAMP}")  

os.makedirs(RECOVERED_DIRECTORY, exist_ok=True)

# Magic Numbers for File Recovery
MAGIC_NUMBERS = {
    # === IMAGES ===
    b'\xFF\xD8\xFF': 'jpg',  # JPEG
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'png',  # PNG
    b'GIF87a': 'gif',  # GIF87a
    b'GIF89a': 'gif',  # GIF89a
    b'\x42\x4D': 'bmp',  # BMP
    b'\x49\x49\x2A\x00': 'tiff',  # TIFF (Little Endian)
    b'\x4D\x4D\x00\x2A': 'tiff',  # TIFF (Big Endian)

    # === DOCUMENTS ===
    b'\x25\x50\x44\x46': 'pdf',  # PDF Document
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'ppt',  # MS Office Legacy PPT
    b'\x50\x4B\x03\x04': 'zip',  # ZIP (Used for further classification)

    # === ARCHIVES ===
    b'\x52\x61\x72\x21\x1A\x07\x00': 'rar',  # RAR
    b'\x37\x7A\xBC\xAF\x27\x1C': '7z',  # 7-Zip
    b'\x1F\x8B\x08': 'gz',  # GZIP
    b'\x75\x73\x74\x61\x72': 'tar',  # TAR

    # === EXECUTABLES ===
    b'\x4D\x5A': 'exe',  # Windows Executable (EXE/DLL)
    b'\x7F\x45\x4C\x46': 'elf',  # Linux ELF Executable

    # === MULTIMEDIA ===
    b'\x49\x44\x33': 'mp3',  # MP3
    b'\xFF\xFB': 'mp3',  # MP3 (Alternative)
    b'\x00\x00\x00\x20\x66\x74\x79\x70\x69\x73\x6F\x6D': 'mp4',  # MP4 (ISO Media)
    b'\x52\x49\x46\x46': 'avi',  # AVI (RIFF format)
    b'\x00\x00\x01\xBA': 'mpg',  # MPEG Video
    b'\x66\x74\x79\x70\x71\x74\x20': 'mov',  # MOV (QuickTime)
    b'\x57\x41\x56\x45': 'wav',  # WAV
}

# Byte Order Marks (BOMs) for Text Files
TEXT_BOMS = {
    b'\xEF\xBB\xBF': 'utf-8',        # UTF-8 BOM
    b'\xFF\xFE': 'utf-16le',         # UTF-16 Little Endian BOM
    b'\xFE\xFF': 'utf-16be',         # UTF-16 Big Endian BOM
    b'\xFF\xFE\x00\x00': 'utf-32le', # UTF-32 Little Endian BOM
    b'\x00\x00\xFE\xFF': 'utf-32be', # UTF-32 Big Endian BOM
}

SHEBANG = b'#!'  # Shebang for script files

# Batch file detection keywords
BATCH_KEYWORDS = ["@echo", "set ", "for ", "goto", "rem "]

def compute_sha256(file_path):
    """Compute the SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_magic_number(file_path):
    """Retrieve the magic number (hex), offset, and ASCII representation."""
    with open(file_path, "rb") as f:
        magic_bytes = f.read(8)  

    magic_hex = " ".join(f"{byte:02X}" for byte in magic_bytes)
    magic_ascii = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in magic_bytes)
    
    return magic_hex, "0x0", magic_ascii 


def check_zip_contents(file_path):
    """
    Check if a ZIP file contains Office document directories.
    """
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            file_list = zip_ref.namelist()
            if any(f.startswith("ppt/") for f in file_list):
                return "pptx"
            elif any(f.startswith("word/") for f in file_list):
                return "docx"
            elif any(f.startswith("xl/") for f in file_list):
                return "xlsx"
            elif any(f.lower().endswith(('.py', '.sh', '.bat', '.pl')) for f in file_list):
                return "script_archive"
    except zipfile.BadZipFile:
        return None 
    return "zip"

def is_text_file(file_path, block_size=512):
    try:
        with open(file_path, 'rb') as file:
            chunk = file.read(block_size)
            if not chunk:
                return False 
            for encoding in ['utf-8', 'utf-16', 'utf-32', 'latin-1']:
                try:
                    chunk.decode(encoding)
                    return True  
                except UnicodeDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return False

def is_pe_file(file_path):
    try:
        with open(file_path, "rb") as f:
            dos_header = f.read(64)

            if not dos_header.startswith(b'MZ'):
                return None  # Not a valid PE file

            # Locate PE header offset (bytes 60-63 contain the offset)
            pe_offset = int.from_bytes(dos_header[60:64], byteorder="little")

            # Seek to PE header and read it
            f.seek(pe_offset)
            pe_header = f.read(4)

            # Check for valid "PE\0\0" signature
            if pe_header != b"PE\0\0":
                return None 

        # Use pefile for further classification
        pe = pefile.PE(file_path)
        if pe.FILE_HEADER.Characteristics & 0x2000:  
            return "dll"
        else:
            return "exe"  

    except pefile.PEFormatError:
        return None  
    except Exception as e:
        print(f"[ERROR] Unable to read PE file {file_path}: {e}")
        return None

def is_batch_file(file_path):
    try:
        with open(file_path, "r", errors="ignore") as f:
            first_lines = f.readlines()[:5]  # Read first few lines
            for line in first_lines:
                if any(keyword in line.lower() for keyword in BATCH_KEYWORDS):
                    return True
    except Exception:
        pass
    return False

def is_powershell_file(file_path):
    try:
        with open(file_path, "r", errors="ignore") as f:
            first_few_lines = [f.readline().strip().lower() for _ in range(6)]
        
        ps_keywords = [
            "<#", "param", "function ", "try", "catch", "throw", "exit",
            "new-object", "set-variable", "get-command", "write-host",
            "get-service", "start-process", "stop-process", "$psversiontable",
            "& ", "#.synopsis", "#.description", "#.example", "#.notes", "#.link"
        ]
        if any(keyword in " ".join(first_few_lines) for keyword in ps_keywords):
            return True

    except Exception:
        pass
    return False 

def manual_recover_files():
    recovered_files = []

    if not os.path.exists(FILE_DIRECTORY):
        print(f"[ERROR] Directory not found: {FILE_DIRECTORY}")
        return recovered_files

    for root, _, files in os.walk(FILE_DIRECTORY):
        for file in sorted(files): 
            file_path = os.path.join(root, file)
            recovered = False

            with open(file_path, "rb") as f:
                header = f.read(8)

            # === PRIORITY CHECK FOR KNOWN MAGIC NUMBERS ===
            ext = None
            for magic, detected_ext in MAGIC_NUMBERS.items():
                if header.startswith(magic):
                    ext = detected_ext
                    break  # Stop checking once we find a match

            # === CHECK IF FILE IS A ZIP (DOCX, XLSX, PPTX, etc.) ===
            if ext == "zip":
                zip_type = check_zip_contents(file_path)
                if zip_type:
                    ext = zip_type  

            # === CHECK IF FILE IS A PE EXECUTABLE (EXE/DLL) ===
            elif ext == "exe":
                try:
                    pe_type = is_pe_file(file_path)
                    if pe_type:
                        ext = pe_type 
                    else:
                        ext = "unknown"
                except Exception:
                    ext = "unknown"

            # === CHECK IF FILE IS A BATCH SCRIPT ===
            elif ext is None and is_batch_file(file_path):
                ext = "bat"

            # === CHECK IF FILE IS A POWERSHELL SCRIPT ===
            elif ext is None and is_powershell_file(file_path):
                ext = "ps1"

            # === DETECT GENERIC TEXT FILES OR SCRIPTS ===
            elif ext is None and is_text_file(file_path):
                with open(file_path, 'r', errors='ignore') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('#!'):
                        if 'bash' in first_line or 'sh' in first_line:
                            ext = 'sh'
                        elif 'python' in first_line:
                            ext = 'py'
                        else:
                            ext = 'script' 
                    else:
                        ext = 'txt'

            # === DEFAULT TO BINARY FILE IF UNIDENTIFIED ===
            if ext is None:
                ext = 'bin'

            # === RECOVER FILE ===
            recovered_file_path = os.path.join(RECOVERED_DIRECTORY, f"{file}.{ext}")
            shutil.copy2(file_path, recovered_file_path)
            recovered_files.append(recovered_file_path)

            print(f"[Recovered] {file} as {ext}")
            recovered = True

    print(f"\n[Recovery Completed] Recovered {len(recovered_files)} files to {RECOVERED_DIRECTORY}")
    return recovered_files

if __name__ == "__main__":
    manual_recover_files()