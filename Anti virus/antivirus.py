import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
import hashlib

def generate_hash(file_path, algorithm="sha256"):
    hash_function = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_function.update(chunk)
    return hash_function.hexdigest()

def file_open():
    app = QApplication(sys.argv)
    file_path, _ = QFileDialog.getOpenFileName(None, "Open File", "", "*.txt;*.pdf;*.doc;*.docx")
    if file_path:
        scan_file(file_path)
    sys.exit(app.exec_())

def scan_file(file_path):
    virus_signature = generate_hash(file_path)
    with open(file_path, 'rb') as f:
        file_content = f.read()

    # Convert virus_signature to bytes
    virus_signature_bytes = virus_signature.encode('utf-8')

    if virus_signature_bytes in file_content:
        print("Virus found in file:", file_path)
    else:
        print("No virus found in file:", file_path)

if __name__ == "__main__":
    file_open()
