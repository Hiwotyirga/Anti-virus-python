import sys
import os
import hashlib
from PyQt5.QtWidgets import QApplication, QFileDialog, QMessageBox

def generate_hash(file_path, algorithm="sha256"):
    hash_function = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_function.update(chunk)
    return hash_function.hexdigest()

def categorize_file(file_path):
    # Add file extensions that you want to categorize as affected by the virus
    virus_file_extensions = {'.txt'}

    _, file_extension = os.path.splitext(file_path)
    return file_extension.lower() in virus_file_extensions

def scan_directory(directory):
    scanned_files = 0
    virus_files = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                scanned_files += 1
                is_virus_file = categorize_file(file_path)

                if is_virus_file:
                    virus_files += 1
                    print("File affected by virus:", file_path)
                    
                    # Ask the user whether to delete the affected file
                    user_response = ask_user_delete_file(file_path)
                    
                    if user_response:
                        delete_file(file_path)
                        print("File deleted.")
                    else:
                        print("File not deleted.")

            except PermissionError as pe:
                print(f"Permission error scanning file {file_path}: {str(pe)}")
            except Exception as e:
                print("Error scanning file:", file_path, "-", str(e))

    print("\nScanned files:", scanned_files)
    print("Files affected by virus:", virus_files)
    print("Files not affected by virus:", scanned_files - virus_files)



def file_open():
    app = QApplication(sys.argv)
    directory = QFileDialog.getExistingDirectory(None, "Select Directory for Scan")
    if directory:
        scan_directory(directory)
    sys.exit(app.exec_()) 

def ask_user_delete_file(file_path):
    # Show a confirmation dialog to the user
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Question)
    msg_box.setText(f"Do you want to delete the affected file:\n{file_path}")
    msg_box.setWindowTitle("File Deletion Confirmation")
    msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    return msg_box.exec_() == QMessageBox.Yes

def delete_file(file_path):
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"Error deleting file {file_path}: {str(e)}")

if __name__ == "__main__":
    # default_directory = "/"  # You can set a default directory here
    # scan_directory(default_directory)
      file_open()

