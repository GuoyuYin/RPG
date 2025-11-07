import os

def scan_directory(directory):
    # Check if the directory exists
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist.")
        return

    # Walk through the directory and list all files
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            # Skip the specific file
            if file_path == '/sys/kernel/security/apparmor/revision':
                print(f"Skipping file: {file_path}")
                continue

            # Check if the file is writable
            if os.access(file_path, os.W_OK):

                # Try reading and printing the entire contents of the file
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().strip()  # Read and strip any extra whitespace

                        # Try to convert the content to an integer
                        try:
                            int_value = int(content)
                            print(f"{file_path}: {int_value}\n\n")
                        except ValueError:
                            pass
                            # If it's not an integer, print the content

                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")

if __name__ == "__main__":
    # Define directories to scan
    directories = ['/proc/sys', '/sys']

    for directory in directories:
        print(f"Scanning directory: {directory}")
        scan_directory(directory)
        print("-" * 40)
