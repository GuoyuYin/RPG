import os
import re

def extract_syscall_structs(file_path):
    # List to store syscall structs
    syscall_structs = []

    # Pattern to match function names and IDs
    syscall_pattern = re.compile(r"^(\w+)%!\(EXTRA int=(\d+),.*\)")

    # Read the specified file
    with open(file_path, "r") as file:
        for line in file:
            match = syscall_pattern.match(line.strip())
            if match:
                callname = match.group(1)
                id_val = match.group(2)
                syscall_structs.append({"callname": callname, "module": "", "id": int(id_val)})

    # Print the syscall structs in a readable format
    print("Syscall Structs:")
    for struct in syscall_structs:
        print(struct)

    return syscall_structs

if __name__ == "__main__":
    # Specify the file to process
    file_path = "run.log"
    syscall_structs = extract_syscall_structs(file_path)
