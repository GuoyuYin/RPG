import os
import re
import csv

def extract_syscall_structs(file_path):
    # List to store syscall structs
    syscall_structs = []

    # Pattern to match function names and IDs
    syscall_pattern = re.compile(r"^([\w\$]+)%!\(EXTRA int=(\d+),.*\)")

    # Extract module name from file path
    module_name = os.path.basename(file_path)

    # Read the specified file
    with open(file_path, "r") as file:
        for line in file:
            match = syscall_pattern.match(line.strip())
            if match:
                callname = match.group(1)
                id_val = match.group(2)

                # Skip callnames starting with "syz_proconfi" or "syz_sysonfi"
                if callname.startswith("syz_proconfig") or callname.startswith("syz_sysconfig"):
                    continue
                else:
                    syscall_structs.append({"callname": callname, "module": module_name, "id": int(id_val)})

    # Print the syscall structs in a readable format
    # print("Syscall Structs:")
    # for struct in syscall_structs:
    #     print(struct)
    print ("df: Extracted syscall structs: ", len(syscall_structs))
    return syscall_structs

def map_syscalls_to_modules(directory, syscall_structs):
    # Dictionary to store the mapping of filenames to syscalls
    module_syscalls = {}

    # Pattern to match function names with the format functionname$variant(args)
    function_pattern = re.compile(r"^([\w\$]+)\(.*\)")

    # Iterate through all .txt files in the specified directory
    for filename in os.listdir(directory):
        # Skip specific file "syzlang-sys.txt"
        if filename == "syzlang-sys.txt":
            continue

        if filename.endswith(".txt"):
            filepath = os.path.join(directory, filename)
            with open(filepath, "r") as file:
                # Extract function names based on the defined pattern
                syscalls = [match.group(1) for line in file if (match := function_pattern.match(line.strip()))]
                module_syscalls[filename] = syscalls

    # Update syscall_structs with the module name from the corresponding file
    for struct in syscall_structs:
        for filename, syscalls in module_syscalls.items():
            if struct["callname"] in syscalls:
                struct["module"] = filename[:-4]

    # Print the updated syscall structs
    # print("Updated Syscall Structs with Module Names:")
    # for struct in syscall_structs:
    #     print(struct)
    print ("df: Updated syscall structs: ", len(syscall_structs))
    return syscall_structs


def extract_configall_structs_with_modules(file_path, c_file_path):
    # Extract syscall structs
    config_structs = []

    # Pattern to match function names and IDs
    syscall_pattern = re.compile(r"^(\w+)%!\(EXTRA int=(\d+),.*\)")

    # Extract module name from file path
    module_name = os.path.basename(file_path)

    # Read the specified file
    with open(file_path, "r") as file:
        for line in file:
            match = syscall_pattern.match(line.strip())
            if match:
                callname = match.group(1)
                id_val = match.group(2)

                # Skip callnames starting with "syz_proconfi" or "syz_sysconfi"
                if callname.startswith("syz_proconfig") or callname.startswith("syz_sysconfig"):
                    config_structs.append({"callname": callname, "module": "", "id": int(id_val)})

    # Extract functions and modules from C file
    functions = extract_functions_from_c_file(c_file_path)

    # Update config_structs with module information from C file functions
    for struct in config_structs:
        for func in functions:
            if struct["callname"] == func["callname"]:
                struct["module"] = func["module"]

    # Print the updated config structs
    # print("Updated Config Structs with Modules:")
    # for struct in config_structs:
    #     print(struct)
    
    print ("df: Extracted config structs: ", len(config_structs))
    return config_structs

def extract_functions_from_c_file(c_file_path):
    # List to store extracted functions and modules
    functions = []

    # Patterns to match function definitions and module paths
    function_pattern = re.compile(r"^static long (\w+)\(")
    module_pattern = re.compile(r'sprintf\(command, \"echo.*> (.*?)\"')

    # Read the .c file
    with open(c_file_path, "r") as file:
        lines = file.readlines()

    current_function = None

    for line in lines:
        # Check for function definition
        function_match = function_pattern.match(line.strip())
        if function_match:
            current_function = function_match.group(1)

        # Check for module path within the function
        if current_function:
            module_match = module_pattern.search(line.strip())
            if module_match:
                module_path = module_match.group(1)
                functions.append({"callname": current_function, "module": module_path})
                current_function = None

    # Print the extracted functions and modules
    # print("Extracted Functions from C File:")
    # for func in functions:
    #     print(func)

    return functions

def extract_module_from_syscall(syscall_structs):
    # Add module2 for syscall_structs if $ exists
    for struct in syscall_structs:
        if "$" in struct["callname"]:
            struct["module2"] = struct["callname"].split("$")[1]
            if struct["callname"].split("$")[1][0].isdigit():
                struct["module2"] = ""
        else:
            struct["module2"] = ""
    return syscall_structs

def extract_module_from_config(config_structs):
    # Add module and module2 for config_structs
    for struct in config_structs:
        if "module" in struct and struct["module"]:
            parts = struct["module"].split("/")
            if len(parts) >= 3:
                struct["module"] = parts[-3]
                struct["module2"] = parts[-2]
            # If module is a single number, set it to ""
            if struct["module"][0].isdigit():
                struct["module"] = ""
            if struct["module2"][0].isdigit():
                struct["module2"] = ""

    print ("df: Extracted module from config structs: ", len(config_structs))
    return config_structs

# def find_common_substrings(string1, string2):

def find_common_substrings(str1, str2, min_length):
    """Check if two strings have a common substring of at least `min_length`."""
    len1, len2 = len(str1), len(str2)
    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            if str1[i - 1] == str2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
                if dp[i][j] >= min_length:
                    return True
    return False


def compute_relation_matrix(config_structs, syscall_structs):
    # Initialize relation matrix
    relation_matrix = [
    [0 for _ in range(len(config_structs))]
    for _ in range(len(syscall_structs))
]
    for i in range(len(syscall_structs)):
        for j in range(len(config_structs)):
            relation_matrix[i][j] = 0
    print("Relation matrix initialized: ", len(relation_matrix), "/", len(relation_matrix[0]))
    
    for i, config in enumerate(config_structs):
        if "reset" in config["callname"]:
            continue
        print("comparing ", config["module"], i,"/",len(config_structs))
        for j, syscall in enumerate(syscall_structs):
            # if config["module2"] no exists
            # Compare module and module2 between config and syscall
            longest_module = find_common_substrings(config["module"], syscall["module"], min(len(config["module"]), len(syscall["module"])))
            longest_module2 = find_common_substrings(config["module2"], syscall["module2"], min(len(config["module2"]), len(syscall["module2"])))
            longest_cross1 = find_common_substrings(config["module"], syscall["module2"], min(len(config["module"]), len(syscall["module2"])))
            longest_cross2 = find_common_substrings(config["module2"], syscall["module"], min(len(config["module2"]), len(syscall["module"])))
            # print(longest_module, longest_module2, longest_cross1, longest_cross2)
            # If any comparison has a sufficiently long common substring, mark as related
            if longest_module or longest_module2 or longest_cross1 or longest_cross2:
                   print("Relation between ", config, "\n", syscall)
                   relation_matrix[j][i] = 15
                
        # Extend relations to other syscalls in the same module
    for i, config in enumerate(config_structs):
        for j, syscall in enumerate(syscall_structs):
            if relation_matrix[j][i] != 0:
                for x, related_syscall in enumerate(syscall_structs):
                    if syscall["module"] == related_syscall["module"] or syscall["module2"] == related_syscall["module2"]:
                        if relation_matrix[x][i] == 0:
                            print("Extending relation between ", i, j, x)
                            relation_matrix[x][i] = 10
                            
    # cnt_all = 0
    # cnt_related = 0
    # for i in range(len(relation_matrix)):
    #     print(len(relation_matrix[i]))
    #     if len(relation_matrix[i]) != len(config_structs):
    #         print("Error: ", len(relation_matrix[i]), len(config_structs))
                
    # print("Relation matrix: ", cnt_related, "/", cnt_all)
    # transposing the matrix
    # relation_matrix = list(map(list, *relation_matrix))
    return relation_matrix


if __name__ == "__main__":
    # Process single file for syscall structs
    file_path = "callinfo.txt"
    syscall_structs = extract_syscall_structs(file_path)

    # Process directory for mapping syscalls to modules and update structs
    directory = "/path/to/syzkaller/sys/linux"
    syscall_structs = map_syscalls_to_modules(directory, syscall_structs)
    

    # Extract and update config structs with module information from C file
    
    c_file_path = "example.c"
    config_structs = extract_configall_structs_with_modules(file_path, c_file_path)

    syscall_structs = extract_module_from_syscall(syscall_structs)
    config_structs = extract_module_from_config(config_structs)
    # print("Final Syscall Structs:")
    # for struct in syscall_structs:
    #     print(struct)
    # print("Final Config Structs:")
    # for struct in config_structs:
    #     print(struct)
        
    # Compute relation matrix
    relation_matrix = compute_relation_matrix(config_structs, syscall_structs)
    
    # save relation_matrix to file
    with open("relation_matrix.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerows(relation_matrix)




# def write_relation_matrix_to_csv(relation_matrix, filename="relation_matrix.csv"):
#     with open(filename, 'w', newline='') as f:
#         writer = csv.writer(f)
#         writer.writerows(relation_matrix)
