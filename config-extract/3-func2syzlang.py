import re
import argparse

def extract_info_from_file(filename):
    """ Extracts function names and command strings from the file. """
    info = []
    regex_pattern = r'void\s+(\w+)\s*\([^)]*\)\s*{\s*char\s+command\[256\];\s*sprintf\(command,\s*"echo\s+(?:%ld\s+>|\d+\s*>)\s*([^"]+)",\s*val\);\s*system\(command\);\s*}'
    with open(filename, 'r') as file:
        content = file.read()
        matches = re.findall(regex_pattern, content)
        for function_name, sys_path in matches:
            print(f"Function: {function_name}, Path: {sys_path}")
            value = 'val' if '%ld' in content else 'default'  # Determine if value is dynamic
            info.append((function_name, sys_path, value))
    return info

def generate_syzlang(info):
    """ Generates Syzlang definitions based on extracted information. """
    definitions = []
    for function_name, sys_path, value in info:
        if 'set' in function_name:
            definitions.append(f"{function_name}(val intptr) #{value}\n")
        elif 'reset' in function_name:
            definitions.append(f"{function_name}() #{value}\n")
    return definitions

def write_definitions_to_file(definitions, output_filename):
    """ Writes the generated Syzlang definitions to a file. """
    with open(output_filename, 'w') as file:
        for definition in definitions:
            file.write(definition)

def main():
    parser = argparse.ArgumentParser(description="Generate Syzlang descriptions from C function implementations")
    parser.add_argument('input_filename', type=str, help='Input file containing the C functions')
    parser.add_argument('output_filename', type=str, help='Output file to write Syzlang definitions')
    
    args = parser.parse_args()

    info = extract_info_from_file(args.input_filename)
    definitions = generate_syzlang(info)
    write_definitions_to_file(definitions, args.output_filename)

if __name__ == "__main__":
    main()
