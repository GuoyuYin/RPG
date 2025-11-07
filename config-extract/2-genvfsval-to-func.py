import re
import argparse

def parse_settings(filename):
    settings = {}
    # Define two patterns with respective prefixes for function naming
    patterns = {
        r'^(/proc/sys/.+):\s*(\d+)$': 'sysconfig',
        r'^(/sys/.+):\s*(\d+)$': 'proconfig'
    }
    with open(filename, 'r') as file:
        for line in file:
            for pattern, prefix in patterns.items():
                match = re.match(pattern, line.strip())
                if match:
                    path_key = match.group(1).replace('/', '_')
                    # Replace any character that's not an underscore with an underscore
                    path_key = re.sub(r'[^a-zA-Z0-9_]', '_', path_key)
                    settings[path_key] = {
                        'value': int(match.group(2)),
                        'prefix': prefix,
                        'path': match.group(1)  # Store the original path
                    }
                    break  # Once matched, no need to test other patterns for the same line
    return settings

def generate_c_functions(settings):
    functions = []
    for path_key, info in settings.items():
        # Function to set the value with a long parameter
        set_function = f"void {info['prefix']}_set_{path_key}(long val) {{\n" \
                       f"    char command[256];\n" \
                       f"    sprintf(command, \"echo %%ld > {info['path']}\", val);\n" \
                       f"    system(command);\n" \
                       f"}}\n"

        # Function to reset the value to the original setting
        reset_function = f"void {info['prefix']}_reset_{path_key}() {{\n" \
                         f"    char command[256];\n" \
                         f"    sprintf(command, \"echo {info['value']} > {info['path']}\", val);\n" \
                         f"    system(command);\n" \
                         f"}}\n"

        functions.extend([set_function, reset_function])
    return functions

def write_functions_to_file(functions, output_filename):
    with open(output_filename, 'w') as file:
        for func in functions:
            file.write(func + '\n')

def main():
    parser = argparse.ArgumentParser(description="Generate C functions from system settings")
    parser.add_argument('input_filename', type=str, help='Input file containing the settings')
    parser.add_argument('output_filename', type=str, help='Output file to write generated C functions')
    
    args = parser.parse_args()

    settings = parse_settings(args.input_filename)
    functions = generate_c_functions(settings)
    write_functions_to_file(functions, args.output_filename)

if __name__ == "__main__":
    main()