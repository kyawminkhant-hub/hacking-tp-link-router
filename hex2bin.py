# Expected Hex Format: "01 00 00 00 54 50 2d 4c 49 4e 4b 20 54 65 63 68"

import sys

def hex_to_bin(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'wb') as outfile:
        for line in infile:
            hex_values = line.strip().split()
            binary_data = bytes.fromhex(''.join(hex_values))
            outfile.write(binary_data)

if __name__ == "__main__":
    input_filename = sys.argv[1]
    output_filename = sys.argv[2]
    hex_to_bin(input_filename, output_filename)
    print(f"Binary file '{output_filename}' created successfully.")

