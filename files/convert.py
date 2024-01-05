import csv
import sys

def psv_to_csv(psv_file, csv_file):
    prefix = '/files/'
    with open(prefix + psv_file, 'r') as psv_input:
        # Read the PSV file using the '|' delimiter
        psv_reader = csv.reader(psv_input, delimiter='|')

        # Write to the CSV file using the ',' delimiter
        with open(prefix + csv_file, 'w', newline='') as csv_output:
            csv_writer = csv.writer(csv_output)

            # Write each row from PSV to CSV
            for row in psv_reader:
                stripped_row = [col.strip() for col in row]
                csv_writer.writerow(stripped_row)

    print('Conversion complete')


if __name__ == "__main__":
    # Check if the correct number of command-line arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python psv_to_csv.py <input_psv_file> <output_csv_file>")
        sys.exit(1)

    # Get input and output file names from command-line arguments
    input_psv_file = sys.argv[1]
    output_csv_file = sys.argv[2]

    # Convert PSV to CSV
    psv_to_csv(input_psv_file, output_csv_file)