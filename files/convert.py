import csv
import glob
import os
import sys
from typing import List, Optional

def psv_to_csv(psv_file: str, csv_file: str) -> None:
    prefix = '/files/'
    with open(prefix + psv_file, 'r') as psv_input:
        psv_reader = csv.reader(psv_input, delimiter='|')
        with open(prefix + csv_file, 'w', newline='') as csv_output:
            csv_writer = csv.writer(csv_output)
            for row in psv_reader:
                stripped_row = [col.strip() for col in row]
                csv_writer.writerow(stripped_row)

    print('Conversion complete')


def _write_with_header(input_path: str, output_path: str, header: List[str]) -> None:
    """Read a '|' delimited text file and write a CSV with a fixed header length.

    If a row has fewer columns than the header, it will be padded with empty strings.
    If a row has more columns, the extras will be concatenated into the last column.
    """
    with open(input_path, 'r') as txt_in, open(output_path, 'w', newline='') as csv_out:
        reader = csv.reader(txt_in, delimiter='|')
        writer = csv.writer(csv_out)
        writer.writerow(header)
        num_cols = len(header)
        for row in reader:
            # Normalize row length against header
            if len(row) < num_cols:
                row = [col.strip() for col in row] + [''] * (num_cols - len(row))
            elif len(row) > num_cols:
                base = [col.strip() for col in row[: num_cols - 1]]
                overflow = [col.strip() for col in row[num_cols - 1 :]]
                base.append('|'.join(overflow))
                row = base
            else:
                row = [col.strip() for col in row]
            writer.writerow(row)


def _find_first_existing(patterns: List[str]) -> Optional[str]:
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        if matches:
            # Use the most recent file if multiple rotate files exist
            matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            return matches[0]
    return None


def convert_dpi_txt_to_csv(dpi_dir: str = '/files/dpi') -> None:
    """Convert super_mediator DPI text files to CSV with headers.

    Outputs CSVs next to the inputs:
    - dns.csv, flow.csv, http.csv, tls.csv
    """
    os.makedirs(dpi_dir, exist_ok=True)

    # dns
    dns_in = _find_first_existing([
        os.path.join(dpi_dir, 'dns.txt*'),
        os.path.join(dpi_dir, 'dns.txt'),
    ])
    if dns_in:
        dns_out = os.path.join(dpi_dir, 'dns.csv')
        dns_header = [
            'flow_id',
            'stime_ms',
            'sub',
            'q_or_r',
            'id',
            'f1',
            'f2',
            'f3',
            'rr_type',
            'ttl',
            'name',
            'value',
        ]
        _write_with_header(dns_in, dns_out, dns_header)

    # flow
    flow_in = _find_first_existing([
        os.path.join(dpi_dir, 'flow.txt*'),
        os.path.join(dpi_dir, 'flow.txt'),
    ])
    if flow_in:
        flow_out = os.path.join(dpi_dir, 'flow.csv')
        flow_header = [
            'flow_id',
            'stime_ms',
            'src_ip',
            'dst_ip',
            'protocol',
            'src_port',
            'dst_port',
            'application',
            'vlan',
        ]
        _write_with_header(flow_in, flow_out, flow_header)

    # http
    http_in = _find_first_existing([
        os.path.join(dpi_dir, 'http.txt*'),
        os.path.join(dpi_dir, 'http.txt'),
    ])
    if http_in:
        http_out = os.path.join(dpi_dir, 'http.csv')
        http_header = [
            'flow_id',
            'stime_ms',
            'sub',
            'http_id',
            'value',
        ]
        _write_with_header(http_in, http_out, http_header)

    # tls
    tls_in = _find_first_existing([
        os.path.join(dpi_dir, 'tls.txt*'),
        os.path.join(dpi_dir, 'tls.txt'),
    ])
    if tls_in:
        tls_out = os.path.join(dpi_dir, 'tls.csv')
        tls_header = [
            'flow_id',
            'stime_ms',
            'sub',
            'tls_id',
            'issuer_subject',
            'f1',
            'value',
        ]
        _write_with_header(tls_in, tls_out, tls_header)

    print('DPI TXT to CSV conversion complete')


if __name__ == "__main__":
    # Modes:
    #  - convert all DPI text files to CSV with headers: `python convert.py dpi`
    #  - convert a single PSV (or '|' separated) file to CSV: `python convert.py in.psv out.csv`
    if len(sys.argv) == 2 and sys.argv[1].lower() == 'dpi':
        convert_dpi_txt_to_csv('/files/dpi')
        sys.exit(0)

    if len(sys.argv) != 3:
        print("Usage:\n  python convert.py dpi\n  python convert.py <input_psv_file> <output_csv_file>")
        sys.exit(1)

    input_psv_file = sys.argv[1]
    output_csv_file = sys.argv[2]
    psv_to_csv(input_psv_file, output_csv_file)