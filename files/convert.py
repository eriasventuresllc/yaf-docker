import csv
import glob
import os
import sys
from typing import Callable, List, Optional

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


def _write_with_header_and_extra(
    input_path: str,
    output_path: str,
    base_header: List[str],
    extra_header: List[str],
    compute_extra_fn: Callable[[List[str]], List[str]],
) -> None:
    """Write CSV with base header plus extra derived columns computed per row.

    The input is a '|' delimited text file. Rows are normalized to match the
    base header length following the same rules as _write_with_header.
    """
    with open(input_path, 'r') as txt_in, open(output_path, 'w', newline='') as csv_out:
        reader = csv.reader(txt_in, delimiter='|')
        writer = csv.writer(csv_out)
        writer.writerow(base_header + extra_header)
        num_cols = len(base_header)
        for row in reader:
            if not row:
                continue
            # Normalize row length against base header
            if len(row) < num_cols:
                row = [col.strip() for col in row] + [''] * (num_cols - len(row))
            elif len(row) > num_cols:
                base = [col.strip() for col in row[: num_cols - 1]]
                overflow = [col.strip() for col in row[num_cols - 1 :]]
                base.append('|'.join(overflow))
                row = base
            else:
                row = [col.strip() for col in row]

            # Skip header-like lines if present (flow_id should be numeric)
            if not row[0] or not row[0].isdigit():
                continue

            extra = compute_extra_fn(row)
            writer.writerow(row + extra)


def _protocol_number_to_name(proto_str: str) -> str:
    try:
        proto = int(proto_str)
    except ValueError:
        return ''
    mapping = {
        6: 'TCP',
        17: 'UDP',
        1: 'ICMP',
        2: 'IGMP',
        103: 'PIM',
    }
    return mapping.get(proto, f'PROTO_{proto}')


HTTP_ID_LABELS = {
    110: 'server',
    111: 'user_agent',
    112: 'request_line',
    113: 'connection',
    114: 'http_version',
    117: 'server_address',
    118: 'server_port',
    120: 'accept',
    122: 'content_type',
    123: 'status',
    221: 'set_cookie',
}


TLS_ID_LABELS = {
    463: 'ja3_hash',
    464: 'ja3_params',
    465: 'ja3s_hash',
    466: 'ja3s_params',
}


DNS_RR_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    35: 'NAPTR',
    43: 'DS',
    44: 'SSHFP',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    52: 'TLSA',
    65: 'HTTPS',
    257: 'CAA',
}


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

        def _dns_extra(row: List[str]) -> List[str]:
            try:
                rr_type_val = int(row[8]) if row[8] else -1
            except ValueError:
                rr_type_val = -1
            rr_name = DNS_RR_TYPES.get(rr_type_val, '') if rr_type_val >= 0 else ''
            return [rr_name]

        _write_with_header_and_extra(
            dns_in,
            dns_out,
            dns_header,
            ['rr_type_name'],
            _dns_extra,
        )
        try:
            os.remove(dns_in)
        except OSError:
            pass

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

        def _flow_extra(row: List[str]) -> List[str]:
            return [_protocol_number_to_name(row[4])]

        _write_with_header_and_extra(
            flow_in,
            flow_out,
            flow_header,
            ['protocol_name'],
            _flow_extra,
        )
        try:
            os.remove(flow_in)
        except OSError:
            pass

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

        def _http_extra(row: List[str]) -> List[str]:
            try:
                http_id = int(row[3]) if row[3] else -1
            except ValueError:
                http_id = -1
            label = HTTP_ID_LABELS.get(http_id, f'http_{http_id}' if http_id >= 0 else '')
            return [label]

        _write_with_header_and_extra(
            http_in,
            http_out,
            http_header,
            ['http_field'],
            _http_extra,
        )
        try:
            os.remove(http_in)
        except OSError:
            pass

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

        def _tls_extra(row: List[str]) -> List[str]:
            try:
                tls_id = int(row[3]) if row[3] else -1
            except ValueError:
                tls_id = -1
            label = TLS_ID_LABELS.get(tls_id, f'tls_{tls_id}' if tls_id >= 0 else '')
            return [label]

        _write_with_header_and_extra(
            tls_in,
            tls_out,
            tls_header,
            ['tls_field'],
            _tls_extra,
        )
        try:
            os.remove(tls_in)
        except OSError:
            pass

    # ja3 (derived from tls, if extracted into /files/dpi/ja3.txt)
    ja3_in = os.path.join(dpi_dir, 'ja3.txt')
    if os.path.exists(ja3_in) and os.path.getsize(ja3_in) > 0:
        ja3_out = os.path.join(dpi_dir, 'ja3.csv')
        ja3_header = [
            'flow_id',
            'stime_ms',
            'sub',
            'tls_id',
            'issuer_subject',
            'f1',
            'value',
        ]

        def _ja3_extra(row: List[str]) -> List[str]:
            try:
                tls_id = int(row[3]) if row[3] else -1
            except ValueError:
                tls_id = -1
            label = TLS_ID_LABELS.get(tls_id, f'tls_{tls_id}' if tls_id >= 0 else '')
            return [label]

        _write_with_header_and_extra(
            ja3_in,
            ja3_out,
            ja3_header,
            ['tls_field'],
            _ja3_extra,
        )
        try:
            os.remove(ja3_in)
        except OSError:
            pass

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