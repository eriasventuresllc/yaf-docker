import csv
import glob
import os
import sys
from datetime import datetime, timezone
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

            # Convert stime_ms (index 1) from epoch milliseconds to ISO 8601 UTC
            if len(row) > 1 and row[1]:
                try:
                    ms_int = int(row[1])
                    dt = datetime.fromtimestamp(ms_int / 1000.0, tz=timezone.utc)
                    # Keep milliseconds precision and Z suffix
                    row[1] = dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                except ValueError:
                    # leave as-is if non-numeric
                    pass

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

    # Post-process: deduplicate JA3 and create joined flows view
    try:
        dedup_ja3_csv(dpi_dir)
    except Exception:
        # non-fatal
        pass
    try:
        create_flows_joined_csv(dpi_dir)
    except Exception:
        # non-fatal
        pass
    print('DPI TXT to CSV conversion complete')


def _dedup_csv_inplace(csv_path: str, key_fields: Optional[List[str]] = None) -> None:
    """Deduplicate a CSV file in place.

    If key_fields is provided, rows are considered duplicates when all key field
    values match. Otherwise, rows are considered duplicates when all field
    values match (full-row dedup).
    """
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        return

    temp_path = csv_path + '.tmp'
    with open(csv_path, 'r', newline='') as src:
        reader = csv.DictReader(src)
        fieldnames = reader.fieldnames or []
        if not fieldnames:
            return
        # Validate provided keys against header
        keys = key_fields if key_fields else fieldnames
        for k in keys:
            if k not in fieldnames:
                # Fall back to full-row dedup if a key is missing
                keys = fieldnames
                break

        seen = set()
        rows: List[dict] = []
        for row in reader:
            key = tuple((k, row.get(k, '')) for k in keys)
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)

    with open(temp_path, 'w', newline='') as dst:
        writer = csv.DictWriter(dst, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    try:
        os.replace(temp_path, csv_path)
    except OSError:
        # Best-effort cleanup on platforms without atomic replace
        try:
            os.remove(temp_path)
        except OSError:
            pass


def dedup_ja3_csv(dpi_dir: str = '/files/dpi') -> None:
    """Deduplicate JA3 CSV to remove repeated entries.

    Prefers uniqueness by (flow_id, tls_field, value) when available.
    Falls back to full-row dedup if headers differ.
    """
    ja3_csv = os.path.join(dpi_dir, 'ja3.csv')
    if not os.path.exists(ja3_csv) or os.path.getsize(ja3_csv) == 0:
        return

    # Try to dedup on specific keys; otherwise full-row
    _dedup_csv_inplace(ja3_csv, key_fields=['flow_id', 'tls_field', 'value'])


def create_flows_joined_csv(dpi_dir: str = '/files/dpi', output_name: str = 'flows_joined.csv') -> None:
    """Create a long-form CSV joining flow metadata with all DPI rules.

    Output schema:
      flow_id, stime_ms, src_ip, dst_ip, protocol_name, src_port, dst_port,
      application, vlan, dpi_table, field, value

    Sources:
      - flow.csv (metadata)
      - dns.csv (field: rr_type_name; value: value or name)
      - http.csv (field: http_field; value)
      - tls.csv (field: tls_field; value) [excluding JA3* entries]
      - ja3.csv (field: tls_field; value) [deduped]
    """
    os.makedirs(dpi_dir, exist_ok=True)
    flow_csv = os.path.join(dpi_dir, 'flow.csv')
    dns_csv = os.path.join(dpi_dir, 'dns.csv')
    http_csv = os.path.join(dpi_dir, 'http.csv')
    tls_csv = os.path.join(dpi_dir, 'tls.csv')
    ja3_csv = os.path.join(dpi_dir, 'ja3.csv')
    out_csv = os.path.join(dpi_dir, output_name)

    # Load flow metadata
    flow_meta: dict = {}
    flow_fields = ['stime_ms', 'src_ip', 'dst_ip', 'protocol_name', 'src_port', 'dst_port', 'application', 'vlan']
    if os.path.exists(flow_csv) and os.path.getsize(flow_csv) > 0:
        with open(flow_csv, 'r', newline='') as f:
            r = csv.DictReader(f)
            for row in r:
                fid = row.get('flow_id')
                if not fid:
                    continue
                flow_meta[fid] = {k: row.get(k, '') for k in flow_fields}

    def _emit_rows_from_file(path: str, dpi_table: str):
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return []
        with open(path, 'r', newline='') as f:
            r = csv.DictReader(f)
            rows = []
            for row in r:
                fid = row.get('flow_id', '')
                stime = row.get('stime_ms', '')
                # Determine field/value per table
                if dpi_table == 'dns':
                    field = row.get('rr_type_name', '') or row.get('rr_type', '')
                    value = row.get('value', '') or row.get('name', '')
                elif dpi_table == 'http':
                    field = row.get('http_field', '') or row.get('http_id', '')
                    value = row.get('value', '')
                else:  # tls or ja3
                    field = row.get('tls_field', '') or row.get('tls_id', '')
                    value = row.get('value', '')

                # Pull flow metadata if available
                meta = flow_meta.get(fid, {})
                rows.append({
                    'flow_id': fid,
                    'stime_ms': stime,
                    'src_ip': meta.get('src_ip', ''),
                    'dst_ip': meta.get('dst_ip', ''),
                    'protocol_name': meta.get('protocol_name', ''),
                    'src_port': meta.get('src_port', ''),
                    'dst_port': meta.get('dst_port', ''),
                    'application': meta.get('application', ''),
                    'vlan': meta.get('vlan', ''),
                    'dpi_table': dpi_table,
                    'field': field,
                    'value': value,
                })
            return rows

    joined_rows: List[dict] = []

    # DNS
    joined_rows.extend(_emit_rows_from_file(dns_csv, 'dns'))

    # HTTP
    joined_rows.extend(_emit_rows_from_file(http_csv, 'http'))

    # TLS (exclude JA3* entries which will be taken from ja3.csv)
    if os.path.exists(tls_csv) and os.path.getsize(tls_csv) > 0:
        with open(tls_csv, 'r', newline='') as f:
            r = csv.DictReader(f)
            filtered_path = tls_csv + '.nofp'
            with open(filtered_path, 'w', newline='') as tmp:
                w = None
                for row in r:
                    tls_field = row.get('tls_field', '')
                    if tls_field in ('ja3_hash', 'ja3_params', 'ja3s_hash', 'ja3s_params'):
                        continue
                    if w is None:
                        w = csv.DictWriter(tmp, fieldnames=r.fieldnames)
                        w.writeheader()
                    w.writerow(row)
            joined_rows.extend(_emit_rows_from_file(filtered_path, 'tls'))
            try:
                os.remove(filtered_path)
            except OSError:
                pass

    # JA3 (after dedup)
    joined_rows.extend(_emit_rows_from_file(ja3_csv, 'ja3'))

    # Write output
    headers = [
        'flow_id', 'stime_ms', 'src_ip', 'dst_ip', 'protocol_name', 'src_port',
        'dst_port', 'application', 'vlan', 'dpi_table', 'field', 'value',
    ]
    with open(out_csv, 'w', newline='') as out:
        w = csv.DictWriter(out, fieldnames=headers)
        w.writeheader()
        for row in joined_rows:
            w.writerow(row)


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