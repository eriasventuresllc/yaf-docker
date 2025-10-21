#!/bin/bash
set -euo pipefail
umask 000
export SILK_CLOBBER=1

# Accept input via env vars:
# - PCAP_PATH: full path to input pcap inside container (e.g., /files/foo.pcap)
# - PCAP_BASENAME: basename (with or without .pcap) assumed to exist under /files
pcap_basename="${PCAP_BASENAME:-merged_output}"
pcap_path="${PCAP_PATH:-}"

if [ -n "$pcap_path" ]; then
input="$pcap_path"
else
pcap_noext="${pcap_basename%.pcap}"
input="/files/${pcap_noext}.pcap"
fi

echo "Running pcap conversion on $input"
if [ ! -f "$input" ]; then
    echo "Input PCAP not found: $input" 1>&2
    exit 2
fi
echo "pcap to ipfix"
# Refer to the documentation for arguments
# https://tools.netsa.cert.org/yaf/yaf.html
yaf \
--in "$input" --out /files/pcap2ipfix.yaf \
--entropy \
--log /files/pcap2ipfix.log ${YAF_VERBOSE:+--verbose}
echo

echo "pcap to ipfix with app labeling"
# Refer to the documentation for arguments
# https://tools.netsa.cert.org/yaf/yaf.html
yaf \
--in "$input" --out /files/pcap2ipfix-applabel.yaf \
--applabel --max-payload=2048 \
--entropy \
--log /files/pcap2ipfix-applabel.log ${YAF_VERBOSE:+--verbose}
echo

echo "pcap to ipfix with app labeling and deep packet inspection"
# Refer to the documentation for arguments
# https://tools.netsa.cert.org/yaf/yaf.html
# https://tools.netsa.cert.org/yaf/yafdpi.html

# Only supply plugin-conf if present under mounted /files/config
plugin_conf_arg=""
if [ -f /files/config/yafDPIRules.conf ]; then
plugin_conf_arg="--plugin-conf=/files/config/yafDPIRules.conf"
fi

yaf \
--in "$input" --out /files/pcap2ipfix-applabel-dpi.yaf \
--applabel --max-payload=2048 \
--plugin-name=/usr/local/lib/yaf/dpacketplugin.la \
$plugin_conf_arg \
--entropy \
--log /files/pcap2ipfix-applabel-dpi.log ${YAF_VERBOSE:+--verbose}
echo

echo "pcap to ipfix with app labeling to ascii using yafscii"
# Refer to the documentation for arguments
# https://tools.netsa.cert.org/yaf/yaf.html
# https://tools.netsa.cert.org/yaf/yafscii.html
yaf \
--in "$input" \
--applabel --max-payload=2048 \
--entropy \
| \
yafscii \
--out /files/pcap2ipfix-applabel-yafscii.psv \
--tabular --print-header \
--log /files/pcap2ipfix-applabel-yafscii.log ${YAF_VERBOSE:+--verbose}
echo

echo "pcap to ipfix with app labeling and deep packet inspection to ascii using super mediator"
# Refer to the documentation for arguments
# https://tools.netsa.cert.org/yaf/yaf.html
# https://tools.netsa.cert.org/yaf/yafdpi.html
# https://tools.netsa.cert.org/super_mediator/super_mediator.html
# Ensure MULTI_FILES PATH directory exists for super_mediator
mkdir -p /files/dpi
echo "Verifying MULTI_FILES PATH:"
ls -ld /files /files/dpi || true

# Allow overriding config from mounted /files directory
config_path="/opt/yaf/dpi_multi_file_extra_fields.conf"
if [ -f /files/dpi_multi_file_extra_fields.conf ]; then
    config_path="/files/dpi_multi_file_extra_fields.conf"
fi
echo "Using super_mediator config: $config_path"
echo "Showing first 30 lines of config:"
nl -ba "$config_path" | sed -n '1,30p' || true
yaf \
--in "$input" \
--applabel --max-payload=2048 \
--plugin-name=/usr/local/lib/yaf/dpacketplugin.la \
$plugin_conf_arg \
--flow-stats \
--entropy \
| \
super_mediator \
-c "$config_path" \
--log /files/pcap2ipfix-applabel-dpi-sm.log ${YAF_VERBOSE:+--verbose}
echo

echo "pcap to ipfix to silk using rwipfix2silk"
# Refer to the documentation for arguments
# https://tools.netsa.cert.org/yaf/yaf.html
# https://tools.netsa.cert.org/silk/rwipfix2silk.html
yaf \
--in "$input" \
--applabel --max-payload=2048 \
--silk \
| \
rwipfix2silk \
--silk-output=/files/pcap2ipfix-applabel-silk.rw \
--interface-values=vlan \
--log-destination /files/pcap2ipfix-applabel-silk.log --log-flags=all
echo
echo "Converting PSV to CSV"
if [ -f /files/pcap2ipfix-applabel-yafscii.psv ]; then
    python3 /opt/yaf/convert.py pcap2ipfix-applabel-yafscii.psv pcap2ipfix-applabel-yafscii.csv
fi
echo
echo "Converting SSL certs to CSV if present"
mkdir -p /files/dpi
if [ -f /files/dpi/sslcerts.txt ]; then
    python3 /opt/yaf/convert.py dpi/sslcerts.txt sslcerts.csv
fi
echo
echo "Converting DPI TEXT files to CSV with headers"
python3 /opt/yaf/convert.py dpi || true

echo
# Optional cleanup of generated outputs after the run when CLEAN_OUTPUTS is set
if [ -n "${CLEAN_OUTPUTS:-}" ]; then
    echo "CLEAN_OUTPUTS is set; removing generated outputs"
    # Core YAF outputs and logs
    rm -f /files/pcap2ipfix.yaf \
          /files/pcap2ipfix-applabel.yaf \
          /files/pcap2ipfix-applabel-dpi.yaf || true

    rm -f /files/pcap2ipfix.log \
          /files/pcap2ipfix-applabel.log \
          /files/pcap2ipfix-applabel-dpi.log \
          /files/pcap2ipfix-applabel-yafscii.log \
          /files/pcap2ipfix-applabel-dpi-sm.log \
          /files/pcap2ipfix-applabel-silk.log || true

    # ASCII/CSV and SiLK outputs
    rm -f /files/pcap2ipfix-applabel-yafscii.psv \
          /files/pcap2ipfix-applabel-yafscii.csv \
          /files/pcap2ipfix-applabel-silk.rw || true

    # DPI directory (text and CSV exports)
    rm -rf /files/dpi || true
fi