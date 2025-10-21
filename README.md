### Quick start

1) Build and run automatically with a single command (auto-build if missing):

```bash
chmod +x ./yaf-run
./yaf-run /absolute/path/to/your/file.pcap
```

2) Or manual build and run:

```bash
docker build -t yaf-super_mediator-silk .
docker run --rm -v /absolute/path/to/pcap/dir:/files -e PCAP_PATH=/files/your.pcap -t yaf-super_mediator-silk
```

Outputs are written into the mounted `/files` directory:
- pcap2ipfix.yaf
- pcap2ipfix-applabel.yaf
- pcap2ipfix-applabel-dpi.yaf
- pcap2ipfix-applabel-yafscii.psv and .csv
- dpi/* exported by super_mediator (per protocol, with headers)
- pcap2ipfix-applabel-silk.rw

Optional: If you have a DPI rules file, mount it at `/files/config/yafDPIRules.conf` and it will be used automatically.

To enable JA3/HASSH fields, this image builds:
- YAF 2.15.0
- super_mediator 1.10.0

Environment variables:
- `PCAP_PATH`: full path to the input pcap inside the container (e.g. `/files/foo.pcap`).
- `PCAP_BASENAME`: if you mounted a directory, you can set the file basename without extension; defaults to `merged_output`.
