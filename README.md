### Add PCAP
Change tor.pcap in run.sh to your pcap name

###  Build image
docker build -t yaf-super_mediator-silk . (this might take 15 minutes or so)

### Run image
docker run -v <path_to_file>:/files -t yaf-super_mediator-silk
