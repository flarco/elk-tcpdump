# elk-tcpdump
Code to aggregate tcpdump traffic and send to ELK (Elasticsearch-Logstach-Kibana)

This allows one to send capture a host's network traffic statistics:
  - Source IP/Host/Port to Target IP/Host/Port
  - Aggregate count of packets over time
  - Aggregate length of packets over time

This is ideal to run on firewalls (such as PfSense) and montoring traffic with a service such as ELK (<https://www.elastic.co>)

# Instruction

This was only tested in Ubuntu. The following programs are required:
- tcpdump
- host

To start collecting tcpdump statistics, run the following on the host:
```shell
tcpdump -U -i eth0 -nn -tttt port not 5141 | python tcpdump_aggregate.py "192.168.2.3:5141"
```

in the example above, the tcpdump aggregates will be sent over to host '192.168.2.3' / port 5141.

Here is an example of the received data on 192.168.2.3:5141:
```shell
netcat -ul 5141
{"source_IP": "172.17.0.3", "source_PORT": 22, "target_IP": "172.17.0.1", "target_PORT": 54686, "type": "TCP", "count": 1, "length": 212, "source_HOST": "172.17.0.3", "target_HOST": "172.17.0.1", "time": "2016-09-08 23:27:40.090202"}
{"source_IP": "172.17.0.1", "source_PORT": 54692, "target_IP": "172.17.0.3", "target_PORT": 22, "type": "TCP", "count": 24, "length": 0, "source_HOST": "NXDOMAIN", "target_HOST": "NXDOMAIN", "time": "2016-09-08 23:28:29.073292"}
{"source_IP": "172.17.0.1", "source_PORT": 54690, "target_IP": "172.17.0.3", "target_PORT": 22, "type": "TCP", "count": 1, "length": 52, "source_HOST": "172.17.0.1", "target_HOST": "172.17.0.3", "time": "2016-09-08 23:28:29.073292"}
{"source_IP": "172.17.0.3", "source_PORT": 22, "target_IP": "172.17.0.1", "target_PORT": 54690, "type": "TCP", "count": 1, "length": 0, "source_HOST": "172.17.0.3", "target_HOST": "172.17.0.1", "time": "2016-09-08 23:28:29.073292"}
{"source_IP": "172.17.0.3", "source_PORT": 22, "target_IP": "172.17.0.1", "target_PORT": 54692, "type": "TCP", "count": 24, "length": 3888, "source_HOST": "172.17.0.3", "target_HOST": "172.17.0.1", "time": "2016-09-08 23:28:29.073292"}
{"source_IP": "172.17.0.1", "source_PORT": 54686, "target_IP": "172.17.0.3", "target_PORT": 22, "type": "TCP", "count": 1, "length": 0, "source_HOST": "172.17.0.1", "target_HOST": "172.17.0.3", "time": "2016-09-08 23:28:29.073292"}
```

With this process, we can use Logstash to parse this data and ingest into Elasticsearch, then view in Kibana.
