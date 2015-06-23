dnsMole is designed to <i>analyse dns traffic</i>, and to potentionaly detect botnet C&C server and infected hosts. It can be used as passive sniffer, and it can analyse already  sniffed network traffic dumped in .pcap file format. Algorithms implemented in this tool are based on research and can viewed in following papers:

1. Anomaly detection for DNS Servers using frequent host selection ( currently under modification )<br>
2. Botnet detection by monitoring group activities in DNS traffic<br>
3. Extending black domain name list by using co-occurrence relation between DNS queres<br>

Since all this methods heavily depends on treshold parameters, you can define your own parameters in dnsMole configuration file and in that way increase ( or decrease :) ) chances of positive detection. dnsMole support storing  black/white list in memory and in that way it can help classify hosts