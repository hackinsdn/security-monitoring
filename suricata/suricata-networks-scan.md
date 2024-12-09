# Scan de redes com Suricata 

Uma vez que o Suricata esteja instalado e configurado, pode-se fazer detecções de diversos tipos de ataques de rede, mas este documento focará nos scans de rede, que podem ser feitos utilizando a ferramenta nmap.

## Conceitos

### Definição de scan de redes

Scans de redes são ataques feito de maneira maliciosa para obter informações sensíveis da rede, como IP's ativos em uma subrede, portas ativas em um único IP, e até mesmo é possível obter informações sobre o sistema operacional da máquina que hospeda um determinado IP e sobre softwares ativos nela. A partir dessas informações, é possível determinar alvos e saber quais serviços desses alvos estão ativos e, portanto, podem ser atacados de maneira mais séria. Ou seja, à princípio, o scan de redes não é considerado um ataque extremamente prejudicial, mas os dados obtidos podem ser usados para realização de ataques mais perigosos.

Nesse sentido, existem dois tipos de scan de rede:

1. Scan Horizontal: Scan de um conjunto uma porta em vários ip's;
2. Scan Vertical: Scan de várias portas em um único ip.

### Scan de redes com NMAP

NMAP é uma ferramenta Open Source que pode ser utilizada para fazer scan de redes com o intuito de obter informaões detalhadas de uma ou mais redes, sendo que essas informações podem ser utilizadas para autidorias de segurança e melhor entendimento da rede. [Mais informações](https://nmap.org/).

Os ataques de scan de redes que foram analisados foram:

- *nmap -sS*: Procura promover o início de conexões TCP, enviando pacotes SYN, mas não dá continuidade a elas;
- *nmap -sT*: Procura a estabelcer diversas conexões TCP;
- *nmap -sU*: Envio de diversos pacotes UDP;

    - Os três ataques citados acima têm em comum o objetivo de verificar quais das portas analisadas estão abertas.

- *nmap -sA*: Procura obter informações diversas sobre a máquina analisada, como sistema operacional e versões de sistemas instalados;
- *nmap -sO*: Procura saber qual o sistema operacional da máquina que hospeda o ip analisado;
- *nmap -sX*: Procura saber quais portas estão abertas, enviando pacotes com flags PSH,FIN e URG, de modo a obter respostas específicas do alvo, como serviços ativos.

### Comandos de timing (-T) Nmap:

Os comandos de timing podem ser usados para promover ataques a partir do envio de pacotes TCP controlando a temportização do envio de pacotes. Ou seja, pode-se determinar se mais ou menos pacotes vão ser enviados. Quanto menor a quantidade de pacotes enviados, mais lento é o ataque, porém, as chances de detecção são menores. Os comandos de timing são:

- *nmap -T0*
- *nmap -T1*
- *nmap -T2*
- *nmap -T3*
- *nmap -T4*
- *nmap -T5*

Os ataques -T0 e -T1 são os mais lentos e menos detectáveis. O ataque -T2 envolve envio de pacotes com maior frequência e pode ser detectado por ferramentas como Suricata. Os ataques -T3, -T4 e -T5, tem um aumento gradual na frequência de envio de pacotes, ou seja, o -T5 é o ataque mais agressivo.


## Análise

Para detectar os scans de redes, foi ativado o conjunto de regras *emeging-scan.rules*, pertencente às regras *Emerging Threats*. Além disso, foram usadas regras presentes nos dois seguintes repositórios: 

1. [Regras criadas por Aleksi Bovellan](https://github.com/aleksibovellan/opnsense-suricata-nmaps/blob/main/local.rules);
2. [Regras de autoria própria](https://github.com/mayara-santos01/local.rules/blob/main/local.rules).

Nos seguintes tópicos, vão ser abordadas quais regras geraram alertas para cada tipo de ataque.

***nmap -sT***

Vertical:

- alert tcp any any -> any ![21,22,23,25,80,88,110,135,137,138,139,161,389,443,445,465,514,587,636,995,1025,1026,1027,1028,1029,1433,1720,3306,3389,5900,8443,11211,27017] (msg:"POSSBL SCAN NMAP TCP (type -sT)"; flow:to_server,stateless; flags:S; window:64240; tcp.mss:1460; threshold:type threshold, track by_src, count 15, seconds 60; classtype:attempted-recon; sid:1000008; priority:2; rev:4;)
- alert tcp any any -> any 4444 (msg:"POSSBL SCAN M-SPLOIT B.SHELL TCP"; classtype:trojan-activity; sid:1000015; priority:1; rev:2;)

Horizontal:

- alert tcp $EXTERNAL_NET ![80,443] -> $HOME_NET ![80,443] (msg: "Possible nmap -sT horizontal scan"; flow: to_server, stateless, no_stream; flags:S; window:64240; tcp.mss: 1460; dsize:0; threshold: type both, track by_src, count 1, seconds 20; classtype:attempted-recon; sid:10000020; rev:1;)

***nmap -sS***

Vertical:

- alert tcp any any -> any ![21,22,23,25,80,88,110,135,137,138,139,161,389,443,445,465,514,587,636,995,1025,1026,1027,1028,1029,1433,1720,3306,3389,5900,8443,11211,27017] (msg:"POSSBL SCAN NMAP TCP (type -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 7, seconds 180; classtype:attempted-recon; sid:1000007; priority:2; rev:2;)
- alert tcp any any -> any [21,22,23,25,80,88,110,135,137,138,139,161,389,443,445,465,514,587,636,995,1025,1026,1027,1028,1029,1433,1720,3306,3389,5900,8443,11211,27017] (msg:"SUSP PORT PROBE KNOWN TCP (type -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 4, seconds 1100; classtype:attempted-recon; sid:1000001; priority:2; rev:2;)
- alert tcp any any -> any [21,22,23,25,80,88,110,135,137,138,139,161,389,443,445,465,514,587,636,995,1025,1026,1027,1028,1029,1433,1720,3306,3389,5900,8443,11211,27017] (msg:"POSSBL SCAN NMAP KNOWN TCP (type -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 3, seconds 1210; classtype:attempted-recon; sid:1000002; priority:2; rev:2;)
- alert tcp $EXTERNAL_NET any -> $HOME_NET 5432 (msg:"ET SCAN Suspicious inbound to PostgreSQL port 5432"; flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src; classtype:bad-unknown; sid:2010939; rev:3; metadata:created_at 2010_07_30, former_category HUNTING, updated_at 2019_07_26;)

Horizontal:

- alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 1024"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:1024; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2009582; rev:3; metadata:created_at 2010_07_30, updated_at 2019_07_26;)
- alert tcp any any -> any ![21,22,23,25,80,88,110,135,137,138,139,161,389,443,445,465,514,587,636,995,1025,1026,1027,1028,1029,1433,1720,3306,3389,5900,8443,11211,27017] (msg:"POSSBL SCAN NMAP TCP (type -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 7, seconds 180; classtype:attempted-recon; sid:1000007; priority:2; rev:2;)
- alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg: "Possible nmap -sS horizontal scan";flow: to_server, stateless, no_stream; flags:S; window:1024;tcp.mss:1460; dsize:0; threshold: type both, track by_src, count 5, seconds 20; classtype:attempted-recon;sid:10000021; priority:1; rev:1;)


***nmap -sU***

Vertical:

- alert udp any any -> any [53,67,68,69,123,161,162,389,520,1026,1027,1028,1029,1434,1900,11211,12345,27017] (msg:"POSSBL SCAN NMAP KNOWN UDP (type -sU)"; flow:to_server,stateless; classtype:attempted-recon; sid:1000003; priority:2; rev:7; threshold:type limit, track by_src, count 3, seconds 1210; dsize:0;)
- alert udp $EXTERNAL_NET ![80,443] -> $HOME_NET ![80,443] (msg: "Possible nmap -sU vertical attack"; threshold: type both, track by_src, count 50, seconds 5; classtype:attempted-recon; sid:10000011;rev:1;)
- alert udp any any -> any 4444 (msg:"POSSBL SCAN M-SPLOIT B.SHELL UDP"; classtype:trojan-activity; sid:1000016; priority:1; rev:2;)

Horizontal:

- alert udp any any -> any any (msg: "Possible nmap -sU horizontal scan"; flow:to_server, stateless; dsize:0; threshold: type limit, track by_src, count 15, seconds 5; classtype:attempted-recon; sid:10000124; priority:1; rev:1;

***nmap -sA***

- alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sA (1)"; fragbits:!D; dsize:0; flags:A,12; window:1024; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2000538; rev:8; metadata:created_at 2010_07_30, updated_at 2019_07_26;)
- alert tcp any 4444 -> any any (msg:"POSSBL SCAN M-SPLOIT R.SHELL TCP"; classtype:trojan-activity; sid:1000013; priority:1; rev:1;)
- alert tcp any any -> any 4444 (msg:"POSSBL SCAN M-SPLOIT B.SHELL TCP"; classtype:trojan-activity; sid:1000015; priority:1; rev:2;)

***nmap -sO***

- alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sO"; dsize:0; ip_proto:21; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2000536; rev:7; metadata:created_at 2010_07_30, updated_at 2019_07_26;)
- alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sA (1)"; fragbits:!D; dsize:0; flags:A,12; window:1024; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2000538; rev:8;)
- alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN PING NMAP"; dsize:0; itype:8; reference:arachnids,162; classtype:attempted-recon; sid:2100469; rev:4; metadata:created_at 2010_09_23, updated_at 2019_07_26;)

***nmap -sX***

- alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN nmap XMAS"; flow:stateless; flags:FPU,12; reference:arachnids,30; classtype:attempted-recon; sid:2101228; rev:8; metadata:created_at 2010_09_23, updated_at 2019_07_26;)
  - Esssa regra, padrão do Suricata ou *Emerging Threats*, acaba gerando muitos alertas, por não ter definições de *thresholding*.

#### Referências:

1. [C.Leckie and R. Kotagiri - A Probabilistic Approach to Detecting Network Scans](https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=8691da6113e480795f06186e5c6d3fcb7af91992)
2. [NMAP Official Site - Port Scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html)
3. [NMAP Official Site - Description](https://nmap.org/book/man.html#man-description)
4. [NMAP Official Site - Timing Templates (-T)](https://nmap.org/book/performance-timing-templates.html)

