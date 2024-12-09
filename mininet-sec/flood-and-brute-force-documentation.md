# Execution and detection of attacks using mnsec and Suricata 

The usage of Mininet-sec detailed in this text was based in the use of the basic topology contained in *firewall.py* file.

## Brute Force

There are plenty of authentication techniques which can be used in Brute Force attacks: 

- SSH: LOGIN (default), PLAIN, CRAM-MD5, DIGEST-MD5, NTLM
   - Additionally TLS encryption via STARTTLS can be enforced with the TLS option. Example: smtp://target/TLS:PLAIN; [Reference](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra-smtp.c#L473).
- IMAP: CLEAR or APOP (default), LOGIN, PLAIN, CRAM-MD5, CRAM-SHA1,CRAM-SHA256, DIGEST-MD5, NTLM
   - Also supports TLS like: imap://target/TLS:PLAIN; [Reference](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra-imap.c#L591)
- POP3: CLEAR (default), LOGIN, PLAIN, CRAM-MD5, CRAM-SHA1, CRAM-SHA256, DIGEST-MD5, NTLM.
   - Also supports TLS like: pop3://target/TLS:PLAIN; [Reference](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra-pop3.c#L779)

In the usage of Mininet-sec documented, the main authentication technique used was LOGIN. The Honeypots Python Package, which is being used in the Mininet-sec project, only supports PLAIN authentication technique, and returns a message of successful execution, which can be a problem, since one of the objectives of the use of honeypots is to deceive the attacker and keep them executing commands, in order to be able to better analyse the attack process. Some solutions to this issue, such as modifying Honeypots Package, can be applied in future versions of Mininet-sec. 

### IMAP 

Command executed in the directory that contained the passwords and logins list:

```
sudo mnsecx o1 hydra  -L top-usernames-shortlist.txt -P top-usernames-shortlist.txt imap://192.168.1.103/LOGIN -V -I -F
```

Rules that generated alerts:

1. alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"ET SCAN Rapid IMAP Connections - Possible Brute Force Attack"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 60; classtype:misc-activity; sid:2002994; rev:7; metadata:created_at 2010_07_30, updated_at 2019_07_26;)
2. alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg: "Possible IMAP Brute Force attack"; flags:S; flow: to_server; threshold: type limit, track by_src, count 20, seconds 40; tcp.mss:1460; dsize:0; window:42340; classtype: credential-theft; sid: 100000137; rev:1;) (self-authored)

### SSH

Command executed in the directory that contained the passwords and logins list:

```
sudo mnsecx o1 hydra  -L top-usernames-shortlist.txt -P top-usernames-shortlist.txt ssh://192.168.1.103/LOGIN -V -I -F
```

Rule that generated alerts:

1. alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 120; reference:url,en.wikipedia.org/wiki/Brute_force_attack; classtype:attempted-recon; sid:2001219; rev:20; metadata:created_at 2010_07_30, updated_at 2019_07_26;)

### POP3

Command executed in the directory that contained the passwords and logins list:

```
sudo mnsecx o1 hydra  -L top-usernames-shortlist.txt -P top-usernames-shortlist.txt pop3://192.168.1.103/LOGIN -V -I -F
```

Rule that generated alerts:

1. alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg: "Possible POP3 Brute Force attack"; flags:S; flow: to_server; threshold: type threshold, track by_src, count 5, seconds 20; classtype: credential-theft; sid: 100000138; rev:1;) (self-authored)

## TCP, UDP and ICMP Flood

### --rand-source

Is a Hping3 attacks parameter which promotes the usage of diverse IP addresses to execute floods. In this sense, all ICMP, UDP and TCP flood attacks triggered ET DROP rules. These rules are based in the detection of activities related to IP addresses known by their relation with flood attakcs.

### Single IP attacks

Usage example (Executed in mnsec shell):

```
<mnsec-host> hping3 <protocol-or-tcp-flag> --flood -p <port-number> <ip-address> 
```

```
o1 hping3 --icmp/--udp --flood --rand-source -p 567 --data 10 192.168.1.103 (h3 host ip address)
```

```
o1 hping3 -S/-P/-U/-A/-F --flood --rand-source -p 567 --data 10 192.168.1.103 (h3 host ip address)
```

### TCP Flood

Using ports not related to specific functions in internet traffic:

1. alert tcp any 4444 -> any any (msg:"POSSBL SCAN M-SPLOIT R.SHELL TCP"; classtype:trojan-activity; sid:1000013; priority:1; rev:1;)

**SSH port:**

Rule that generated alerts:

1. alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 120; reference:url,en.wikipedia.org/wiki/Brute_force_attack; classtype:attempted-recon; sid:2001219; rev:20; metadata:created_at 2010_07_30, updated_at 2019_07_26;)

**POP3 ports:**

Rule that generated alerts:

1. alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg: "Possible POP3 Brute Force attack"; flags:S; flow: to_server; threshold: type limit, track by_src, count 5, seconds 20; classtype: credential-theft; sid: 100000138; rev:1;) (self-authored)
2. alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"ET SCAN Rapid POP3 Connections - Possible Brute Force Attack"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 120; classtype:misc-activity; sid:2002992; rev:7; metadata:created_at 2010_07_30, updated_at 2019_07_26;)

**IMAP Flood**

Rules that generated alerts:

1. alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"ET SCAN Rapid IMAP Connections - Possible Brute Force Attack"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 60; classtype:misc-activity; sid:2002994; rev:7; metadata:created_at 2010_07_30, updated_at 2019_07_26;)

### UDP Flood 

Rule that generated alerts:

1. alert udp any 4444 -> any any (msg:"POSSBL SCAN M-SPLOIT R.SHELL UDP"; classtype:trojan-activity; sid:1000014; priority:1; rev:1;)

### ICMP Flood 

Was not detected by any rule, and the difficulties related to the detection of ICMP Floods can be justified by the challenge of differentiating legitm traffic involving ICMP from malicious one. 

### Fragmentation

The promotion fragmentation of packets fragmentation in traffic can happen, for example in these ways:

1. Seding of a traffic in which the packets have a data sizer greater than the MTU of the targeted computer;
2. Sending of packets with a data size smaller or equal to the MTU of the targetd computer, however, using techniques to promote the fragmentation;
3. Reducing the MTU of the computer.

The flood attacks with packets fragmentation were not detected by Suricata, and there are difficulties to create rules in this sense due to the difficulty in obtaining informations about traffic related to this type of attack. Moreover, reassembling packets in order to analyse is a resource and time consumpting task, increasing the complexity of attacks investigation.

## Conclusion

In general, Suricata made a good detection of attacks promoted, and it was also possible to create new rules for the cases in which the detection was not happening, and the custom rules also had a good performance. Since some rules are based on the features of the packets related to the traffic which we want to create alerts for, some rules triggered for both Brute Force and Flood attacks related to SSH, IMAP and POP3 protocols. The Suricata rules for *Possible Scan M-Sploit R.Shell TCP/UDP* only triggered for Flood attacks. These rules detect attempts of exploitation of the network to detect vulnerabilities, in order to implement remote shell, i.e., is an attack related to attempts of getting remote shell acess over an targeted computer.
