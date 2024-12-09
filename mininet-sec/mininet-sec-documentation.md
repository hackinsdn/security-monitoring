# Activation

[Installation of Mininet-sec](https://github.com/mininet-sec/mininet-sec?tab=readme-ov-file#mininet-sec)

If you get the error message *"No module called Mininet"* during the instllation process, even with Mininet already installed in your system, you can execute the following commands to solve the problem:

```
sudo -i
cd ~
git clone https://github.com/mininet/mininet.git
export PYTHONPATH=$PYTHONPATH:$HOME/mininet
```

[Kytos-ng](https://github.com/kytos-ng/kytos?tab=readme-ov-file#kytos-ngkytos) is the SDN controller which will be used along with mnsec, in order to create and manage the connections between the components of the netowork, beyond executing other functions. It can be activated in different ways. Each one of the processes further described should be executed in different windows. 

⚠️ The steps 1 and 3 are not necessary if the user is going to use the topology defined in *firewall.py* file, they are necessary to activate Kytos-ng, in order to allow its use as a remote controller, and stablish the connections between the components of the network (NOS activation), in case of use of a custom topology.

### 1. Activate Kytos;

```
source test_env/bin/activate
cd teste
cd kytos
sudo ./docker/scripts/add-etc-hosts.sh 
export MONGO_USERNAME=mymongouser
export MONGO_PASSWORD=mymongopass
docker compose up -d
docker ps 
kytosd -f --database mongodb
```

### 2. Iniciate mnsec;

**It is important to use root mode while executing these commands.** Mnsec can be used with pre-defined topologies, for instance:

```
cd mininet-sec
cd examples
python3 firewall.py
```

In this topology, we have 3 internal hosts (h1,h2,h3), 1 external server (o1), 2 servers (srv1,srv2), 3 switches (s1,s2,nettap1) and the presence of a firewall (fw0)

This is the network established:

1. fw0 fw0-eth0:s1-eth4 fw0-eth1:s2-eth3 fw0-eth2:nettap1-eth1
2. h1 h1-eth0:s1-eth1
3. h2 h2-eth0:s1-eth2
4. h3 h3-eth0:s1-eth3
5. o1 o1-eth0:nettap1-eth2
6. srv1 srv1-eth0:s2-eth1
7. srv2 srv2-eth0:s2-eth
8. nettap1 lo:  nettap1-eth1:fw0-eth2 nettap1-eth2:o1-eth0 nettap1-ethmona:  nettap1-ethmonb:
9. s1 lo:  s1-eth1:h1-eth0 s1-eth2:h2-eth0 s1-eth3:h3-eth0 s1-eth4:fw0-eth0
10. s2 lo:  s2-eth1:srv1-eth0 s2-eth2:srv2-eth0 s2-eth3:fw0-eth1

nettap1 is a switch which promotes the connection between the internal components of the net and the internet, through the firewall interface fw0-eth2. It also uses the interface nettap-eth2 to connect with o1 host. Moreover, there are interfaces which promotes the connection of the firewall and the internet:

1. nettap1-ethmona: Connection with the internet, promotes the sending of traffic from the firewall towards internet.
2. nettap1-ethmonb: Connection with the internet, promotes the sending of traffic from the internet towards firewall.


or the user can create a custom topology, for instance:

```
mnsec --topo linear,3 --apps h3:ssh:port=22,h3:http:port=80,h3:ldap,h3:smtp,h3:imap,h3:pop3 --controller=remote,ip=127.0.0.1
```

In this case, we are creating a linear topology with 3 hosts (h1,h2,h3), and the h3 has some important ports in h3 defined as open, in order to test attacks.

### 3. Activation of NOS;

```
for sw in $(curl -s http://127.0.0.1:8181/api/kytos/topology/v3/switches | jq -r '.switches[].id'); do curl -H 'Content-type: application/json' -X POST http://127.0.0.1:8181/api/kytos/topology/v3/switches/$sw/enable; curl -H 'Content-type: application/json' -X POST http://127.0.0.1:8181/api/kytos/topology/v3/interfaces/switch/$sw/enable; done

for l in $(curl -s http://127.0.0.1:8181/api/kytos/topology/v3/links | jq -r '.links[].id'); do curl -H 'Content-type: application/json' -X POST http://127.0.0.1:8181/api/kytos/topology/v3/links/$l/enable; done
```
```
curl -H 'Content-type: application/json' -X POST http://127.0.0.1:8181/api/kytos/mef_eline/v2/evc/ -d '{"name": "my evc1", "dynamic_backup_path": true, "enabled": true, "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"}, "uni_z": {"interface_id": "00:00:00:00:00:00:00:01:2"}}'
```

