# Zeek Info

- Zeek is a traffic monitoring tool which generates logs about the network activities, and, thus, these informations can be used to detect anomalies in the traffic;
- There is the possibility of promoting a custom analysis over the traffic, generating specific logs with information that interests the user.
  
### Zeek structure

- Analyzers: Parse the incoming traffic, and divide the payload in units. Each unit have parameters, related to the processing of specific parts of the payload;
- Events: Whenever Zeek ends the processing of a unit, an event is generated;
- Scripts: One of the main functions of Zeek Scripts is to generate logs based on the events. In this sense, events can be used as functions in scripts, to define the execution of some commands in the context of the triggering of an event;
- In this sense, the parameters defined in the analyzers can be used in the scripts, just like a parameter of a common function.

## Creating a new script in Zeek

- Zeek's documentation has plenty of information on the topic of creating [new scripts](https://docs.zeek.org/en/master/scripting/basics.html);
- If you want to develop a new script, you can create a new folder in the directory `/usr/local/zeek/share/zeek/policy/protocols`, and place your script in there. A zeek script is a `.zeek` file.
- Then, to make Zeek recognize your script, you should change the `local.zeek` file, located in the `/usr/local/zeek/share/zeek/site/` directory, and add some lines, like it is shown in the following example:

```
# Write a brief description of your script
@load protocols/<your_folder_name>/<your_script_name>
```

- You should **not** write the `.zeek` extension while adding tour script to `local.zeek` file.

## Creating a new analyzer

- The generation of logs in Zeek is related to analyzers which parse packets to detect a certain protocol. From this parsing, it is possible to determine events related to a protocol, and they can be mentioned in scripts to provoke the execution of some actions following their triggering, including the generation of logs;
- In this sense, the parsing of packets is realized by Spicy, a parser generator whose deep integration with Zeek simplifies the creation of new analyzers;
- You can read more information about Zeek analyzers in [Zeek's documentation](https://docs.zeek.org/en/master/devel/spicy/getting-started.html) and also in [Spicy's documentation](https://docs.zeek.org/projects/spicy/en/latest/getting-started.html).

To create a new analyzer in Zeek, you can run the following command:

``` 
zkg create --features=spicy-protocol-analyzer --packagedir MyProtocol
```

Where *MyProtocol* is just a mock name for the analyzer.

Then, you will have to make some configurations, like in the following example:


```matlab
"package-template" requires a "name" value (the name of the package, e.g. "FooBar" or "spicy-http"): 
name: MyProtocol
"package-template" requires a "analyzer" value (name of the Spicy analyzer, which typically corresponds to the protocol/format being parsed (e.g. "HTTP", "PNG")): 
analyzer: myprotocol
"package-template" requires a "protocol" value (transport protocol for the analyzer to use: TCP or UDP): 
protocol: TCP
"package-template" requires a "unit_orig" value (name of the top-level Spicy parsing unit for the originator side of the connection (e.g. "Request")): 
unit_orig: my_unit
"package-template" requires a "unit_resp" value (name of the top-level Spicy parsing unit for the responder side of the connection (e.g. "Reply"); may be the same as originator side): 
unit_resp: my_unit
```

After that, you should change the files in the `analyzer` file, in order to define the parameters of parsing as well as defining events and confirm the activation of the protocol. It is essential to read the comments present in the files to understand which changes make in each file. You should also change the `scripts/main.zeek` file, in order to define logs over the events defined.

Then, you can compile the `.evt` and `.spicy` file in a binary and executable `.htlo` using spicyz:

```
spicyz -o myprotocol.htlo myprotocol.spicy myprotocol.evt
```

After that, you can read files using tour custom protocol, like in the following example:

```
zeek -Cr traffic_file.pcap myprotocol.htlo main.zeek
```

Building the custom analyzer:

```
rm -rf build
mkdir build
cd build
cmake ..
cmake --build .
```

```
sudo rm -rf build
mkdir build
cd build
sudo cmake ..
sudo cmake --build .
```

## Installation of a custom analyzer

Two processes are important when you want to install a custom analyzer: Building and testing it. Building process can be described as the compilation of codes contained in the analyzer in order to allow its implementation on Zeek. On the other hand, testing processes the execution of simple commands using the analyzer, in order to observe its coherence.

In this sense, Zeek uses [Btest](https://github.com/zeek/btest#btest---a-generic-driver-for-powerful-system-tests) framework to execute tests. Its documentation has important information about the testing processing, which can be useful if you are developing a custom analyzer.

In order to test your analyzer, after implementing the right features to detect the desired protocol, you can build it and then change the [baselines](https://github.com/zeek/btest#using-baselines) of BTest in order to update the expected results of the tests.

1. Change the test files, if necessary, adding `.pcap` files related to the protocol that is being studied in `trace.zeek` file or changing the test string in `standalone.spicy` file.
2. Building the custom analyzer:

    ```
    rm -rf build
    mkdir build
    cd build
    cmake ..
    cmake --build .
    ```
3. To update the baselines:
   ```
   cd testing
   btest -U tests/standalone.spicy && btest -U tests/trace.zeek
   ```
   It is interesting to execute `btest --help` and see parameters that can help you make troubleshooting, like verbose (-v) and diagnostic (-d).
   
4. Testing the analyzer:
   ```
   cd testing
   btest -c btest.cfg
   ```

If all tests are succesful, you are ready to install the custom analyzer.

To install your custom analyzer in order to apply it in live network analysis, you can execute the following command:

```
zkg install /path/to/your/analyzer
```

Make sure you are using the [most recent version](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html#installation) of zkg. Zkg stands for Zeek Packet manager, which "makes it easy for Zeek users to install and manage third party scripts as well as plugins for Zeek and ZeekControl" [{1}](https://github.com/zeek/package-manager#zeek-package-manager).


OBS:

grep -r "modules_name" /usr/local/zeek/logs/current/loaded_scripts.log 

zeek -NN | grep -i 'your_analyzer'

Download the latest version of zeek, develop the custom analyzer in a docker container using the latest zeek image, then save the folder of the analyzer in your local host and save it in a git repository. Whenever you make major changes in the analyzer, run a docker container with the folder containing the analyzer (insert example code) and update the baselines. After that, you should remove the analyzer and install it again.

```
docker pull zeek/zeek:latest
docker run --rm -it zeek/zeek:latest bash
docker run --rm -it /PathToCustomAnalyser:/CustomAnalyser zeek/zeek:latest bash
apt-get update && apt-get install -y --no-install-recommends g++ cmake make libpcap-dev vim
```
