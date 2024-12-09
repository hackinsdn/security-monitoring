# Documentação Suricata



  Este repositório contém informações sobre o processo de desinstalação, instalação e configuração da ferramenta de IDS Suricata. Para obter mais informações sobre Suricata, é recomendado acessar a [documentação oficial](https://docs.suricata.io/). Em caso de dúvidas, é válido consultar o [fórum](https://forum.suricata.io/) oficial do Suricata, onde diversos problemas são discutidos.
  
**⚠️ OBS**: As informações são relacionadas à utilização do Suricata no sistema operacional Ubuntu versão 22.04. Alguns comandos podem precisar de alterações a depender do sistema operacional utilizado.

## Instalação



  Para instalar Suricata, execute os seguintes comandos:

```
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```

  Para verificar se a instalação foi bem sucedida, execute:

```
suricata -V
```
  Este comando deve ter como retorno a versão instalada do Suricata.
  
## Configuração

### Suricata Update



Suricata Update é uma ferramenta utilizada para gerenciar as regras instaladas, podendo ser usada para atualizar as regras, bem como também é usada para ativar, desativar, configurar e alterar regras a partir de arquivos específicos. Nesse sentido, é uma ferramenta essencial a ser instalada para melhor aproveitamento dos recursos do Suricata.

Verifique se Suricata Update está instalado:

```
suricata-update -V
```

Caso não esteja, instale utilizando o seguinte comando:

```
sudo pip install --upgrade suricata-update
```

### Verificação de diretório dos arquivos instalados



  Um dos primeiros passos da configuração é verificar se os principais arquivos foram instalados no diretório padrão. Alguns exemplos de arquivos a serem verificados são:

  - _drop.conf_: Neste arquivo, as regras mencionadas irão se tornar do tipo _drop_, ou seja, o tráfego relacionado à regra será descartado.
  - _modify.conf_: Neste arquivo, pode-se promover alterações de regras.
  - _enable.conf_: Arquivo no qual o usuário pode-se especificar as regras que deseja ativar.
  - _update.yaml_: Este arquivo é usado para promover atualização das regras existentes, a partir dos 3 arquivos mencionados anteriormente e a partir de outras configurações.

  Esses arquivos, por padrão, deveriam estar no diretório _/etc/suricata_. Se não estiverem, você pode encontrar o diretório que contém esses aquivos executando o seguinte comando:

```
sudo find / -name "nome_do_arquivo"
```
  E, em seguida, mover para o diretório padrão:

```
sudo mv /diretorio/arquivo /etc/suricata
```

  Também é necessário verificar em qual diretório foram instaladas as regras padrão e modificar o diretório especificado para as regras no arquivo _update.yaml_, caso não seja o padrão. Isso pode ser feito acessando o arquivo _update.yaml_ e, em seguida, modificando as seguintes linhas:

```
local:
  # A directory of rules.
  - /usr/share/suricata/rules
  # A single rule file.
  - /usr/share/suricata/rules/app-layer-events.rules
  # A wildcard.
  - /usr/share/suricata/rules/*.rules
```

### Uso de regras _Emerging Threats_



_Emerging Threats_ (ET) é um projeto Open Source que fornece uma grande variedade de regras de detecção de ataques cibernéticos, as quais são atualizadas constantemente.O Suricata possui um conjunto de regras instaladas por padrão, mas é interessante instalar as regras ET para promover uma melhor detecção de ataques.

Tendo isso em vista, baixe o conjunto de regras ET seguindo as instruções [desse link](https://rules.emergingthreats.net/OPEN_download_instructions.html). Depois, mova o arquivo das regras para o diretório anterior ao qual as regras estão instaladas. Ou seja, se as regras foram instaladas em */usr/share/suricata/rules*, mova o arquivo para */usr/share/suricata*. **Isso deve ser feito para que as regras ET fiquem no diretório padrão de regras**. Em seguida, promova a extração do arquivo, executando o seguinte comando:

```
sudo tar -xvzf emerging.rules.tar.gz
```

Outro conjunto de regras que pode ser baixado no diretório padrão de regras, principalmente para detecção de ataques de scan de redes, é o [OPNsense's Suricata IDS/IPS NMAP Detection Rules](https://github.com/aleksibovellan/opnsense-suricata-nmaps), de autoria de Aleksi Bollevan. Deve-se baixar o arquivo *local.rules*.

### Configuração de monitoramento de rede



Para configurar os ips que serão monitorados, é preciso abrir o arquivo _suricata.yaml_ que, por padrão, está presente no diretório */etc/suricata*, e escrever o ip monitorado nesse trecho: 

```
vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
```

Depois disso, se define a interface a partir da qual o tráfego será analisado, no mesmo aquivo, nos seguintes trechos:

```
# Linux high speed capture support
af-packet:
  - interface: eth0
```

```
# Cross platform libpcap capture support
pcap:
  - interface: eth0
```

Onde *eth0* deve ser substituído pela interface a ser monitorada.

Nesse sentido, o Suricata funcionará a partir de uma máquina na qual será monitorada a interface especificada, de modo que o tráfego entre o ip dessa máquina e os ip's especificados em *HOME_NET* pode gerar alertas. Portanto, se voce estiver utilizando uma única máquina para realizar ataques, é recomendado que o ip dela não faça parte do *HOME_NET*, a fim de obter melhores resultados. 

Em sistemas linux possível criar unidades de rede virtuais, a partir das quais podemos realizar experimentos básicos de tráfego, essas unidades se chamam *Network Namespaces*. Essa funcionalidade pode ser útil para criação de ips diversos em única máquina, podendo promover uma melhor utilização do Suricata. [Mais informações](https://www.youtube.com/watch?v=j_UUnlVC2Ss).

## Teste

Verificar se o Suricata está ativo:

```
sudo systemctl status suricata
```

Se não estiver, ative executando:

```
sudo systemctl start suricata
```

Abra o arquivo no qual ficam registrados os alertas Suricata:

```
sudo tail -f /var/log/suricata/fast.log
```

Execute o comando, que realiza uma requisição HTTP:

```
curl http://testmynids.org/uid/index.html
```

Que deve retornar a seguinte resposta:

```
Output
uid=0(root) gid=0(root) groups=0(root)
```

Além disso, deve-se gerar um alerta que ficará registrado em fast.log

## Desinstalação



  Para desintalar o Suricata, execute o seguinte o comando:

```
sudo apt remove suricata 
```

  Além disso, pode-se também apagar todas os arquivos relacionados ao Suricata para evitar conflitos no processo de instalação:

```
sudo find / -type f -name "*suricata*" -exec rm -f {} \;
```

#### Referências

1. [Suricata Install Guide - Digital Ocean](https://www.digitalocean.com/community/tutorials/how-to-install-suricata-on-ubuntu-20-04)
2. [Suricata Official documentation - Quickstart guide](https://docs.suricata.io/en/suricata-7.0.4/quickstart.html#installation)
3. [OISF - suricata-update](https://github.com/OISF/suricata-update#suricata-update)
4. [Suricata uninstallation](https://www.thelinuxfaq.com/ubuntu/ubuntu-17-04-zesty-zapus/suricata?type=uninstall)









