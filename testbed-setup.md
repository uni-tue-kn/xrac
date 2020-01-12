# Testbed Setup

In the following, we describe testbed setup instructions for xRAC. The instructions were tested on Ubuntu 18.04.3 LTS and might differ on other platforms.

## Testbed Host

### Install Ryu SDN Controller + xRAC CA Application
Installation instructions:
* Install Ryu from source code:
    ```bash
    $ git clone git://github.com/osrg/ryu.git
    ```
* Include `lib/packet/EAP.py` and `lib/packet/RADIUS.py` from the `xrac-ca` folder
* Install requirements with PIP: `pip install -r tools/pip-requires`
* Install Ryu with `python ryu/setup.py install`

Afterwards, the 802.1X CA can be started with `ryu-manager app/EAPoUDP.py` from the `xrac-ca` folder.

### Setup Open vSwitch

Open vSwitch is already part of Ubuntu 18.04.3 LTS. Verify its status with `systemctl status openvswitch-switch.service`. To create the SDN switch used in the testbed, please perform the following steps:

* Create a new OvS bridge:
    ```bash
    ovs-vsctl add-br mybridge
    ```
* Setup the Ryu OpenFlow controller
    ```bash
    ovs-vsctl set-controller mybridge tcp:127.0.0.1:6653
    ```
* Create tap devices (vnet0, vnet1, vnet2) for the three VMs (managed host, public server, private server) and add them to the bridge
    ```bash
    ip tuntap add mode tap vnet0
    ip link set vnet0 up
    ovs-vsctl add-port br0 vnet0
    ```
* Configure an IPv6 address for the bridge
    ```bash
    ifconfig mybridge inet6 add 2001:db8::1/64
    ```

### Setup FreeRADIUS 802.1X AS

* Install via `apt install freeradius`
* Copy the following files from `xrac-as` to `/etc/freeradius/3.0/`:
  - `clients.conf` (add xRAC-CA application as RADIUS client)
  - `dictionary` (add new vendor and additional Vendor-Specified-Attributes (VSPs))
  - `site-available/default` (add policies, e.g. restict access to a given docker-image-id)
  - `users` (specify reply attributes, e.g. allowed IP addresses)
*  Stop FreeRADIUS service:
    ```bash
    systemctl stop freeradius.service
    ```
* Run FreeRADIUS in interactive mode:
    ```bash
    freeradius -X
    ```

## xRAC Managed Host Setup

### VM Setup
* Create a VirtualBox VM with Ubuntu Server 18.04.3 LTS
* Set up a bridged network interface to `vnet0`
* Set up a static IPv6 Address using netplan (`/etc/netplan/01-xrac-mh.yaml`):
    ```bash
    network:
        ethernets:
            enp0s3:
                addresses:
                - 2001:db8::11:0/64
                dhcp4: no
                dhcp6: no
        version: 2
    ```
* Apply the new netplan configuration
    ```bash
    netplan apply
    ```

### Docker Setup
* Install requirements
    ```bash
    apt install apt-transport-https ca-certificates curl software-properties-common
    ```
* Add GPG key for official Docker repo
    ```bash
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    ```
* Add Docker package repository
    ```bash
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
    ```
* Update package manager and install Docker
    ```bash
    apt update
    apt install docker-ce
    ```
* Verify that the Docker daemon can be executed corectly
    ```bash
    systemctl status docker
    ```
* Disable the Docker daemon
    ```bash
    systemctl disable docker
    ```

### Install 802.1X CS
* Install Python 3 requirements (`Flask`, `docker`, `uWSGI`) via PIP
* Install uWSGI for Python 3 with
    ```bash
    apt install uwsgi_python3
    ```
* Run the 802.1X CS via uWSGI
    ```bash
    uwsgi_python3 --ini uwsgi.ini
    ```

### Configure and Start NDPPD

* Set `/etc/ndppd.conf` to
    ```bash
    route-ttl 30000
    proxy enp0s3 {
    router yes
    timeout 500   
    ttl 30000
    rule 2001:db8::/64 {
        auto
    }
    }
    ```
* Start `ndppd` via `ndppd -vv -c /etc/ndppd.conf`


## Public Server
* Create a VirtualBox VM with Ubuntu Server 18.04.3 LTS
* Set up a bridged network interface to `vnet1`
* Set up a static IPv6 Address using netplan (`/etc/netplan/01-xrac-public-server.yaml`):
    ```bash
    network:
        ethernets:
            enp0s3:
                addresses:
                - 2001:db8::aa:0/64
                dhcp4: no
                dhcp6: no
        version: 2
    ```
* Apply the new netplan configuration
    ```bash
    netplan apply
    ```


## Private Server
* Create a VirtualBox VM with Ubuntu Server 18.04.3 LTS
* Set up a bridged network interface to `vnet1`
* Set up a static IPv6 Address using netplan (`/etc/netplan/01-xrac-private-server.yaml`):
    ```bash
    network:
        ethernets:
            enp0s3:
                addresses:
                - 2001:db8::bb:0/64
                dhcp4: no
                dhcp6: no
        version: 2
    ```
* Apply the new netplan configuration
    ```bash
    netplan apply
    ```