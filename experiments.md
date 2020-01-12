# Experiments

## Execute RAC
* Create the Docker configuration
    ```bash
    {
        "debug": true,
        "ipv6": true,
        "fixed-cidr-v6": "2001:db8::11:0/116"
    }
    ```
* Start the Docker daemon 
    ```bash
    dockerd --config-file /etc/docker/daemon.json --authorization-plugin=authz
    ```
* Run the Busybox RAC:
    ```bash
    docker run -e "AUTHZ_USER=testing" -e "AUTHZ_PASS=password" -e "ipv6=2001:db8::11:2" --ip6 2001:db8::11:2 --name test_ping_protected --rm -it busybox
    ```

Within the Busybox RAC:

* Ping the public server
    ```bash
    ping 2001:db8::aa:0
    ```
* Ping the private server
    ```bash
    ping 2001:db8::bb:0
    ```