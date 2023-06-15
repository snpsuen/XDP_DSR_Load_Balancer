# XDP_DSR_Load_Balancer
## Introduction
The XDP code for direct server return is simplier than the one of https://github.com/snpsuen/XDP_Stateful_Load_Balancer. First, it  does not process any return packets. In additon, there is no change to IP addresses. Only MAC addresses will be modified to transmit Ethernet frames from the load balancer to the backends.
## Build the load balancer
The whole end-to-end set up is to be done in the Killercoda online lab, https://killercoda.com/. The simple load balancer wil be hardcoded to dispatch requests randomly to two backend servers at known IP and MAC addresses.
1. Pull a pre-built eBPF/XDP ready docker to run a container as the platform of the load balancer.
```
docker run -d --privileged --name simplelb -h simplelb snpsuen/ebpfxdp:v05
docker exec -it simplelb bash
```
2. Download this repo, XDP_DSR_Load_Balancer.
```
cd /var/tmp
git clone https://github.com/snpsuen/XDP_DSR_Load_Balancer.git
```
3. Build and attach the load balancer to eth0.
```
cd XDP*
make
ls /sys/fs/bpf
ip addr show eth0
```
4. Open a terminal to the host of the container and display the on-going eBPF/XDP kernel traces in real time.
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Set up backend servers
1. Run a pair of backend servers on the nginx hello docker.
```
docker run -d --name backend-A -h backend-A nginxdemos/hello:plain-text
docker run -d --name backend-B -h backend-B nginxdemos/hello:plain-text
```
2. Login to each backend containers and assign a given virtual IP (VIP) as an alias address to the loopback interface.
```
docker exec -it backend-A sh
ip addr add 192.168.25.10/24 dev lo
```
Similar steps are taken on the baclend-B container. In this case, clients will use the VIP 192.168.10.25 to access the requested service via the load balancer.

## Set up client

docker run -d --name curlclient -h curlclient curlimages/curl:latest sleep infinity
```

## Test it out
The load balancer is hardcoded to the IP 172.17.0.2.
1. Issue a curl command from the curl client to the load balancer in a loop.
```
docker exec -it curlclient sh

while true
do
curl -s http://172.17.0.2
sleep 3
echo ""
done
```
Expect to receive replies randomly from backend-A, 172.17.0.3 or backend-B, 172.17.0.4.
```
~ $ while true
> do
> curl -s http://172.17.0.2
> sleep 3
> echo ""
> done
Server address: 172.17.0.4:80
Server name: backend-b
Date: 14/Jun/2023:17:35:10 +0000
URI: /
Request ID: 7b33d855729771f3c5428497253a7496

Server address: 172.17.0.3:80
Server name: backend-a
Date: 14/Jun/2023:17:35:13 +0000
URI: /
Request ID: 443b0d7e6ad822be6ab4254eccf8f84b

Server address: 172.17.0.4:80
Server name: backend-b
Date: 14/Jun/2023:17:35:16 +0000
URI: /
Request ID: 3e709e55e19ae3aa9236527335aab01c

Server address: 172.17.0.3:80
Server name: backend-a
Date: 14/Jun/2023:17:35:19 +0000
URI: /
Request ID: 2a39c56438dbbf041379e18e09a1fc5f
```code borrows from Liz Rice's sample eBPF load balancer from scratch, https://github.com/lizrice/lb-from-scratch. Our contribution is to provide some basic stateful elements for it to redirect packets belonging to the same TCP connection consistently.
* A forward table to send the traffic of a TCP connection toward a chosen backend server via DNAT.
* A return table to bring the traffic of a TCP connection back to the requesting client via SNAT.
## Build the load balancer
The whole end-to-end set up is to be done in the Killercoda online lab, https://killercoda.com/. The simple load balancer wil be hardcoded to dispatch requests randomly to two backend servers at known IP and MAC addresses.
1. Pull a pre-built eBPF/XDP ready docker to run a container as the platform of the load balancer.
```
docker run -d --privileged --name simplelb -h simplelb snpsuen/ebpfxdp:v05
docker exec -it simplelb bash
```
2. Download this repo, XDP_Stateful_Load_Balancer.
```
cd /var/tmp
git clone https://github.com/snpsuen/XDP_Stateful_Load_Balancer.git
```
3. Build and attach the load balancer to eth0.
```
cd XDP*
make
ls /sys/fs/bpf
ip addr show eth0
```
4. Open a terminal to the host of the container and display the on-going eBPF/XDP kernel traces in real time.
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Deploy backend servers and client
1. Run a pair of backend servers on the nginx hello docker.
```
docker run -d --name backend-A -h backend-A nginxdemos/hello:plain-text
docker run -d --name backend-B -h backend-B nginxdemos/hello:plain-text
```
2. Run a curl client container on the curlimages docker.
```
docker run -d --name curlclient -h curlclient curlimages/curl:latest sleep infinity
```

## Test it out
The load balancer is hardcoded to the IP 172.17.0.2.
1. Issue a curl command from the curl client to the load balancer in a loop.
```
docker exec -it curlclient sh

while true
do
curl -s http://172.17.0.2
sleep 3
echo ""
done
```
Expect to receive replies randomly from backend-A, 172.17.0.3 or backend-B, 172.17.0.4.
```
~ $ while true
> do
> curl -s http://172.17.0.2
> sleep 3
> echo ""
> done
Server address: 172.17.0.4:80
Server name: backend-b
Date: 14/Jun/2023:17:35:10 +0000
URI: /
Request ID: 7b33d855729771f3c5428497253a7496

Server address: 172.17.0.3:80
Server name: backend-a
Date: 14/Jun/2023:17:35:13 +0000
URI: /
Request ID: 443b0d7e6ad822be6ab4254eccf8f84b

Server address: 172.17.0.4:80
Server name: backend-b
Date: 14/Jun/2023:17:35:16 +0000
URI: /
Request ID: 3e709e55e19ae3aa9236527335aab01c

Server address: 172.17.0.3:80
Server name: backend-a
Date: 14/Jun/2023:17:35:19 +0000
URI: /
Request ID: 2a39c56438dbbf041379e18e09a1fc5f
```
