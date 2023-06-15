# XDP_DSR_Load_Balancer
## Introduction
In comparision, the XDP code for direct server return is simplier. First, it  does not process any return packets. In additon, there is no change to IP addresses by DNAT or SNAT. Only MAC addresses will be modified to transmit Ethernet frames from the load balancer to the backends.
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
4. Open a terminal to the host of the container and trace the on-going eBPF/XDP kernel mesages in real time.
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
Similar steps are taken on the backend-B container. In this case, the VIP is hardcoded to 192.168.10.25, which will be used by clients to access the requested service through the load balancer.

## Set up a client container
1. Run a client container based on the latest curl docker.
```
docker run -d --name curlclient -h curlclient curlimages/curl:latest sleep infinity
```
2. Add a host route to the the VIP 192.168.10.25/32 via the load balancer at 172.17.0.2.
```
docker exec -it curlclient sh
ip route add 192.168.25.10/32 via 172.17.0.2
```

## Test it out
1. Issue a curl command from the curl client to the service VIP in a loop.
```
while true
do
curl -s http://192.168.25.10
sleep 3
echo ""
done
```
Expect to receive replies randomly from backend-A or backend-B.
```
/home/curl_user # while true
> do
> curl -s http://192.168.25.10
> sleep 3
> echo ""
> done
Server address: 192.168.25.10:80
Server name: backend-a
Date: 15/Jun/2023:09:03:44 +0000
URI: /
Request ID: 5821794b6313f1d4770201d5e79abad6

Server address: 192.168.25.10:80
Server name: backend-a
Date: 15/Jun/2023:09:03:47 +0000
URI: /
Request ID: d6ab760758ef93462a422bac5ce2a0cb

Server address: 192.168.25.10:80
Server name: backend-a
Date: 15/Jun/2023:09:03:50 +0000
URI: /
Request ID: aa3c365b30261d13726738c231b6d9f2

Server address: 192.168.25.10:80
Server name: backend-b
Date: 15/Jun/2023:09:03:53 +0000
URI: /
Request ID: 774487b5e3e01967e0bfb5fe86752d16

Server address: 192.168.25.10:80
Server name: backend-a
Date: 15/Jun/2023:09:03:56 +0000
URI: /
Request ID: 616153625c060cde7be942b234ed22a7

Server address: 192.168.25.10:80
Server name: backend-b
Date: 15/Jun/2023:09:03:59 +0000
URI: /
Request ID: d37c0af522469a2e4de74798d0166079
```
