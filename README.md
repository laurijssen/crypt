# crypt

# Docker related setup

* sudo apt-get install \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
* sudo mkdir -p /etc/apt/keyrings
* curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
* install docker on every host ```sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin```
* sudo systemctl enable docker
* change its bridged ip to something else than 172.17.x.x, otherwise workstations in the 172.17 network cant reach it anymore
* login from the kube master to get this done
* sudo systemctl start docker
* add local docker container registry. ```docker run -d -p 5000:5000 --restart=always --name registry registry:2```

Let docker pull the containers insecurely by editing /etc/docker/daemon.json :

```
{
    "bip": "10.200.200.90/24"
    "insecure-registries" : [ "ubdock05.fujicolor.nl:5000" ]
}
```

## pull latest pablo by running pull_pablo.sh script

./pull_pablo.sh s.laurijxxx@fujicolor.nl ~/.ssh/certif

## Add service which changes docker0 to 10.x.x.x and removes 172.17.x.x

Unit file looks like:

```
[Unit]
Description=Change docker0 default IP
# When systemd stops or restarts the docker.service, the action is propagated to this unit
PartOf=docker.service
# Start this unit after the docker.service start
After=docker.service

[Service]
# The program will exit after running the script
Type=oneshot
#Execute the shell script
ExecStart=/bin/bash /lib/systemd/system/docker-network-setup.sh
# This service shall be considered active after start
RemainAfterExit=yes

[Install]
# This unit should start when docker.service is starting
WantedBy=docker.service
```

Create script docker-network-service.sh:

```
ip=$(hostname -i | awk -F. ' { print $4 } ')
sudo ip addr add dev docker0 10.200.200.${ip}/24
if [[ $? -eq 0 ]];
then
        sudo ip addr del dev docker0 172.17.0.1/16
fi
```

Add bridged ip of docker0 to /etc/docker/daemon.json

```
{
    "bip": "10.200.200.90/24",
    "insecure-registries" : [ "10.203.32.90:5000" ]
}
```

### VMWare specific change

Add the following to /etc/multipath.conf and restart multipathd to get rid of VMWare harddisk sda sdb failures.

```
blacklist {
    device {
        vendor "VMware"
        product "Virtual disk"
    }
}
```

## Let iptables see bridged traffic

iptables is used for forwarding packets to nodes / pods.

```
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
br_netfilter
EOF

cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

sudo sysctl --system
```

## docker without sudo

To run docker without sudo.

```
sudo groupadd docker
sudo usermod -aG docker $USER
```

login again or reboot

# running the pablo server

## Create the systemd service

**create the unit file** and call it pablo.service

```
[Unit]
Description=Web server handling pablo calls

[Service]
User=root
WorkingDirectory=/usr/local
ExecStart=/usr/bin/python3 server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

* copy this file on every server to /etc/systemd/system/pablo.service
* copy server.py to /usr/local, the unit file points to that script
* sudo systemctl daemon-reload
* sudo systemctl restart pablo
* sudo systemctl enable pablo

## logging from pablo

To follow logging from pablo

```sudo journalctl -u pablo -f```

or no filter on pablo

```sudo journalctl -f```

# Kubernetes setup

* install k8s signing key
* curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add
* sudo apt-add-repository "deb http://apt.kubernetes.io/ kubernetes-xenial main"
* sudo apt-get install kubeadm kubelet kubectl
* sudo apt-mark hold kubeadm kubelet kubectl

Everything is installed. Now initialize the master node.

```sudo kubeadm init --pod-network-cidr=10.244.0.0/16```

pod-network-cidr **must** be 10.244.0.0/16 as we have to install a container network interface. We'll take flannel's CNI and that uses 10.244.0.0 for its internal network.

```sudo kubeadm join 10.203.32.80:6443 --token u2jppa.0wlyabb2gpx3j5vc --discovery-token-ca-cert-hash sha256:ad743f9d1e85d0c48425e5ad8f8c0aeafde69d12267dc123940c1d1f78a2405f```

When the issue arises that the join command runs forever pass the flag --v=3 . verbosity 3 prints what it is doing exactly.
The time must be the same on all servers as certificate expiration and start times depend on that.

### manually updating k8s certificates

```kubeadm certs check-expiration```

[check-expiration] Reading configuration from the cluster...
[check-expiration] FYI: You can look at this config file with 'kubectl -n kube-system get cm kubeadm-config -o yaml'

CERTIFICATE                EXPIRES                  RESIDUAL TIME   CERTIFICATE AUTHORITY   EXTERNALLY MANAGED
admin.conf                 Jul 06, 2024 07:44 UTC   27d             ca                      no
apiserver                  Jul 06, 2024 07:44 UTC   27d             ca                      no
apiserver-etcd-client      Jul 06, 2024 07:44 UTC   27d             etcd-ca                 no

```kubeadm certs renew all``` and all certificates are renewed

```sudo kubeadm reset``` to leave cluster and on master ```kubectl delete node NODE_NAME```

```kubeadm token create --print-join-command```

Will print out:

```kubeadm join 192.168.56.3:6443 --token ir9pss.8hz2ih9l7gpv5tf6     --discovery-token-ca-cert-hash sha256:c6a89e6267d282d0b0a380c43bee640e1cdf44b265eb0d48093a3e70537c63c4```

A token is 24 hours valid

To work with the correct certificates again

* mkdir -p $HOME/.kube
* sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
* sudo chown $(id -u):$(id -g) $HOME/.kube/config

### enable autocompletion for kubectl

To enable autocompletion for kubectl:

```echo 'source <(kubectl completion bash)' >>~/.bashrc```

Usually an alias is created for kubectl alias k='kubectl' and autocompletion for aliases do not work automatically.

Add the following line to bashrc to have autocomplete work on alias 'k' too:

```complete -F __start_kubectl k```

## Install flannel CNI

Well deploy the flannel daemonset from a yaml, but it must be edited first.

So download it:
``` curl https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml -O```

Edit the part for the kube-flannel container and add --iface=enp0sxxxx, check the interface of the kubemaster's ip that is publicly available and enter that.

```ip -4 addr show```

```
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.168.56.3/24 brd 192.168.56.255 scope global enp0s8
       valid_lft forever preferred_lft forever
```

So in this case --iface=enp0s8 is the correct one

```
      containers:
      - name: kube-flannel
        image: quay.io/coreos/flannel:v0.14.0
        command:
        - /opt/bin/flanneld
        args:
        - --ip-masq
        - --kube-subnet-mgr
        - --iface=enp0s8 [!!!!!!]
```

``` sudo kubectl apply -f kube-flannel.yml ```

Also, in on premise environments it can happen that services still are not reachable.

One solution for this is to change vxlan into host-gw in kube-flannel.yaml. host-gw lets flannel create IP routes to subnets via remote machine IPs, but it requires direct layer2 connectivity between the machine. So it only works on premise not on cloud providers.

```
  net-conf.json: |
    {
      "Network": "10.244.0.0/16",
      "Backend": {
        "Type": "host-gw"
      }
    }
```

And apply....or apply at runtime

```kubectl edit cm -n kube-system kube-flannel-cfg```

replace vxlan with host-gw

**this is not recommended but it does work in on premise environments**

## joining a windows node to the linux cluster

It is possible to let a windows machine join a cluster, the only prerequisite is that the api-controller *must* be linux (as it is now).

Information taken from here:

https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/adding-windows-nodes/

When flannel uses *vxlan* type (cloud providers) net-conf.json section must be altered.

Add:
* VNI 4096
* Port 4789

net-conf.json: |
    {
      "Network": "10.244.0.0/16",
      "Backend": {
        "Type": "vxlan",
        "VNI": 4096,
        "Port": 4789
      }
    }
    
**When using host-gw no changes need to be made.**

Now Windows-compatible versions of Flannel and kube-proxy must be added. 
In order to ensure a compatible version of kube-proxy, substitute the tag of the image. The following example shows usage for Kubernetes v1.24.0 by replacing VERSION with 1.24.0.

```curl -L https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/kube-proxy.yml | sed 's/VERSION/v1.24.0/g' | kubectl apply -f -```

If you're using host-gateway use https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/flannel-host-gw.yml

```curl -L https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/flannel-host-gw.yml | sed 's/VERSION/v1.24.0/g' | kubectl apply -f -```

unfortunately this yaml does not contain the VERSION tag but hardcoded v.0.13.0-nanoserver.

image: sigwindowstools/flannel:v0.13.0-nanoserver

```kubectl apply -f https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/flannel-overlay.yml```

## install containerd or docker engine

*for containerd:*

On the windows machine, start administrator powershell.

run curl for the containerd powershell.
```curl.exe -LO https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/Install-Containerd.ps1```

```.\Install-Containerd.ps1```

*for docker engine:*

Install-WindowsFeature -Name containers


Install crictl from the cri-tools project which is required so that kubeadm can talk to the CRI endpoint.

Install wins, kubelet, and kubeadm

```curl.exe -LO https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/scripts/PrepareNode.ps1```

```.\PrepareNode.ps1 -KubernetesVersion v1.24.0```

Run the usual kubeadm join command. First ```kubeadm token create --print-join-command``` on control plane

When deployed

* kubectl logs -n kube-system kube-flannel-ds-1
* kubectl logs -n kube-system kube-flannel-ds-2
* kubectl logs -n kube-system kube-flannel-ds-3

I0603 07:03:14.430280  1 main.go:533] Using interface with name enp0s8 and address 192.168.56.3
I0603 07:03:14.430280  1 main.go:533] Using interface with name enp0s8 and address 192.168.56.4
I0603 07:03:14.430280  1 main.go:533] Using interface with name enp0s8 and address 192.168.56.5

## Install kubectl windows

To be able to control the cluster from windows:

* Open command prompt, create directory and go there. e.g. D:\k8s
* curl -LO https://dl.k8s.io/release/v1.21.0/bin/windows/amd64/kubectl.exe
* Add D:\k8s to PATH
* Create .kube directory in home directory C:\users\*username*\.kube
* Create file named 'config' and add below content. (content may change when cluster changes)
* Contents of config are generated on master in '/etc/kubernetes/admin.conf'
* Done. run 'kubectl cluster-info'

```
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJeE1EY3dOakEzTkRRd05sb1hEVE14TURjd05EQTNORFF3Tmxvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTTZQCkk5WDQ0L0NyZjF4dkhCVjREOFZmYmppYzd6cGFGbEZqZVdhdDFuT0ZiVDJtbEIvaWFvTlh5Sk1UdTNuNzdRN2IKV2Q2ZGc1OHZYUkFLb1V4aWRPQlFUbVFMbkJmdnhqUWhvb2JHMmVyNVZDekVCeDJOM1VINzlJY1owMXZlRkY2RApyKzlGZUZXY2xOcjdlSlNoU0FHcVdrMEhwNDZOaVVNYkpYZWFuTUYvbmMvYUQvd1N3bG9EbzNYcjBiZkNaMFlNCnNJZXpaQjRSR0dOSHhGdExsVG9zTEIrWWhQY3Ziek51WW1aYUVzNVkyTUVWMDRQWFhxaGJtTVJXNHRMVzhxU1MKdERqM3l3eXV5eitmWExFK3R2eTJHQVRBV0xPVGhDZnBmL0dqd0dhd01NWTJyTFJUNUUrU29zY0RaRVFodHZZSQpxc3pVbmNOUDVubGRhdW1XOWM4Q0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZPSmZEcGlHRVBkRDlBNXNYMzF0bTdpQzlYTzJNQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFCdGloQjB5b05xcktPdExJU1B1UU5VMFErSy9seG5kVkRvR1lsOFg4dEgvTUlUZThvSgpSSmN3dnJMK2R2K3IzSFc3RFJ6d25kRTJMZjNEcCtMYmJDUUlJZEYvWmJzYzZ5RWZ1ZGI1UTVudXVUdmYxZXpmCnkxZEsxbFJueFYzL2Nqa0JNa3BiWXloeWRMZkliK0VwRSt6R0U3T1RuMGQ3anVqNEhRNzVEZDdKYnBMeG9ndWEKQkFjN2hUMFhGYzdLYlBjRGsxc0kzQ1BkSUdhRkxoRVpTTFAvc0poRUVDNUlnNW5KYTFDZEh6YVIwclA4eThzNQprNlZ0QnRScHRGSDNFdEhTRWcyL1orVGQ4czRKSU1pNDZuY2FWUmJBRWxRVUhNZFpVdUN4TDFUR0NwT2tGc2MyCklGUkFucDlJaFRsOVZDVGxZOEJUUXZIQUoybWErQnhSNW5xdwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://10.203.32.90:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubernetes-admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJVENDQWdtZ0F3SUJBZ0lJWlRiVFgxOEFrNVF3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TVRBM01EWXdOelEwTURaYUZ3MHlNakEzTURZd056UTBNVEZhTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXg5SVcvcGM1RGl0Nk8rbnIKUndXTmZlZFJyUGVTYVV5amR0RlBqU1pPM2dUaDYyOEd2ZzREUHJFZzFjUkJ5b0xUUjNncW1UREtQOEUyVDZ4cgpuQzNicnBUUmJyaEZycEttOWh6SjNWQWp2VDFTaFFmWEtORHVuZm9wcng3MG9FK29jYUlpWmljT3ZKd1RxYWJ3CnEvMUQ2RlR3QlVOWGFNTHFETjN3R09ZRWxvYnZmOW95eTM3MW5TbDU3SVJRTFdDRHl4NXNsZlZ1dFF0eU5Ha3oKaVZ2Mk9OY2NxeTQrSWFudGpnYUJONHBPbFgyUlVRVlhocm5sN3FPZ3JldHZhcEZaYXdRd1Z1Q3E2K2E4SXpuRgp2SU1UWUFwTkd6b2F4Yjl2Ujd1aDQ2Y3I4d0w0MisrWEpLMEp1SFZoU0o5dnRkYW1xTFNweWhBUm5MM2lEaFZECmgxTW5rd0lEQVFBQm8xWXdWREFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RBWURWUjBUQVFIL0JBSXdBREFmQmdOVkhTTUVHREFXZ0JUaVh3NlloaEQzUS9RT2JGOTliWnU0Z3ZWegp0akFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBZVQ0RkFiMURYeE9pWnVUZXBWNWk0R3hWVjJVaWtXaXFRdndDCkkxOXpVNUZza0R5NXdJbTVrSzVxaExkclR1T3d3Rm44WXR3WDNzenRYbDJZdk5QQ09tVTFtUzZwYzhKNTltY1YKYVFycGZiMEFxVEtHODRZVGJCdTJqTHhaK241bGhiUUtPZjJWSko1TWdBMVhnaUU5c1RuMWIvZ1BXMTF5L1NpbApaMXRXWlU5Y3hGRUpacHVva0x2Z0EwWlMwemozQ1E0M2ZkN1ZQQVc1UXdkL1VWWHFtbEdKRGlRSzVpZkk4NW5sClYxNVpWQXdqSnZkOGV5V01iS1V1d00wU1dyY0x5RXVoMjIrV2kxUnorL0RxckxFeTh4Ymc2eG5rbU5uQWdrK0kKVVYvOTVmSWwxUjVqcm94Y1pJVVlncTJjeEVZTitpMThyWmhwc1N4eE1TUHV5bGM4aGc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeDlJVy9wYzVEaXQ2TytuclJ3V05mZWRSclBlU2FVeWpkdEZQalNaTzNnVGg2MjhHCnZnNERQckVnMWNSQnlvTFRSM2dxbVRES1A4RTJUNnhybkMzYnJwVFJicmhGcnBLbTloekozVkFqdlQxU2hRZlgKS05EdW5mb3ByeDcwb0Urb2NhSWlaaWNPdkp3VHFhYndxLzFENkZUd0JVTlhhTUxxRE4zd0dPWUVsb2J2ZjlveQp5MzcxblNsNTdJUlFMV0NEeXg1c2xmVnV0UXR5TkdremlWdjJPTmNjcXk0K0lhbnRqZ2FCTjRwT2xYMlJVUVZYCmhybmw3cU9ncmV0dmFwRlphd1F3VnVDcTYrYThJem5GdklNVFlBcE5Hem9heGI5dlI3dWg0NmNyOHdMNDIrK1gKSkswSnVIVmhTSjl2dGRhbXFMU3B5aEFSbkwzaURoVkRoMU1ua3dJREFRQUJBb0lCQVFDWitlMVlMNlY2b3N3bApRUUxaRHBGU2RKNitmMlBtR25WWUNNQ1pUdXkxTHVQOExPandLUklkREJiMlFxNUQ0LzMwODhjM2xwNHk5S3JxClNEMy84bUozTEJ3YWlvcS9sQ2h1UEE3ZHFIUnh6Y0E1M0tuU3ZQVXk3T09VRzNGNzJ3WTgwaWhadVQwazM4eFQKRGQ0bFdoc3ErOUNjN2FCOGpMNFlQaWxXdG1EUXNEb1I4OFZuWjdHR3dpZEZYTUtaeXQ1S1p2ejBKRUNKS2syYgo2ZDdUcU16UExyMGRTSTlIRm5ZSUFVR1JwNTd6QVRxNHRUTlBoRlVZMjJEK2RWc0RwUmlVckhmT0UzeEJ5eTVOCk5mbVRsSlFPTnpSWXp2cjZ1OG1UR2kvZ1BJUkEvWm00WVVWS2pESE80MGdFbkhtSjVncVkxZUJWSFZaMzFqTDgKWXFOTlZoY1pBb0dCQU04cjNMbzB0UXJVeTNNbHlSTWlweElHVXVPdW9paS9Jd00yY3h5dncwdFFJamk5Nm9SdApMUFZuQ1RnRlN0dlMzN1ZwRlVJenZMRkpoQktXRmFyY2cvZHlESHJRL3RrbllPT0xOVXhkbjFqcHRHbjBORExoClVDbHdxcHZkVHI1MWFaaEdDcmZYNTVUNmFWelpwOVEyS3lhb3BLTmpDVXVMVVhXbXNxbDRRdzduQW9HQkFQYnEKdFdVd01waTVvMGJaTkJRUWo4NDI2QlBpcVJ0U1JRdEdTcGJVWGVoMjU3dWtSNTdyejBycmdZRE5CUmYxR1pidgpTSk9MTlZsY1BhbHRWZWVnOUcwRS9kU0xOQXVaMEFOZHBPZktWZTh5d0dOME9HbFNIUHBON2pLODlONytIcFVSCkxxZis2bjFtY01JVlNsczhCMCthNjEwWWw2RGVqUGY1OXBMUjlPaDFBb0dBZFRpaVNoSHNwbFpGVDcvL2gvNUIKZmlkcDJ6NUNycitIdGhlbkJvSkZCR1l4RnQ0T3hpTm9IdXJRQW95c0VMbStyc3pvcEc3Vnc1S1BVbHp0b2FIbwpZYWg4ZXptcUdZRDRoNGVLL3N5eWp3S2RmSjRhc3ZkZC9qU3J0RW1DZHEzRXM4NWQzaXdoOHQvRm9pM2RrbXViCit1SE5WazJCUXVkdmpoeG1WeEdmRDkwQ2dZRUFqTnZxclpZb1Z4NFgrbFB3dEwyWi9DOHdpQitYRDBJSXAxenIKTWs1bVlEWnREb3V5WEFQMFZxNHhTOVFwNHJmdGFFQ0xhN2hQci9IQ0w0UnpMRmVTK1JxTzM1Q21HVFFmQ2J5RApWY1FFOEJkSXo3TytkcjdrVHhya0YwZmFmZGdFaEUrd0NTQ1Fqd2RBcmtmTkNtMGRVcGx6U2NHOHhvWVBiMnZHCjhZMGJKUDBDZ1lFQWkyRXo1blRoVDN0RGJwY1dodkVLamdKY2RVU2Z6QjJCejNRYUJsRmwrU2FDbTVJZHhvMHoKVFhzU2tSbVhEZE1VVlVpWWEzYjREZHhrczlvSjhvU056K2JTTTVDYVZteWlEYTF6cVU4d0FLekliblI0SG4zdwpVcEcxRWxtb2NaeVBqL3ZCSDRscEJQSkVjdzJwNkt3b2hnb3MxVGxYSkgxMGwwT3hiakpJQ3VVPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=

```

## Monitoring

Monitoring is done on port 10255:

To enable monitoring, put the following line in /var/lib/kubelet/kubeadm-flags.env on every node.

KUBELET_KUBEADM_ARGS="--network-plugin=cni --pod-infra-container-image=k8s.gcr.io/pause:3.4.1 --read-only-port=10255

And restart kubelet.

http://${IP}:10255/metrics

http://${IP}:10255/stats/summary

# loadbalancing

This system uses ip_vs for loadbalancing.

To enable ipvs edit the configmap for kube-proxy

```kubectl edit cm kube-proxy -n kube-system```

edit the ipvs section

set mode to ipvs

```yaml
mode: "ipvs"
```

and the ipvs section

```yaml
ipvs:
      excludeCIDRs: null
      minSyncPeriod: 0s
      scheduler: "rr"
```

# Windows shares

To be able to access windows share from the linux system, first install keyutils.

```
sudo apt-get install keyutils
sudo apt-get install cifs-utils
```

Then create file /etc/cifspasswd

```
username=ServicesDocker
password=RrHZFybq00axAU6aRp81
domain=fujicolor
```

Then mount the windows share by adding the following line to /etc/fstab.

```//dfs/FujiFE /mnt/dfs cifs nocase,rw,cred=/etc/cifspasswd 0 1```

and sudo mount -a

## Flexvolumes

To have a container mount a cifs share from withing the container, use k8s flexvolume system with fstab/cifs project.

First create a secret that fstab/cifs uses, values are base64 encoded

```
echo -n ServicesDocker | base64
echo -n RrHZFybq00axAU6aRp81 | base64
echo -n fujicolor | base64
```

Enter the base64 encoded output in the secrets yaml

```yaml
apiVersion: v1
kind: Secret
metadata:
name: cifs-secret
namespace: default
type: fstab/cifs
data:
username: 'ZXhhbXB==????'
password: 'bXktc2V???'
domain: 'bXktc2Vjc????'
```

**And apply the secret**

```kubectl apply -f secret.yml```

Then **on every node** deploy the fstab~cifs flexvolume for cifs shares

```
git clone https://github.com/fstab/cifs

for i in `seq 1 4`;
do
    ssh -l user ubdock0${i} 'sudo mkdir -p /usr/libexec/kubernetes/kubelet-plugins/volume/exec/fstab~cifs'
    ssh -l user  ubdock0${i} 'sudo chmod a+w /usr/libexec/kubernetes/kubelet-plugins/volume/exec/fstab~cifs'
    scp cifs/cifs -l user ubdock0${i}:/usr/libexec/kubernetes/kubelet-plugins/volume/exec/fstab~cifs
    ssh -l user ubdock0${i} 'sudo chmod a+x /usr/libexec/kubernetes/kubelet-plugins/volume/exec/fstab~cifs/cifs'
    ssh -l user ubdock0${i} 'sudo systemctl restart kubelet'
done
```

* Install jq, the JSON commandline tool. It is used in the cifs script
* Install mountpoint to see if a directory or file is a mountpoint. It is used in the cifs script
* Install mount.cifs / cifs-utils

Or run the cifs script manually with *cifs init* it will assert all the needed packages.

```
init() {
	assertBinaryInstalled mount.cifs cifs-utils
	assertBinaryInstalled jq jq
	assertBinaryInstalled mountpoint util-linux
	assertBinaryInstalled base64 coreutils
	echo '{ "status": "Success", "message": "The fstab/cifs flexvolume plugin was initialized successfully", "capabilities": { "attach": false } }'
	exit 0
}
```

It is possible to deploy a daemonset for this when there are a lot of nodes.

The cifs script takes care of the mounting/unmounting

Then every deployment/pod can be configured 

```yaml
	volumeMounts:
	- name: dfs
		mountPath: /data       

     volumes:
     - name: dfs
       flexVolume:
        driver: "fstab/cifs"
        fsType: "cifs"
        secretRef:
          name: "cifs-secret"
        options:
          networkPath: "//dfs.fujicolor.nl/FujiFE"
          mountOptions: "dir_mode=0755,file_mode=0644,noperm"
```

* The pod will take the just installed cifs driver from the host's system /usr/libexec/kubernetes/kubelet-plugins/volume/exec.
* It creates create a /data directory inside the container and mounts it to //dfs.fujicolor.nl/FujiFE.
* It uses the secrets installed with **kubectl create secret**

# Install metrics server

In order to have a working HorizontalPodAutoscaler a metrics-server must be installed.

```
kubectl autoscale deployment desired-deployment --cpu-percent=50 --min=1 --max=10
```

or apply:

```yaml
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
  creationTimestamp: null
  name: deployment
spec:
  maxReplicas: 10
  minReplicas: 1
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: deployment
  targetCPUUtilizationPercentage: 50
status:
  currentReplicas: 0
  desiredReplicas: 0
```

At this pint the metric-server is not installed so the autoscaler can not get its metrics.

```
kubectl describe hpa revproxy-deployment

horizontal-pod-autoscaler  invalid metrics (1 invalid out of 1), first error is: failed to get cpu utilization: unable to get metrics for resource cpu: unable to fetch metrics from resource metrics API: the server could not find the requested resource (get pods.metrics.k8s.io)
```

Pabloproject has metrics-server-deploy.yaml available.

```
kubectl apply -f metrics-server-deploy.yaml

kubectl get po -n kube-system
```

**metrics-server-6c66b84467-tfqw5      1/1     Running   0**

Add the resource request to the deployment yaml

```
- name: web
image: "192.168.56.3:5000/nginxsidecar"
resources:
requests:
	cpu: 200m
```

> kubectl describe hpa deployment

```
AbleToScale     True    ScaleDownStabilized  recent recommendations were higher than current one, applying the highest recent recommendation
ScalingActive   True    ValidMetricFound     the HPA was able to successfully calculate a replica count from cpu resource utilization (percentage of request)
ScalingLimited  False   DesiredWithinRange   the desired count is within the acceptable range
```

# Cleanup disk space

To cleanup disk space.

## Cleanup old snap packages
	
Script:

```
	set -eu

	snap list --all | awk '/disabled/{print $1, $3}' |
		while read snapname revision; do
		snap remove "$snapname" --revision="$revision"
		done
```
## Turn off swap

First just turn it off by disabling all swap files from /etc/fstab.

```swapoff -a```

Then safely delete the file

```sudo rm /swap.img```

## Clear logs

sudo journalctl --vacuum-time=2s

```Vacuuming done, freed 1.4G of archived journals from /var/log/journal/a86466848fb24025b5413443b7bea9e3```

# Root privileges

## Create certificate

Login to the system without password

```ssh-keygen -t rsa -b 2048```

Name it whatever you want. Copy the public key text mykey.pub $HOME/.ssh/authorized_keys.

```ssh-copy-id -i .ssh/mykey user@ubdock02```

Now login without password.

```ssh -i .ssh/mykey user@ubdock01```

Configure the certificate as IdentityFile in Visual Studio code remote SSH.

```
Host 10.203.32.80
  HostName 10.203.32.80
  IdentityFile .ssh/mykey
  User laurijssen
```

## sudo for normal user

As root.
```sudo visudo /etc/sudoers```

Add the following lines to the file, or better yet add a new file to /etc/sudoers.d/

* laurijssen ALL=(ALL:ALL) ALL
* root ALL=(ALL) NOPASSWD:ALL

## UPDATE PABLO CONTAINERS
**Manually**
```
docker login
docker pull docker.io/iplabs/pablo
docker tag iplabs/pablo 10.203.32.90:5000/pablo
docker push 10.203.32.90:5000/pablo
```

## upgrade kubernetes version

For master node(s):

* sudo apt-mark unhold kubeadm && sudo apt-get update && sudo apt-get install -y kubeadm=1.23.7-00 && sudo apt-mark hold kubeadm
* kubeadm upgrade plan
* kubeadm upgrade apply
* apt-mark unhold kubelet sudo apt-get update && sudo apt-get install -y kubelet=1.23.7-00 && sudo apt-mark hold kubelet
* systemctl daemon-reload
* systemctl restart kubelet

For all worker nodes:

upgrade kubeadm
```sudo apt-mark unhold kubeadm && sudo apt-get update && sudo apt-get install -y kubeadm=1.22.7-00 && sudo apt-mark hold kubeadm```

on master node:
```kubectl drain nodename.fujicolor.nl --ignore-daemonsets```

back to worker node:
```sudo kubeadm upgrade node```

upgrade kubelet
```sudo apt-mark unhold kubelet && sudo apt-get update && sudo apt-get install -y kubelet=1.22.7-00 && sudo apt-mark hold kubelet```
```systemctl daemon-reload```
```sudo systemctl restart kubelet```

On master node:
```kubectl uncordon <worker>```
