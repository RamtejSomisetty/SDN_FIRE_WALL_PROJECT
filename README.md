# SDN_FIRE_WALL_PROJECT
This guide walks you through the steps to implement and test an SDN firewall using **Mininet**, **POX controller**, and a custom **L2 learning firewall script**.
---
##  Setup Steps
### 1. Open Terminals and Connect to Mininet
Open **three separate terminals** and SSH into Mininet in each using the following command:
```bash
ssh -Y mininet@localhost -p 2223
```
When prompted, enter the password:
```
mininet
```
---
### 2. Place the Firewall Script in the Correct Directory
In one terminal:
```bash
cd pox/pox/forwarding
```
Place your `firewall_l2_learning.py` script in this directory.

---

### 3. Run the POX Controller with the Firewall Module
In another terminal:
```bash
cd pox
```
Run the POX controller with firewall rules (IP, MAC, and port-based blocking):
```bash
python3.8 pox.py forwarding.firewall_l2_learning \
  --blocked_ips=10.0.0.3 \
  --blocked_macs=00:00:00:00:00:03 \
  --blocked_ports=80,443
```
> You can modify the `--blocked_*` parameters as per your test case.
---
### 4. Run the Mininet Topology
In the third terminal, navigate to the directory where your `Topology.py` file is located:
```bash
sudo python3 Topology.py
```
Make sure:
- Your file is named correctly (`Topology.py`)
- It is in the working directory
---
### Setup is Complete
---

##  Testing the Firewall
### 1. General Connectivity Check
From the **Mininet CLI**:
```bash
h11 ping h12
```
> This should **succeed**, confirming general connectivity.
---
### 2. Test Firewall Rules
####  IP-Based Blocking

```bash
python3.8 pox.py forwarding.firewall_l2_learning --blocked_ips=10.0.0.3
```
Then test:
```bash
h11 ping h13
```
> Expected result: **Ping fails** due to IP-based blocking.
---
####  MAC-Based Blocking
```bash
python3.8 pox.py forwarding.firewall_l2_learning --blocked_macs=00:00:00:00:00:03
```
Test again:
```bash
h11 ping h13
```
> Expected result: **Ping fails** due to MAC-based blocking.
---
####  Port-Based Blocking
Start a simple HTTP server on h12:
```bash
h12 python3 -m http.server 8000 &
```
Verify server is running:
```bash
h12 netstat -tulpn
```
Try accessing it from h11:
```bash
h11 wget http://10.0.0.2:8000
```
Run the firewall with blocked port:

```bash
python3.8 pox.py forwarding.firewall_l2_learning --blocked_ports=8000
```
> Expected result: **Request is blocked**.
---
##  Additional Useful Commands

- Check if POX is running on the correct port (default OpenFlow port: `6633`):
```bash
sudo netstat -tulnp | grep 6633
```
- Kill a POX process (use the actual PID):
```bash
sudo kill -9 <pid>
```
- Get host MAC address:
```bash
h12 ifconfig
```
---
## Examples
### Block IP:
```bash
python3.8 pox.py forwarding.firewall_l2_learning --blocked_ips=10.0.0.3
```
### Block MAC:
```bash
python3.8 pox.py forwarding.firewall_l2_learning --blocked_macs=00:00:00:00:00:03
```
### Block Port:
```bash
python3.8 pox.py forwarding.firewall_l2_learning --blocked_ports=8000
```

---

## 🧠 Notes

- Ensure your topology script assigns IPs and MACs according to the block rules you wish to test.
- Always restart POX after updating rule parameters.
