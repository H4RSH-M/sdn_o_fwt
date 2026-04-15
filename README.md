# Multi-Layer SDN Firewall 

### 1. Problem Statement
The objective of this project is to implement an advanced, multi-layer SDN-based firewall solution using Mininet and the OS-Ken OpenFlow controller. Moving beyond basic IP blocking, this firewall demonstrates complex controller-switch interaction by executing a cascading inspection gauntlet across the OSI model (Layer 2 MAC, Layer 3 Network, and Layer 4 Transport) before dynamically pushing hard drop rules to the Open vSwitch (OVS) hardware.

### 2. Architecture & Approach
While standard implementations rely on generic ICMP (ping) traffic to test firewall rules, this architecture separates network-layer security enforcement from application-layer traffic generation. 

To prove Layer 4 deep packet inspection, a custom multi-threaded POSIX socket application was developed in C++ to simulate real-world data exfiltration targeting a specific port, alongside standard network diagnostic tools.

**The Topology:** A single switch (`s1`) connected to 5 hosts (`h1` through `h5`).
* **The Target (h5):** Runs the C++ TCP server listening on Port 8080.
* **The Controller Logic:** Operates as a standard L2 learning switch for general traffic, but actively intercepts and inspects all IPv4 headers against a strict security checklist.

**The Inspection Gauntlet:**
* **Layer 2 Hardware Block (h1):** Traffic originating from MAC address `00:00:00:00:00:01` is blacklisted. Packets are dropped before IP inspection occurs.
* **Layer 3 Network Block (h2):** Passes the MAC check, but explicitly denies ICMP protocol traffic from `10.0.0.2`. Pings are dropped, but TCP could theoretically pass.
* **Layer 4 Application Block (h3):** Passes L2 and L3. The controller parses the TCP header. Attempts from `10.0.0.3` to access Port `22` (SSH) or Port `8080` (the custom C++ payload) are explicitly blocked.
* **Default Allow / Trusted (h4):** Traffic from `10.0.0.4` survives all checks. The controller permits the TCP handshake and file transfer, pushing a standard forwarding rule to the switch.

When a violation occurs, the OS-Ken controller immediately pushes a priority-100 hard OpenFlow drop rule to the virtual switch to prevent CPU exhaustion from subsequent unauthorized packets.

### 3. Setup and Execution Steps

**Prerequisites**
* Mininet Network Emulator
* Python 3.12+ with OS-Ken framework (`pip install os-ken`)
* G++ Compiler

**Execution Instructions**

**Step 1: Compile the C++ Payload Application** Navigate to the `app` directory and compile the server and client binaries.
```bash
cd app
make
```

**Step 2: Start the OS-Ken Controller** Initialize the multi-layer firewall logic in a dedicated terminal.
```bash
osken-manager controller/firewall.py
```

**Step 3: Launch Mininet Topology** Start the virtual network with a single switch, 5 hosts, and a remote controller. Ensure previous caches are cleared.
```bash
sudo mn -c
sudo mn --topo single,5 --mac --controller=remote
```

**Step 4: Execute the Multi-Layer Tests** Open the host terminals (`mininet> xterm h1 h2 h3 h4 h5`) and run the sequence to trigger the cascading blocks:

1.  **Initialize Target:** Start the server on h5.
    * `h5` terminal: `./app/server`
2.  **Test L2 MAC Block:** * `h1` terminal: `ping -c 3 10.0.0.5` *(Fails immediately)*
3.  **Test L3 ICMP Block:** * `h2` terminal: `ping -c 3 10.0.0.5` *(Fails immediately)*
4.  **Test L4 Port Blocks:** * `h3` terminal: `ping -c 3 10.0.0.5` *(Succeeds - ICMP allowed)*
    * `h3` terminal: `nc -vz 10.0.0.5 22` *(Fails - SSH blocked)*
    * `h3` terminal: `./app/client 10.0.0.5 ../payload/confidential.txt` *(Fails - Port 8080 blocked)*
5.  **Test Trusted Host:** * `h4` terminal: `./app/client 10.0.0.5 ../payload/confidential.txt` *(Succeeds - File transferred)*
