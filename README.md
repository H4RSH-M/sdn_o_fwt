# SDN-Based L4 Firewall

## 1. Problem Statement
The objective of this project is to implement an SDN-based firewall solution using Mininet and the Ryu/OS-Ken OpenFlow controller. The firewall must demonstrate controller-switch interaction, flow rule design (match-action), and network behavior observation by explicitly blocking or allowing traffic between specific hosts.

## 2. Architecture & Approach
While standard implementations rely on generic ICMP (`ping`) or default `iperf` traffic to test firewall rules, I developed a custom multi-threaded POSIX socket application in C++ to simulate real-world data exfiltration and test application-specific L4 port blocking.

* **The Payload Setup:** A C++ TCP server runs on Host 2 (`h2`) listening on `Port 8080`. A C++ client application is used on the other hosts to transmit a payload (`confidential.txt`) across the simulated network.
* **The Firewall Logic:** The SDN controller operates as a standard L2 learning switch for general traffic, but actively inspects IPv4 and TCP headers for traffic bound to Port 8080.
  * **Allowed Rule:** Traffic originating from the trusted host `h3` (10.0.0.3) is permitted to complete the TCP handshake and file transfer.
  * **Blocked Rule:** Traffic originating from the malicious host `h1` (10.0.0.1) is intercepted. The controller drops the packet and immediately pushes a hard OpenFlow drop rule to the virtual switch to prevent CPU exhaustion from subsequent unauthorized packets.

This architecture explicitly separates application-layer traffic generation from network-layer security enforcement, proving the controller can perform deep header inspection to protect specific services.

## 3. Setup and Execution Steps

### Prerequisites
* Mininet Network Emulator
* Python 3.x with Ryu or OS-Ken framework
* G++ Compiler

### Execution Instructions

**Step 1: Compile the C++ Payload Application**
Navigate to the `app` directory and compile the server and client binaries.
```bash
cd app
make
```

**Step 2: Start the SDN Controller**
Initialize the firewall logic in a dedicated terminal.
```bash
ryu-manager controller/firewall.py
```

**Step 3: Launch Mininet Topology**
Start the virtual network with a single switch, 3 hosts, and a remote controller.
```bash
sudo mn --topo single,3 --mac --controller=remote
```

**Step 4: Execute the Tests**
Open the host terminals (`mininet> xterm h1 h2 h3`) or run directly from the Mininet CLI:

1. Start the server on h2:
   `mininet> h2 ./app/server &`
2. Test Trusted Host (h3) - *Expected to Succeed*:
   `mininet> h3 ./app/client 10.0.0.2 ../payload/confidential.txt`
3. Test Blocked Host (h1) - *Expected to Hang/Fail & Trigger Firewall Alert*:
   `mininet> h1 ./app/client 10.0.0.2 ../payload/confidential.txt`
