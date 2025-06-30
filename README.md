# ebpf-iot-ddos-thesis

This project presents a real-time DDoS mitigation system for IoT environments using eBPF/XDP on Raspberry Pi. It features low-latency packet filtering in the kernel, a user-space Python controller for IP blocking, real-time Telegram alerts, and log persistence for forensic analysis. The solution was tested in both Docker-based simulations and real hardware setups.

## Features

- 🛡️ Kernel-level UDP flood detection using eBPF/XDP
- 🔐 Dynamic IP blocking via `iptables`
- 📡 Real-time notifications using Telegram Bot API
- 📁 Local alert logging to `/home/tolay/alerts.log`
- ⚙️ Evaluation in Docker and physical Raspberry Pi environment
- 📊 CPU utilization and mitigation effectiveness analysis

## Components

- `udp_filter_kern.c` — eBPF/XDP kernel program for tracking per-IP packet rates
- `controller.py` — Python script for IP blocking, logging, and Telegram alerting
- `test_configs/` — Example scripts and iperf3 commands for traffic generation

## How to Use

1. **Deploy eBPF Program**  
   Compile and attach `udp_filter_kern.c` to the network interface (`eth0` or `wlan0`).

2. **Run Controller**  
   Use `controller.py` to monitor `trace_pipe`, apply mitigation, and send alerts.

3. **Test Traffic**  
   Use `iperf3` or similar tools to simulate legitimate and malicious traffic.

## System Requirements

- Raspberry Pi 4 (or any eBPF/XDP-capable Linux device)
- Linux kernel 5.4+
- `bcc`, `iptables`, `Python3`, `requests`, `socket`, `subprocess`
- Telegram bot token and chat ID

## License

This project is provided for academic and research purposes. Consider adding an [MIT License](https://choosealicense.com/licenses/mit/) or similar if planning to open-source it.

## Author

Abdurrahman Tolay  
Istinye University, MSc in Computer Engineering  
Thesis Advisor: Dr. Hüsamettin Osmanoğlu
