#!/usr/bin/env python3
"""
MASTER EXPERIMENT SCRIPT: Encrypted (HTTPS) SDN DDoS Testbed
Architecture: Single Switch, 4 Hosts (h1-h4)
Controller: Remote (Ryu)
"""

import time
import os
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
import random

VICTIM_IP = "10.0.0.2"

# ================= TRAFFIC SCENARIOS =================

def run_benign_baseline(net):
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    print("\n[Baseline] Starting Benign Traffic (TCP, ICMP, HTTPS)...")
    h2.cmd("iperf -s &")
    h1.cmd(f"iperf -c {VICTIM_IP} -t 60 -P 4 > /dev/null 2>&1 &")
    h3.cmd(f"ping -c 100 -i 0.2 {VICTIM_IP} > /dev/null 2>&1 &")
    h4.cmd(f"h2load -n 5000 -c 50 https://{VICTIM_IP}:443/ > /dev/null 2>&1 &")

def run_volumetric_attack(net):
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    print("\n[Attack] Starting Volumetric DDoS (SYN & UDP Flood)...")
    h1.cmd(f"hping3 -S -p 80 --flood {VICTIM_IP} > /dev/null 2>&1 &")
    h3.cmd(f"hping3 --udp -p 53 --flood {VICTIM_IP} > /dev/null 2>&1 &")

def run_encrypted_flood(net):
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    print("\n[Attack] Starting Encrypted HTTPS Flood (TLS Stress)...")
    h1.cmd(f"h2load -n 100000 -c 500 -t 4 https://{VICTIM_IP}:443/ > /dev/null 2>&1 &")
    h3.cmd(f"h2load -n 100000 -c 500 -t 4 https://{VICTIM_IP}:443/ > /dev/null 2>&1 &")

def run_distributed_botnet(net):
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    print("\n[Attack] Starting Distributed Botnet (3 Attackers)...")
    # os.system("ovs-ofctl del-flows s1")
    print("\n[Attack] Starting Distributed Botnet (3 Attackers)...")
    for attacker in [h1, h3, h4]:
        attacker.cmd(f"hping3 -S -p 80 --flood {VICTIM_IP} > /dev/null 2>&1 &")

def run_mixed_flow(net):
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    print("\n[Mixed] Starting Mixed Flow...")

    # 1. Start "Legitimate" Background Noise (Varying intensities)
    for host in [h3, h4]:
        concurrency = random.randint(50, 150)
        host.cmd(f"h2load -n 50000 -c {concurrency} https://{VICTIM_IP}:443/ > /dev/null 2>&1 &")

    # 2. Short staggered delay to let noise stabilize
    time.sleep(random.uniform(1, 3))

    # 3. Start "Hidden" Attack (Targeting the same port as the noise)
    print("[Attack] Launching Randomized SYN Flood on Port 443...")
    h1.cmd(f"hping3 -S -p 443 --flood --rand-source {VICTIM_IP} > /dev/null 2>&1 &")

# def run_fpr_flash_crowd(net):
#     h1, h3, h4 = net.get('h1', 'h3', 'h4')
#     print("\n[FPR] Starting Flash Crowd (Legitimate High-Volume HTTPS)...")
#     for host in [h1, h3, h4]:
#         host.cmd(f"h2load -n 20000 -c 150 -m 10 https://{VICTIM_IP}:443/ > /dev/null 2>&1 &")
def run_fpr_flash_crowd(net):
    h1, h3, h4 = net.get('h1', 'h3', 'h4')
    print("\n[FPR] Starting Flash Crowd (Legitimate High-Volume HTTPS)...")
    
    # We use h2load to simulate high-concurrency legitimate traffic
    # -n: total requests, -c: concurrent clients, -m: max concurrent streams
    for host in [h1, h3, h4]:
        print(f"  --> {host.name} initiating 20,000 HTTPS requests...")
        host.cmd(f"h2load -n 20000 -c 150 -m 10 https://{VICTIM_IP}:443/ > /dev/null 2>&1 &")
        # Small delay to prevent ARP storms or initial packet drops
        time.sleep(0.5)

def run_stealth_slowloris(net):
    h1 = net.get('h1')
    print("\n[Stealth] Starting Low-and-Slow Attack (Under Thresholds)...")
    h1.cmd(f"hping3 -S -p 443 -i u25000 {VICTIM_IP} > /dev/null 2>&1 &")

def cleanup_traffic(net):
    print("\n🧹 Cleaning up all background traffic processes...")
    for host in net.hosts:
        host.cmd("pkill hping3")
        host.cmd("pkill iperf")
        host.cmd("pkill h2load")
        host.cmd("pkill ping")
    time.sleep(2)

# ================= INFRASTRUCTURE =================

def start_https_server(net):
    h2 = net.get('h2')
    print("[+] Generating TLS certificate on h2...")
    h2.cmd("openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem "
           "-out /tmp/cert.pem -days 1 -nodes -subj '/CN=localhost' 2>/dev/null")
    print("[+] Starting HTTPS server on h2 (10.0.0.2:443)")
    h2.cmd("python3 -m http.server 443 --bind 10.0.0.2 "
           "--certfile /tmp/cert.pem --keyfile /tmp/key.pem > /dev/null 2>&1 &")

def configure_network():
    net = Mininet(controller=RemoteController, link=TCLink, autoSetMacs=True, autoStaticArp=True)
    
    print("[+] Adding Remote Controller (Ryu)...")
    net.addController('c0', ip='127.0.0.1', port=6653)

    print("[+] Adding Hosts (h1-h4)...")
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2') # Victim
    h3 = net.addHost('h3', ip='10.0.0.3')
    h4 = net.addHost('h4', ip='10.0.0.4')

    s1 = net.addSwitch('s1')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    net.start()
    print("[+] Topology Started (ENCRYPTED MODE)")
    return net

# ================= MAIN LOOP =================

def main():
    if os.getuid() != 0:
        print("⚠️  Error: Run with sudo")
        return

    net = configure_network()
    start_https_server(net)
    time.sleep(3)

    menu = {
        "1": run_benign_baseline,
        "2": run_volumetric_attack,
        "3": run_encrypted_flood,
        "4": run_distributed_botnet,
        "5": run_mixed_flow,
        "6": run_fpr_flash_crowd,
        "7": run_stealth_slowloris,
        "8": cleanup_traffic
    }

    try:
        while True:
            print("\n" + "="*40)
            print("   SDN SECURITY EXPERIMENT MENU")
            print("="*40)
            print("1. Benign Baseline     2. Volumetric DDoS")
            print("3. Encrypted HTTPS     4. Distributed Attack")
            print("5. Mixed Flow          6. FPR (Flash Crowd)")
            print("7. Stealth (Slow)      8. STOP ALL TRAFFIC")
            print("0. EXIT & STOP MININET")
            
            choice = input("\nSelect Scenario: ")
            
            if choice == "0":
                break
            elif choice in menu:
                if choice != "8": cleanup_traffic(net)
                menu[choice](net)
            else:
                print("Invalid choice.")
    
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping Experiment...")
        cleanup_traffic(net)
        net.stop()

if __name__ == "__main__":
    main()