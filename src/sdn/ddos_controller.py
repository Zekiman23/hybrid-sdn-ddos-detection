# ================== Hybrid DDoS Controller (Fixed & Optimized - 2025 Update) ====================
# - Asynchronous ML inference via FastAPI (non-blocking, pooled, rate-limited)
# - Permanent L2 forwarding flows after MAC learning
# - Proactive ARP/ICMP handling
# - Strike-based mitigation with auto-unblock
# - Robust for long idle periods in Mininet/SDN environments
# =============================================================================================

import os
import time
import csv
from collections import defaultdict
import psutil

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls, DEAD_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp
from ryu.lib.packet import ether_types
from ryu.lib import hub
import requests
from eventlet.semaphore import Semaphore


# ---------------- Configuration ----------------
DETECTION_API = "http://127.0.0.1:9000/detect"
LOG_FILE = "../../logs/online_test_results/detection_log.csv"
LATENCY_LOG = "../../logs/online_test_results/latency_log.csv"

# Blocking policy
UNBLOCK_TIMEOUT = 120           # seconds to auto-unblock
STRIKE_THRESHOLD_1 = 1          # first alert → monitoring
STRIKE_THRESHOLD_2 = 1          # repeated → hard block (drop) — lowered for testing

MAX_CONCURRENT_ML = 8           # Prevent overload

# ---------------- Global Statistics ----------------
FLOW_STATS = defaultdict(lambda: {
    "start_time": time.time(),
    "last_seen": time.time(),
    "fwd_packets": 0,
    "bwd_packets": 0,
    "fwd_pkt_len": [],
    "bwd_pkt_len": [],
    "syn_count": 0,
    "ack_count": 0,
    "total_bytes": 0
})

SUSPECT_IP = defaultdict(lambda: {"strikes": 0, "last_flagged": 0})
# ✅ NEW: Distributed tracking
DST_STATS = defaultdict(lambda: {
    "sources": set(),
    "source_ratios": defaultdict(lambda: {"syn": 0, "ack": 0}), # Tracks per-source for this IPss
    "syn": 0,
    "ack": 0,
    "last_update": time.time(),
    "alert_count": 0,
    "is_blocked": False
})



class DDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}  # dp.id → {mac: port}
        os.makedirs("logs", exist_ok=True)
        print("Current working directory:", os.getcwd())
        print("Trying to create latency_log.csv in:", os.path.abspath(LATENCY_LOG))
        ###
        # Initialize latency log file with header if it doesn't exist
        if not os.path.exists(LATENCY_LOG):
            with open(LATENCY_LOG, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "src_mac",
                    "dst_mac",
                    "total_latency_ms",
                    "inference_latency_ms",
                    "decision",
                    "ml_call_percentage",
                    "is_correct",
                    "time_to_mitigation_s", 
                    "cpu_utilization_pct",  
                    "mem_utilization_pct"   
                ])
                writer.writerow([
                    "timestamp", "src_mac", "total_latency_ms", "inference_latency_ms",
                    "ttm_s", "cpu_util", "mem_util", "is_correct", "decision"
                ])
            print(f"[LOG] Initialized latency_log.csv with header")

        self.total_detections = 0
        self.ml_calls = 0

        print("\n================ Hybrid DDoS Controller Ready ================")
        print(" → Asynchronous ML inference (non-blocking, pooled)")
        print(" → Permanent L2 forwarding flows")
        print(" → Proactive ARP/ICMP rules")
        print(" → Strike-based mitigation + auto-unblock")
        print(f" → Max concurrent ML calls: {MAX_CONCURRENT_ML}")
        print("==============================================================\n")

        # HTTP session with large pool + keep-alive
        self.http_session = requests.Session()
        self.http_session.headers.update({"Connection": "keep-alive"})
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50,
            pool_maxsize=150,
            max_retries=3,
            pool_block=False
        )
        self.http_session.mount('http://', adapter)
        self.http_session.mount('https://', adapter)

        # Limit concurrent ML inferences
        self.ml_semaphore = Semaphore(MAX_CONCURRENT_ML)

        # Start background cleanup thread
        self.gc_thread = hub.spawn(self._cleanup_loop)

        self.ground_truth = {
            "00:00:00:00:00:01": "ATTACKER",
            "00:00:00:00:00:03": "ATTACKER",
            "00:00:00:00:00:04": "ATTACKER",
            "00:00:00:00:00:02": "VICTIM"
        }

        # Stats for Accuracy calculation
        self.stats_counters = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    # ---------------- Logging ----------------
    def log_event(self, src_mac, dst_mac, decision, confidence, features):
        header_needed = not os.path.exists(LOG_FILE)
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            if header_needed:
                writer.writerow([
                    "timestamp", "src_mac", "dst_mac", "decision", "confidence",
                    "duration", "fwd_packets", "bwd_packets",
                    "fwd_pkt_len_mean", "bwd_pkt_len_mean",
                    "bytes_per_sec", "packets_per_sec",
                    "syn_count", "ack_count"
                ])
            writer.writerow([
                time.time(), src_mac, dst_mac, decision, confidence,
                features["duration"], features["fwd_packets"],
                features["bwd_packets"], features["fwd_pkt_len_mean"],
                features["bwd_pkt_len_mean"], features["bytes_per_sec"],
                features["packets_per_sec"], features["syn_count"],
                features["ack_count"]
            ])
 

    #----------------- ryu terminal refresher -----
    def switch_state_change_handler(self, ev):
        datapath = ev.datapath
        dpid = datapath.id if datapath else "unknown"

        if ev.state == DEAD_DISPATCHER:
            print(f"[STATE] Switch {dpid} disconnected → clearing MAC & flow state")
            if dpid in self.mac_to_port:
                del self.mac_to_port[dpid]
        else:
            print(f"[STATE] Switch {dpid} entered MAIN_DISPATCHER")
    # ---------------- Cleanup Loop ----------------
    def _cleanup_loop(self):
        while True:
            now = time.time()
            for flow_key in list(FLOW_STATS):
                if now - FLOW_STATS[flow_key]["last_seen"] > 300:
                    del FLOW_STATS[flow_key]
            for ip in list(SUSPECT_IP):
                if now - SUSPECT_IP[ip]["last_flagged"] > UNBLOCK_TIMEOUT:
                    print(f"🟢 AUTO-UNBLOCK {ip}")
                    del SUSPECT_IP[ip]
             # ✅ Distributed stats cleanup
            for dst in list(DST_STATS):
                if now - DST_STATS[dst]["last_update"] > 5:
                    DST_STATS[dst] = {
                        "sources": set(),
                        "syn": 0,
                        "ack": 0,
                        "last_update": now
                    }

            hub.sleep(10)

    # ---------------- Flow Installation Helper ----------------
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    # ---------------- Switch Features (Proactive Rules) ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match_https_back = parser.OFPMatch(
            eth_type=0x0800, 
            ip_proto=6, 
            tcp_src=443  # Matches traffic coming FROM the server
        )
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 110, match_https_back, actions)
        print("[+] Visibility Fix: Specific HTTPS-Return mirroring installed")

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 10, match, actions, idle_timeout=0, hard_timeout=0)

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 10, match, actions, idle_timeout=0, hard_timeout=0)

        print(f"[+] Switch {datapath.id} connected – proactive rules installed")

    # ---------------- Asynchronous Detection ----------------
    def _perform_detection(self, features, src_mac, dst_mac, datapath, parser, 
                           packet_in_time=None, trigger_time=None, src_tracker=None):
        
        if SUSPECT_IP.get(src_mac, {}).get("blocked", False):
            return
        self.total_detections += 1
        start_time = time.time()

        # This line pulls the latest numbers from the tracker we passed in
        syn_count = src_tracker["syn"] if src_tracker else 0
        ack_count = src_tracker["ack"] if src_tracker else 0
        
        # Resource monitoring for Thesis Performance Chapter
        cpu_util = psutil.cpu_percent(interval=None) 
        mem_util = psutil.virtual_memory().percent
        
        # Initialize Suspect Entry
        if src_mac not in SUSPECT_IP:
            SUSPECT_IP[src_mac] = {
                "strikes": 0, 
                "blocked": False,
                "last_flagged": 0,
                "first_detected": time.time()
            }
            
        # Default values for logging integrity
        decision = 0  
        confidence = 0.0
        mode = "FAILED_CALL"
        ml_prob = 0.0
        rule_score = 0.0
        ttm = 0.0
        is_correct = False

        
        with self.ml_semaphore:
            if SUSPECT_IP.get(src_mac, {}).get("blocked", False):
                return
            try:
                          
                # 1. API CALL TO ML SERVICE
                response = self.http_session.post(
                    DETECTION_API,
                    json={"features": features},
                    timeout=10
                )
                response.raise_for_status()
                result = response.json()
                
                # Extract results
                decision = result.get("decision", 0)
                confidence = result.get("confidence", 0.0)
                ml_prob = result.get("ml_prob", 0.0)
                rule_score = result.get("rule_score", 0.0)
                mode = result.get("mode", "UNKNOWN")
                ml_used = result.get("ml_used", True)
                response_time = time.time()

                # Only count as ML call if ML was actually used
                if ml_used:
                    self.ml_calls += 1

                # 2. ACCURACY TRACKING (Ground Truth Comparison)
                actual_role = self.ground_truth.get(src_mac, "BENIGN").upper()
                if decision == 1:
                    if actual_role == "ATTACKER":
                        self.stats_counters["TP"] += 1
                        is_correct = True
                    else:
                        self.stats_counters["FP"] += 1
                else:
                    if actual_role != "ATTACKER":
                        self.stats_counters["TN"] += 1
                        is_correct = True
                    else:
                        self.stats_counters["FN"] += 1

                # Start the TTM (Time to Mitigate) clock on the first suspicious event
                if decision == 1 and "first_suspicious_time" not in SUSPECT_IP[src_mac]:
                    SUSPECT_IP[src_mac]["first_suspicious_time"] = time.time()

                # 3. LATENCY CALCULATION
                decision_time = time.time()
                total_latency_ms = (decision_time - packet_in_time) * 1000 if packet_in_time else 0
                inference_latency_ms = (response_time - start_time) * 1000

                # 4. SYMMETRY SHIELD (The FPR Killer)
                # Pull the ABSOLUTE LATEST counts from the tracker reference
                syn_count = src_tracker["syn"] if src_tracker else 0
                ack_count = src_tracker["ack"] if src_tracker else 0                
            
                is_asymmetric = True 

                if syn_count > 0 and ack_count > 0:
                    ratio = syn_count / ack_count
                    
                    # Check if the handshake behavior is healthy (Ratio between 0.5 and 2.0)
                    if 0.5 <= ratio <= 2.0:
                        # FLASH CROWD CALIBRATION:
                        # Attack -c 500 often hits > 200 SYN per interval.
                        # Flash Crowd -c 150 usually stays < 100 SYN per interval.
                        if syn_count > 250: 
                            is_asymmetric = True
                            print(f"⚠ SHIELD OVERRIDE: Volumetric Flood Detected (SYN={syn_count})")
                        else:
                            is_asymmetric = False
                            # This will trigger the "✅ VETO" in your terminal
                    else:
                        is_asymmetric = True # Clearly Asymmetric (Flood)
                else:
                    is_asymmetric = True # No ACKs received (SYN Flood)

                print(f"🔍 [ML-RESULT] src={src_mac} | Decision={decision} | Conf={confidence:.2f}")
                print(f"🛡️ [SHIELD-CHECK] syn={syn_count} ack={ack_count} | Asymmetric={is_asymmetric}")

                # 5. MITIGATION LOGIC
                if decision == 1:
                    current_status = SUSPECT_IP[src_mac]
                    
                    if current_status.get("blocked", False):
                        return

                    if is_asymmetric:
                        current_status["strikes"] += 1
                        current_status["last_flagged"] = time.time()
                        strikes = current_status["strikes"]
                        
                        print(f"⚠ FLAGGED {src_mac} | strikes={strikes}/{STRIKE_THRESHOLD_2}")

                        if strikes >= STRIKE_THRESHOLD_2:
                            # Apply OpenFlow DROP rule
                            match = parser.OFPMatch(eth_src=src_mac)
                            self.add_flow(datapath, 100, match, [], idle_timeout=0, hard_timeout=0)
                            current_status["blocked"] = True
                            
                            if "first_suspicious_time" in current_status:
                                ttm = time.time() - current_status["first_suspicious_time"]
                                print(f"🔴 HARD BLOCK {src_mac} | TTM: {ttm:.2f}s")
                            
                            # Clean up victim stats
                            if dst_mac in DST_STATS:
                                DST_STATS[dst_mac]["alert_count"] = 0
                    else:
                        # IMPORTANT: Overwrite variables so the Log is accurate
                        decision = 0 
                        is_correct = True # It is now "Correct" because we correctly identified benign traffic
                        print(f"✅ VETO: {src_mac} is a Flash Crowd (Symmetric Traffic). Blocking bypassed.")

                # 6. CSV LOGGING
                with open(LATENCY_LOG, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        time.time(),
                        src_mac,
                        dst_mac,
                        total_latency_ms,
                        inference_latency_ms,
                        decision,
                        (self.ml_calls / self.total_detections * 100),
                        is_correct,
                        ttm,
                        cpu_util,
                        mem_util,
                        syn_count,
                        ack_count
                    ])

            except Exception as e:
                print(f"❌ Detection execution failed: {e}")
                self.logger.warning(f"Detection error: {e}")
    # ---------------- Packet-In Handler ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        packet_in_time = time.time()

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # 1. INITIALIZE FLOW STATS
        flow_key = (src_mac, dst_mac)
        fs = FLOW_STATS[flow_key]
        src_tracker = None

        # 2. SYMMETRY TRACKING (Final Optimized Version)
        if ip_pkt and tcp_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # --- SYN: Client to Server ---
            if tcp_pkt.bits & tcp.TCP_SYN:
                stats = DST_STATS[dst_ip]
                if "source_ratios" not in stats:
                    stats["source_ratios"] = defaultdict(lambda: {"syn": 0, "ack": 0})
                stats["source_ratios"][src_ip]["syn"] += 1
                src_tracker = stats["source_ratios"][src_ip]

            # --- ACK: Server to Client ---
            elif tcp_pkt.bits & tcp.TCP_ACK:
                stats = DST_STATS[src_ip] # Server is source
                if "source_ratios" in stats and dst_ip in stats["source_ratios"]:
                    stats["source_ratios"][dst_ip]["ack"] += 1
                    src_tracker = stats["source_ratios"][dst_ip]

            # --- FALLBACK: Ensure src_tracker is ALWAYS found for the ML Call ---
            if src_tracker is None:
                # Check if this is a Client -> Server data packet
                stats = DST_STATS.get(dst_ip)
                if stats and "source_ratios" in stats:
                    src_tracker = stats["source_ratios"].get(src_ip)

        # 3. MAC LEARNING & FORWARDING (Standard Switch Logic)
        if SUSPECT_IP[src_mac]["strikes"] >= STRIKE_THRESHOLD_2:
            return # Drop if already hard-blocked

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 50, match, actions, idle_timeout=0, hard_timeout=0)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        # 4. FLOW STATISTICS UPDATE
        now = time.time()
        rev_key = (dst_mac, src_mac)
        fs["last_seen"] = now
        pkt_size = len(msg.data)
        fs["total_bytes"] += pkt_size

        if rev_key in FLOW_STATS:
            FLOW_STATS[rev_key]["bwd_packets"] += 1
            FLOW_STATS[rev_key]["bwd_pkt_len"].append(pkt_size)
        else:
            fs["fwd_packets"] += 1
            fs["fwd_pkt_len"].append(pkt_size)

        # 5. SYMMETRY SHIELD & ML TRIGGER
        # Check if this specific source is behaving like a Flash Crowd
        is_flash_crowd = False
        if src_tracker:
            s_syn = src_tracker["syn"]
            s_ack = src_tracker["ack"]
            s_ratio = s_syn / s_ack if s_ack > 0 else s_syn
            if s_syn > 20 and s_ratio < 2.0:
                is_flash_crowd = True

        # Trigger ML only if it's NOT a confirmed Flash Crowd
        if not is_flash_crowd and fs["fwd_packets"] % 50 == 0 and fs["fwd_packets"] > 0:
            trigger_time = time.time()
            duration = max(now - fs["start_time"], 0.001)
            
            features = {
                "duration": duration,
                "fwd_packets": fs["fwd_packets"],
                "bwd_packets": fs["bwd_packets"],
                "fwd_pkt_len_mean": sum(fs["fwd_pkt_len"]) / len(fs["fwd_pkt_len"]) if fs["fwd_pkt_len"] else 0,
                "bwd_pkt_len_mean": sum(fs["bwd_pkt_len"]) / len(fs["bwd_pkt_len"]) if fs["bwd_pkt_len"] else 0,
                "bytes_per_sec": fs["total_bytes"] / duration,
                "packets_per_sec": (fs["fwd_packets"] + fs["bwd_packets"]) / duration,
                "syn_count": fs["syn_count"],
                "ack_count": fs["ack_count"],
            }
            
            # Spawn detection asynchronously
            hub.spawn(
                self._perform_detection,
                features, 
                src_mac, 
                dst_mac, 
                datapath, 
                parser,
                packet_in_time=packet_in_time,
                trigger_time=trigger_time,
                # Pass the reference to the dictionary itself, not the numbers
                src_tracker=src_tracker 
            )