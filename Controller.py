import time
import json
import threading
import statistics
import logging
import queue
from ryu.app.wsgi import WSGIApplication, ControllerBase, Response, route
from webob import Response
import traceback

from ryu.base import app_manager
from ryu.cmd import manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp, udp, icmp

from api_handlers import BlocklistApi, NetworkStatsApi, HostApi, PROTO_MAP 

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("Initializing controller...")
        
        #--------------------------------------- Gestione degli switch e dei flussi ---------------------------------------
        self.datapaths = {}
        self.mac_to_port = {}
        self.mac_to_ip = {}

        #Statistiche delle porte
        self.port_stats = {}
        self.port_stats_lock = threading.Lock()

        #Statistiche dei flussi
        self.flow_stats = {}
        self.flow_stats_lock = threading.Lock()

        #Flussi bloccati
        self.blocked_flows = {} # blocked_flows: {datapath_id: {flow_key: {...}}}
        self.blocked_flows_lock = threading.Lock()
        
        #Flussi da sbloccare
        self.unblocked_flows = {} # unblocked_flows: {datapath_id: {flow_key: {...}}}
        self.unblocked_flows_lock = threading.Lock()

        #--------------------------------------- Gestione della bandwidth dinamica --------------------------------------- 
        self.total_bandwidth = 300000
        self.threshold_bandwidth = 0.8 * self.total_bandwidth
        self.threshold_bandwidth_lock = threading.Lock()
        self.bandwidth_thread = hub.spawn(self._calculate_threshold_bandwidth)

        #--------------------------------------- Gestione delle anomalie e congestione ---------------------------------------
        self.error_percentage_threshold = 0.04 #4% di errore ammissibile sulle trasmissioni nella rete

        # Variabili per la detection di burst/anomalie
        self.BURST_CHANGE_RATE_BW_THRESHOLD = 0.4 # 40% di aumento
        self.BURST_CHANGE_RATE_PKT_THRESHOLD = 0.4 # 40% di aumento

        self.HIGH_PACKET_RATE_THRESHOLD = 10000 # inizializzato a 10000 pacchetti/sec - viene aggiornato dinamicamente in _calculate_threshold_bandwidth 

        self.congestion = False

        #Numero di tentativi per bloccare/sbloccare un flusso in base al suo ip_proto
        self.block_thresholds = {6: 10, 17: 2} #i flussi UDP vengono bloccati più velocemente dei flussi TCP perchè tendono ad occupare velocemente la banda
        self.unblock_thresholds = {6: 2, 17: 2}

        #--------------------------------------- Gestione delle API ---------------------------------------
        self.enforcement_queue = queue.Queue() # Coda per le azioni di enforcement (per la modularità)

        # Inizializzazione WSGI per l'API REST
        self.wsgi = kwargs['wsgi']
        
        # Dati da passare alle API. Includi tutte le strutture necessarie
        """self.api_data = {
            'dps': self.datapaths,
            'enforcement_queue': self.enforcement_queue,
            'mac_to_ip': self.mac_to_ip, 
            'port_stats': self.port_stats, # statistiche delle porte
            'port_stats_lock': self.port_stats_lock,
            'flow_stats': self.flow_stats, # statistiche dei flussi
            'flow_stats_lock': self.flow_stats_lock,
            'logger': self.logger, # logger
            'blocked_flows': self.blocked_flows,
            'blocked_flows_lock': self.blocked_flows_lock,
            'unblocked_flows': self.unblocked_flows,
            'unblocked_flows_lock': self.unblocked_flows_lock
        }"""
        
        # Registra le API con i dati condivisi
        self.wsgi.register(BlocklistApi, {'dps': self.datapaths, 
                                          'blocked_flows': self.blocked_flows,
                                          'unblocked_flows': self.unblocked_flows, 
                                          'enforcement_queue': self.enforcement_queue,
                                          'blocked_flows_lock': self.blocked_flows_lock,
                                          'unblocked_flows_lock': self.unblocked_flows_lock,
                                          'logger': self.logger})
        self.wsgi.register(NetworkStatsApi, {'port_stats': self.port_stats, 
                                             'port_stats_lock': self.port_stats_lock,
                                             'flow_stats': self.flow_stats, 
                                             'flow_stats_lock': self.flow_stats_lock,
                                             'mac_to_ip': self.mac_to_ip, 
                                             'logger': self.logger})
        self.wsgi.register(HostApi, {'mac_to_ip': self.mac_to_ip, 
                                     'port_stats': self.port_stats,
                                     'port_stats_lock': self.port_stats_lock,
                                     'flow_stats': self.flow_stats, 
                                     'flow_stats_lock': self.flow_stats_lock,
                                     'blocked_flows': self.blocked_flows, 
                                     'blocked_flows_lock': self.blocked_flows_lock,
                                     'logger': self.logger})

        #--------------------------------------- Monitoraggio ed enforcement --------------------------------------- 
        self.sleep_time = 2
        self.monitor_thread = hub.spawn(self._monitor)
        self.thread = hub.spawn(self._enforcement_manager)

    #-------------------------------------------------------- Utility Function --------------------------------------------------------
    def _initial_threshold_bandwidth(self):
        return 0.8 * self.total_bandwidth

    def _calculate_threshold_bandwidth(self): 
        while True:
            hub.sleep(10)
            min_bandwidth = self.total_bandwidth * 0.1  # B/s
            max_bandwidth = self.total_bandwidth
            adjustment_factor = 0.05  # 5%

            with self.port_stats_lock:
                throughputs = [
                                    port_data['total']
                                    for dp_stats in self.port_stats.values()
                                    for port_data in dp_stats.values()
                                    if 'total' in port_data
                                ]
                
                packet_sizes = [
                    port_data['average_packet_size']
                    for dp_stats in self.port_stats.values()
                    for port_data in dp_stats.values()
                    if 'average_packet_size' in port_data and port_data['average_packet_size'] > 0
                ]

            if not throughputs:
                self.logger.info(f"\n ****************[BANDWIDTH UPDATE] Dati insufficienti per l'aggiornamento **************** \n")
                continue  # Nessun dato disponibile

            average_usage = statistics.mean(throughputs)
            std_dev = statistics.stdev(throughputs) if len(throughputs) > 1 else 0

            with self.threshold_bandwidth_lock:
                new_threshold = self.threshold_bandwidth
                if average_usage < 0.2 * self.threshold_bandwidth:
                    if average_usage == 0 or average_usage < min_bandwidth * 0.1:
                        new_threshold *= (1 - adjustment_factor)
                    else:
                        new_threshold *= (1 + adjustment_factor)
                elif average_usage > 0.9 * self.threshold_bandwidth or std_dev > average_usage * 0.5:
                    new_threshold *= (1 - adjustment_factor)

                new_threshold = max(min_bandwidth, min(max_bandwidth, new_threshold))
                self.threshold_bandwidth = new_threshold

                """if packet_sizes:
                    average_packet_size = statistics.mean(packet_sizes) # media delle dimensioni dei pacchetti osservate
                    self.HIGH_PACKET_RATE_THRESHOLD = int(self.threshold_bandwidth / average_packet_size)
                else:
                    self.HIGH_PACKET_RATE_THRESHOLD = 10000""" # Fallback a un valore predefinito se non ci sono dati di dimensione pacchetto

            self.logger.info(f"\n ****************[BANDWIDTH UPDATE] Nuova soglia dinamica: {new_threshold:.2f} B/s ****************\n")
    
    def _check_congestion(self): #TODO: integrare la funzione con un meccanismo di rilevazione della congestione anche a livello dei singoli switch
        with self.port_stats_lock:
            total = [p['total'] for dp in self.port_stats.values() for p in dp.values() if 'total' in p]
            packet_rates = [p['packet_rate_total'] for dp in self.port_stats.values() for p in dp.values() if 'packet_rate_total' in p]
        
            """rx_errors = sum(p['rx_errors'] for dp in self.port_stats.values() for p in dp.values() if 'rx_errors' in p)
            tx_errors = sum(p['tx_errors'] for dp in self.port_stats.values() for p in dp.values() if 'tx_errors' in p)
            rx_packets = sum(p['rx_packets'] for dp in self.port_stats.values() for p in dp.values() if 'rx_packets' in p)
            tx_packets = sum(p['tx_packets'] for dp in self.port_stats.values() for p in dp.values() if 'tx_packets' in p)
"""
            rx_errors = sum(p.get('delta_rx_errors', 0) for dp in self.port_stats.values() for p in dp.values() if 'delta_rx_errors' in p)
            tx_errors = sum(p.get('delta_tx_errors', 0) for dp in self.port_stats.values() for p in dp.values() if 'delta_tx_errors' in p)
            rx_packets = sum(p.get('delta_rx_packets', 0) for dp in self.port_stats.values() for p in dp.values() if 'delta_rx_packets' in p)
            tx_packets = sum(p.get('delta_tx_packets', 0) for dp in self.port_stats.values() for p in dp.values() if 'delta_tx_packets' in p)

        if not total:
            #self.logger.debug("[CHECK CONGESTION] Nessun dato totale disponibile per rilevare congestione.")
            self.congestion = False
            return False
        
        avg = statistics.mean(total)
        avg_packet_rate = statistics.mean(packet_rates) if packet_rates else 0

        new_threshold = self.threshold_bandwidth
        packet_rate_threshold = self.HIGH_PACKET_RATE_THRESHOLD

        is_throughput_high = avg > new_threshold
        is_packet_rate_high = avg_packet_rate > packet_rate_threshold

        total_errors_current = rx_errors + tx_errors
        total_packets_current = rx_packets + tx_packets

        is_errors_high = False
        error_percentage = 0.0
        if total_packets_current > 0:
            error_percentage = total_errors_current / total_packets_current
            if error_percentage > self.error_percentage_threshold:
                is_errors_high = True
                #self.logger.warning(f"[CHECK CONGESTION] Alta percentuale di errori rilevata: {error_percentage:.2%}")

        #self.logger.debug(f"[CHECK CONGESTION DEBUG] Avg Throughput: {avg:.2f} B/s (Threshold: {new_threshold:.2f} B/s) -> High Throughput: {is_throughput_high}")
        #self.logger.debug(f"[CHECK CONGESTION DEBUG] Avg Packet Rate: {avg_packet_rate:.2f} Pkts/s (Threshold: {packet_rate_threshold} Pkts/s) -> High Packet Rate: {is_packet_rate_high}")
        #self.logger.debug(f"[CHECK CONGESTION DEBUG] Total Errors Delta (Interval): {total_errors_current}, Total Packets Delta (Interval): {total_packets_current}, Error Pct: {error_percentage:.2%} (Threshold: {self.error_percentage_threshold:.2%}) -> High Errors: {is_errors_high}")

        congestion = is_throughput_high or is_errors_high or is_packet_rate_high
        #self.logger.info(f"CONGESTION {is_throughput_high} - {is_errors_high} - {is_packet_rate_high}")
        if congestion:
            self.congestion = True
            #self.logger.info(f"[CHECK CONGESTION] CONGESTIONE RILEVATA: Throughput alto ({avg:.2f} B/s vs {new_threshold:.2f} B/s) o Errori elevati.")
        else:
            self.congestion = False
            #self.logger.info(f"[CHECK CONGESTION] Rete non congestionata. Avg throughput: {avg:.2f} B/s.")
            
        return congestion
    
    def _calculate_bandwidth_and_delay(self, stat, datapath_id, flow_key):
        match = stat.match

        ip_src = match.get('ipv4_src')
        if ip_src is None:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

        now = time.time()
        byte_count = stat.byte_count
        packet_count = getattr(stat, 'packet_count', 0)

        prev = self.flow_stats.setdefault(datapath_id, {}).get(flow_key)

        # Initialize variables
        delta_bytes = 0
        delta_packets = 0
        elapsed = 0
        bandwidth = 0.0
        packet_rate = 0.0
        bw_change_rate = 0.0
        pkt_change_rate = 0.0

        if prev is None:
            with self.flow_stats_lock: 
                self.flow_stats[datapath_id][flow_key] = {
                    'timestamp': now,
                    'byte_count': byte_count,
                    'packet_count': packet_count,
                    'last_bandwidth': 0.0,  
                    'last_packet_rate': 0.0
                }
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 

        elapsed = now - prev['timestamp']

        if elapsed <= 1e-6:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    
        if elapsed > 1e-6: 
            delta_bytes = byte_count - prev['byte_count']
            delta_packets = packet_count - prev.get('packet_count', 0)

            if delta_bytes < 0: # Assumendo contatori a 64-bit per Ryu OpenFlow stats
                return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
            if delta_packets < 0:
                return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

            bandwidth = delta_bytes / elapsed * 8 / 1e6 
            packet_rate = delta_packets / elapsed 

            prev_bandwidth = prev.get('last_bandwidth', 0.0)
            if prev_bandwidth > 0:
                bw_change_rate = (bandwidth - prev_bandwidth) / prev_bandwidth
            else:
                bw_change_rate = 0.0 #bandwidth 

            prev_packet_rate = prev.get('last_packet_rate', 0.0)
            if prev_packet_rate > 0:
                pkt_change_rate = (packet_rate - prev_packet_rate) / prev_packet_rate
            else:
                pkt_change_rate = 0.0

        with self.flow_stats_lock: 
            self.flow_stats[datapath_id][flow_key] = {
                'timestamp': now,
                'byte_count': byte_count,
                'packet_count': packet_count, 
                'last_bandwidth': bandwidth,
                'last_packet_rate': packet_rate 
            }

        return bandwidth, elapsed, bw_change_rate, pkt_change_rate, delta_bytes, delta_packets, packet_rate
    
    #-------------------------------------------------------- Gestione della rete --------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"Switch {datapath.id} connected and default flow added.")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(f"Datapath {datapath.id} registered.")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info(f"Datapath {datapath.id} unregistered.")

                # Pulizia strutture dati associate
                self.mac_to_port.pop(datapath.id, None)
                with self.port_stats_lock:
                    self.port_stats.pop(datapath.id, None)
                with self.blocked_flows_lock:
                    self.blocked_flows.pop(datapath.id, None)
                with self.unblocked_flows_lock:
                    self.unblocked_flows.pop(datapath.id, None)
                self.mac_to_ip.pop(datapath.id, None)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        datapath_id = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port'] if 'in_port' in msg.match else None 
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        ip_src = None
        ip_dst   = None
        ip_proto = None

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst   = ip_pkt.dst
            ip_proto = ip_pkt.proto
            match = parser.OFPMatch(
                eth_type=0x0800,
                in_port=in_port,
                eth_dst=dst,
                eth_src=src,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst,
                ip_proto=ip_proto
            )
        else:
            match = parser.OFPMatch(eth_type=0x0806, eth_src=src, eth_dst=dst, in_port=in_port)

        with self.blocked_flows_lock:
            if datapath_id in self.blocked_flows and src in self.blocked_flows[datapath_id]:
                if self.blocked_flows[datapath_id][src].get("blocked", False):
                    self.logger.info(f" [PACKET IN HANDLER INFO] Dropping packet from blocked source {src} on switch {datapath_id}")
                    return

        self.mac_to_port.setdefault(datapath_id, {})
        self.mac_to_port[datapath_id][src] = in_port

        self.mac_to_ip.setdefault(datapath_id, {})
        self.mac_to_ip[datapath_id][src] = {
            'ip_src': ip_src,
            'in_port': in_port,
            'ip_proto': ip_proto
        }

        out_port = self.mac_to_port[datapath_id].get(dst, ofproto.OFPP_FLOOD)
        
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, 
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)

    #-------------------------------------------------------- Gestione statistiche di rete --------------------------------------------------------

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep_time)

    def _request_stats(self, datapath):
        self.logger.debug(f"[REQUEST STATS] Requesting stats from datapath {datapath.id}")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800) #per filtrare solo i flussi IP

        req_flow = parser.OFPFlowStatsRequest(datapath, match = match)
        datapath.send_msg(req_flow)

        req_port = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req_port)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev): 
        body = ev.msg.body
        datapath = ev.msg.datapath
        datapath_id = datapath.id
        current_time = time.time()

        with self.port_stats_lock:
            self.port_stats.setdefault(datapath_id, {})

        self.logger.info(f"\n       [PORT STATS][{datapath_id}] Port | RX_Bytes | TX_Bytes | RX_rate(B/s) | TX_rate(B/s) | Total(B/s) | RX_Pkts | TX_Pkts | RX_Err | TX_Err")
        for stat in body:
            port_no = stat.port_no
            if port_no == datapath.ofproto.OFPP_LOCAL:
                continue

            rx_bytes = stat.rx_bytes
            tx_bytes = stat.tx_bytes

            rx_packets = stat.rx_packets
            tx_packets = stat.tx_packets

            rx_errors = stat.rx_errors
            tx_errors = stat.tx_errors

            rx_rate = 0.0
            tx_rate = 0.0
            total = 0.0
            packet_rate_port = 0.0
            average_packet_size_port = 0.0
            delta_rx_packets = 0
            delta_tx_packets = 0
            delta_rx_bytes = 0
            delta_tx_bytes = 0
            delta_rx_errors = 0
            delta_tx_errors = 0

            total_delta_bytes = delta_rx_bytes + delta_tx_bytes
            total_delta_packets = delta_rx_packets + delta_tx_packets

            prev_stats = self.port_stats[datapath_id].get(port_no)
            if prev_stats:
                elapsed = current_time - prev_stats['timestamp']
                if elapsed > 0:
                    delta_rx_bytes = rx_bytes - prev_stats['rx_bytes']
                    delta_tx_bytes = tx_bytes - prev_stats['tx_bytes']
                    delta_rx_packets = rx_packets - prev_stats['rx_packets']
                    delta_tx_packets = tx_packets - prev_stats['tx_packets']
                    delta_rx_errors = rx_errors - prev_stats['rx_errors']
                    delta_tx_errors = tx_errors - prev_stats['tx_errors']
                    
                    rx_rate = delta_rx_bytes / elapsed
                    tx_rate = delta_tx_bytes / elapsed
                    total = rx_rate + tx_rate 

                    packet_rate_port = (delta_rx_packets + delta_tx_packets) / elapsed 

                    # Calcola la dimensione media dei pacchetti per questa porta
                    total_delta_bytes = delta_rx_bytes + delta_tx_bytes
                    total_delta_packets = delta_rx_packets + delta_tx_packets

                    if total_delta_packets > 0:
                        average_packet_size_port = total_delta_bytes / total_delta_packets
                    else: 
                        average_packet_size_port = 0
                else:
                    continue 

            self.logger.info(f"                   [{port_no:^4}] | {rx_bytes:>9.2f} | {tx_bytes:>9.2f} | {rx_rate:>12.2f} | {tx_rate:>12.2f} | {total:>11.2f} | {rx_packets:>7} | {tx_packets:>7} | {rx_errors:>6} | {tx_errors:>6}")
                
            with self.port_stats_lock:
                self.port_stats[datapath_id][port_no] = { #ne dizionario mi serve solo le rilevazioni precedenti per fare il confronto con quelle attuali
                    'timestamp': current_time,
                    'rx_bytes': rx_bytes,
                    'tx_bytes': tx_bytes,
                    'throughput_rx': rx_rate,
                    'throughput_tx': tx_rate,
                    'total': total,
                    'rx_packets': rx_packets,
                    'tx_packets': tx_packets,
                    'packet_rate_total': packet_rate_port,
                    'average_packet_size': average_packet_size_port,
                    'rx_errors': rx_errors,
                    'tx_errors': tx_errors,
                    'delta_rx_packets': delta_rx_packets, 
                    'delta_tx_packets': delta_tx_packets,
                    'delta_rx_errors': delta_rx_errors,
                    'delta_tx_errors': delta_tx_errors
                }

        self.logger.info(f"     [REQUEST STATS][PORTS STATS - {datapath_id}] STAT TRANSMISSION COMPLETED\n")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev): 
        body = ev.msg.body
        datapath = ev.msg.datapath
        datapath_id = datapath.id
        datapath_id = datapath.id

        self.logger.info(f"\n       [FLOW STATS][{datapath_id}]                         Byte_count | Duration | Total(B/s) | Bandwidth Variation | Packet Rate | Packet Rate Variation ")
        
        for stat in body: 
            match = stat.match
            if match.get('eth_type') != 0x0800:
                #self.logger.info("\n    [REQUEST STATS][FLOW STATS - {datapath_id}] Il flusso non è IP. Skipping stats.")
                continue

            ip_src = match.get('ipv4_src')
            if ip_src is None:
                #self.logger.debug(f"[FLOW STATS][{datapath_id}] No IP source found, skipping flow.")
                continue

            ip_dst = match.get('ipv4_dst', None)

            ip_proto = match.get('ip_proto', None)
            if ip_proto is None:   # Se il protocollo non è nel match, lo cerca in mac_to_ip
                for _, info in self.mac_to_ip.get(datapath_id, {}).items():
                    if info.get('ip_src') == ip_src:
                        ip_proto = info.get('ip_proto')
                        break
                if ip_proto is None: # Se ancora non trovato, salta
                    continue

            src_port = match.get('src_port', None)
            dst_port = match.get('dst_port', None)

            flow_key = (ip_src, ip_dst, src_port, dst_port, ip_proto)

            self._process_flow_for_policy_decision(datapath, stat, flow_key, ip_proto)
    
    def _process_flow_for_policy_decision(self, datapath, stat, flow_key, ip_proto): #TODO: RICONTROLLARE, CI SONO DELLE PARTI CHE NON MI CONVINCONO
        datapath_id = datapath.id
        current_time = time.time()

        # Calcolo della soglia dinamica per il blocco
        threshold_bandwidth = self.threshold_bandwidth
        if ip_proto == 17:
            threshold = threshold_bandwidth * 0.6 # i flussi UDP hanno una soglia pari al 60% della soglia dinamica perchè tendono a essere più bursty
        else:
            threshold = threshold_bandwidth * 1.0

        # Calcolo delle statistiche del flusso
        bandwidth, duration_sec, bw_change_rate, pkt_change_rate, _, _, packet_rate = self._calculate_bandwidth_and_delay(stat, datapath_id, flow_key)
        self.logger.info(f"        [FLOW {flow_key}]      {stat.byte_count:.2f}  |       {duration_sec:.2f}  |     {bandwidth:.2f} B/s  | {bw_change_rate:.2f} | {packet_rate:.2f} | {pkt_change_rate:.2f}")
        
        #Verifica dei burst e anomalie - TODO: si possono cambiare le soglie in base al tipo di flusso
        is_bursty_bandwidth = bw_change_rate > self.BURST_CHANGE_RATE_BW_THRESHOLD
        is_bursty_packet_rate = pkt_change_rate > self.BURST_CHANGE_RATE_PKT_THRESHOLD
        is_high_packet_rate = packet_rate > self.HIGH_PACKET_RATE_THRESHOLD #attacchi come SYN floods o UDP floods si basano su un elevato numero di pacchetti, non necessariamente un alto throughput in byte

        #Controllo sullo stato di congestione della rete
        congestion = self._check_congestion() 

        ip_src, ip_dst, src_port, dst_port, _ = flow_key
        default_match_params = {
            'eth_type': 0x0800,
            'ipv4_src': ip_src,
            'ipv4_dst': ip_dst,
            'ip_proto': ip_proto,
        }
        # Aggiungi le porte solo se non sono None
        if src_port is not None:
            if ip_proto == 6: # TCP
                default_match_params['tcp_src'] = src_port
            elif ip_proto == 17: # UDP
                default_match_params['udp_src'] = src_port
        if dst_port is not None:
            if ip_proto == 6: # TCP
                default_match_params['tcp_dst'] = dst_port
            elif ip_proto == 17: # UDP
                default_match_params['udp_dst'] = dst_port

        #Verifica sullo stato del flusso (bloccato lato controller o admin)
        current_block_status = False
        is_admin_blocked = False
        with self.blocked_flows_lock:
            flow_data = self.blocked_flows.get(datapath_id, {}).get(flow_key)
            if flow_data:
                current_block_status = flow_data['blocked']
                is_admin_blocked = flow_data.get('admin_blocked', False)

        #Gestione dei flussi già bloccati dal controller - le regole di blocco hanno priorità 2
        if stat.priority == 2:
            with self.unblocked_flows_lock:
                self.logger.info(f" [UNBLOCK CHECK][FLOW {flow_key}]")
                uflows = self.unblocked_flows.get(datapath_id, {})
                if flow_key in uflows:
                    self.logger.info(f" [UNBLOCK CHECK][FLOW {flow_key}] Flusso bloccato considerato per sblocco automatico.")
                    flow_info = uflows[flow_key]

                    # Flussi bloccati dall'admin NON DEVONO essere sbloccati automaticamente
                    if is_admin_blocked:
                        self.logger.info(f" [UNBLOCK CHECK][FLOW {flow_key}] Flusso bloccato da admin, non considerato per sblocco automatico.")
                        return 

                    # Condizione per incrementare il conteggio per lo sblocco:
                    if not congestion and bandwidth < threshold:
                        flow_info['count'] += 1
                        self.logger.info(f" [UNBLOCK CHECK][FLOW {flow_key}] Traffico droppato sotto soglia e rete non congestionata: {flow_info['count']} verifiche positive per lo sblocco.")
                    else:
                        if flow_info['count'] > 0: 
                            flow_info['count'] = 0
                            self.logger.info(f" [UNBLOCK COUNT][FLOW {flow_key}] Reset conteggio sblocco: Traffico droppato ancora alto o rete congestionata.")
            return
        
        #Gestione dei flussi bloccati dall'admin
        if is_admin_blocked:
            self.logger.warning(f" [POLICY DECISION][FLOW {flow_key}] Traffic is admin-blocked. Ensuring block rule is in place.")
            if not current_block_status:
                self.enforcement_queue.put({
                    'type': 'block', 
                    'datapath': datapath, 
                    'flow_key': flow_key,
                    'admin_override': True, 
                    'match_params': default_match_params # Passa il dizionario dei parametri del match
                })
            return
        
        #Gestione dei flussi non bloccati: per poter bloccare un flusso, la rete deve essere congestionata e il traffico deve superare le soglie di banda o pcket_rate
        if not current_block_status and not is_admin_blocked:
            block_window = self.block_thresholds.get(ip_proto, 5)

            with self.blocked_flows_lock:
                self.blocked_flows.setdefault(datapath_id, {}).setdefault(flow_key, {'count': 0, 'blocked': False, 'type': ip_proto})
                if self.congestion: #se la rete è congestionata
                    self.logger.info(f"[FLOW BLOCK][FLOW {flow_key}] Congestione E anomalia rilevata.")

                    #Verifica se il flusso ha superato le soglie di band o packet_rate oppure ci sono stati burst
                    if bandwidth >= threshold or is_bursty_bandwidth or is_bursty_packet_rate or is_high_packet_rate:
                        flow_info = self.blocked_flows[datapath_id][flow_key]
                        flow_info['count'] += 1

                        if flow_info['count'] < block_window:
                            self.logger.warning(f"  [FLOW BLOCK][FLOW {flow_key}] Anomalia rilevata: {block_window - flow_info['count']} rilevazioni prima del blocco")
                            flow_info.update({
                                'count': flow_info['count'],
                                'time': current_time,
                                'blocked': False,
                                'type': ip_proto
                            })
                        else:
                            self.logger.warning(f"  [FLOW BLOCK][FLOW {flow_key}] Anomalia persistente. Mettendo in coda per blocco.")
                            flow_info.update({'blocked': True, 'time': current_time})
                            self.enforcement_queue.put({
                                'type': 'block', 
                                'datapath': datapath, 
                                'flow_key': flow_key, 
                                'admin_override': False, 
                                'match_params': default_match_params # Passa il dizionario dei parametri del match
                            })
                            with self.unblocked_flows_lock:
                                self.unblocked_flows.setdefault(datapath_id, {})
                                self.unblocked_flows[datapath_id][flow_key] = {
                                    'count': 0, 'time': current_time, 'type': ip_proto, 'match': None # 'match' verrà aggiornato da _limit_traffic
                                }
                            current_block_status = True
                            hub.spawn(self._check_and_unblock_traffic, datapath, flow_key, ip_proto)

    def _enforcement_manager(self): #TODO: 
        self.logger.info("Enforcement Manager thread started.")

        while True:
            try:
                action = self.enforcement_queue.get() # Blocca finché non c'è un'azione

                action_type = action.get('type')
                datapath = action.get('datapath')
                flow_key = action.get('flow_key')
                admin_override = action.get('admin_override', False)
                match_params = action.get('match_params', None)

                if action_type == 'block':
                    self._limit_traffic(datapath, flow_key, match_params, admin_override)
                    self.logger.info(f"  [ENFORCEMENT] Blocked {flow_key} (Admin: {admin_override}) via manager.")
                elif action_type == 'unblock':
                    self._unblock_flows(datapath, flow_key, match_params)
                    self.logger.info(f"  [ENFORCEMENT] Unblocked {flow_key} (Admin: {admin_override}) via manager.")
                else:
                    self.logger.warning(f"  [ENFORCEMENT] Unknown action type: {action_type}")

                self.enforcement_queue.task_done()
            except Exception as e:
                self.logger.error(f"Error in Enforcement Manager: {e}")

    #-------------------------------------------------------- Gestione blocco/sblocco --------------------------------------------------------

    def _build_match(self, parser, **kwargs):
        return parser.OFPMatch(**{k: v for k, v in kwargs.items() if v is not None})
                           
    def _limit_traffic(self, datapath, flow_key, match_params, admin_override=False):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
  
        match = None
        match = self._build_match(parser, **match_params) #TODO: ASSICURARE CHE L'API FORNISCA SEMPRE MATCH_PARAMS
        """Campi match_params:  'eth_type': 0x0800, 
                                'ipv4_src': ip_src,
                                'ip_proto': ip_proto,
                                'ipv4_dst': ipv4_dst,
                                'eth_src': eth_src,
                                'in_port': in_port """
        
        if match is None:
            self.logger.error(f"Failed to build match for flow_key {flow_key}. Cannot block.")
            return

        with self.blocked_flows_lock:
            self.blocked_flows.setdefault(datapath.id, {})
            self.blocked_flows[datapath.id].setdefault(flow_key, {}) 
            
            self.blocked_flows[datapath.id][flow_key]['match'] = match 
            self.blocked_flows[datapath.id][flow_key]['blocked'] = True
            self.blocked_flows[datapath.id][flow_key]['time'] = time.time()
            self.blocked_flows[datapath.id][flow_key]['admin_blocked'] = admin_override
            self.blocked_flows[datapath.id][flow_key]['match_params_dict'] = match_params

        instructions = [] 

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=2,
            match=match,
            instructions=instructions,
            command=ofproto.OFPFC_ADD,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )

        datapath.send_msg(flow_mod)
        self.logger.info(f"             [FLOW BLOCK {datapath.id:016x}][FLOW {flow_key}] Flow blocked.")  

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        match_data = msg.match.to_jsondict().get('OFPMatch', {})
        
        ip_src = None
        ip_dst = None
        ip_proto = None
        src_port = None
        dst_port = None

        if 'oxm_fields' in match_data:
            for oxm_tlv in match_data['oxm_fields']:
                field_data = oxm_tlv.get('OXMTlv', {})
                field_name = field_data.get('field')
                field_value = field_data.get('value')

                if field_name == 'ipv4_src':
                    ip_src = field_value
                elif field_name == 'ipv4_dst':
                    ip_dst = field_value
                elif field_name == 'ip_proto':
                    ip_proto = field_value
                elif field_name == 'tcp_src':
                    src_port = field_value
                elif field_name == 'tcp_dst':
                    dst_port = field_value
                elif field_name == 'udp_src':
                    src_port = field_value
                elif field_name == 'udp_dst':
                    dst_port = field_value

        flow_key = (ip_src, ip_dst, src_port, dst_port, ip_proto)
        
        if ip_proto is not None:
            try:
                ip_proto = int(ip_proto)
            except (ValueError, TypeError):
                self.logger.error(f"Could not convert ip_proto '{ip_proto}' to int for flow {flow_key}")
                ip_proto = None # Reset to None if conversion fails

        reason = {
            ofp.OFPRR_IDLE_TIMEOUT:  "IDLE TIMEOUT",
            ofp.OFPRR_HARD_TIMEOUT:  "HARD TIMEOUT",
            ofp.OFPRR_DELETE:        "DELETE",
            ofp.OFPRR_GROUP_DELETE:  "GROUP DEL"
        }.get(msg.reason, "UNKNOWN")

        self.logger.info(f"[FLOW REMOVED][DATAPATH {dp.id:016x}][RECONSTRUCTED_FLOW_KEY {flow_key}] Rule removed due to: {reason}. Raw Match: {match_data}")

        flow_processed = False

        with self.blocked_flows_lock:
            if dp.id in self.blocked_flows:
                target_flow_key = None

                # 1. Try direct lookup using the reconstructed_flow_key
                if flow_key in self.blocked_flows[dp.id]:
                    target_flow_key = flow_key
                    self.logger.debug(f"[FLOW REMOVED] Direct match found for {flow_key}.")
                else:
                    # 2. Fallback: Iterate and compare by reconstructing flow_key from stored match_params_dict
                    self.logger.debug(f"[FLOW REMOVED] Direct match failed. Attempting deep comparison for {flow_key}.")
                    for stored_fk, flow_data in list(self.blocked_flows[dp.id].items()):
                        stored_match_params = flow_data.get('match_params_dict')
                        if stored_match_params:
                            # Reconstruct the flow_key from the *stored* match_params
                            stored_ip_src = stored_match_params.get('ipv4_src', None)
                            stored_ip_dst = stored_match_params.get('ipv4_dst', None)
                            stored_ip_proto = stored_match_params.get('ip_proto', None)
                            
                            stored_src_port = None
                            if stored_ip_proto == 6:
                                stored_src_port = stored_match_params.get('tcp_src', None)
                            elif stored_ip_proto == 17:
                                stored_src_port = stored_match_params.get('udp_src', None)
                            
                            stored_dst_port = None
                            if stored_ip_proto == 6:
                                stored_dst_port = stored_match_params.get('tcp_dst', None)
                            elif stored_ip_proto == 17:
                                stored_dst_port = stored_match_params.get('udp_dst', None)
                            
                            reconstructed_from_stored_params = (stored_ip_src, stored_ip_dst, stored_src_port, stored_dst_port, stored_ip_proto)
                            
                            if flow_key == reconstructed_from_stored_params:
                                target_flow_key = stored_fk # Found the actual stored key
                                self.logger.info(f"[FLOW REMOVED][DATAPATH {dp.id:016x}][RECONSTRUCTED_FLOW_KEY {flow_key}] Found matching stored key: {target_flow_key} via params comparison.")
                                break # Exit inner loop once found

                if target_flow_key:
                    # Process the found flow_key
                    if reason in ["DELETE", "IDLE TIMEOUT", "HARD TIMEOUT"]:
                        self.logger.info(f"Cleaning up internal state for {target_flow_key} on DP {dp.id}.")
                        
                        del self.blocked_flows[dp.id][target_flow_key]
                        
                        with self.unblocked_flows_lock:
                            removed_from_unblocked = self.unblocked_flows[dp.id].pop(target_flow_key, None)
                            if removed_from_unblocked:
                                self.logger.info(f"Flow {target_flow_key} also removed from unblocked_flows state.")
                            else:
                                self.logger.debug(f"Flow {target_flow_key} was not found in unblocked_flows state (or already removed).")
                        
                        flow_processed = True
                    else:
                        self.logger.warning(f"Flow {target_flow_key} on DP {dp.id} removed for reason '{reason}', but not cleaned from state (expected DELETE/TIMEOUT).")
                else:
                    self.logger.debug(f"Flow {flow_key} removed from DP {dp.id}, but no matching key found in blocked_flows internal state.")
            else:
                self.logger.debug(f"Flow removed from DP {dp.id}, but datapath {dp.id} not found in blocked_flows internal state.")
        
        if not flow_processed:
            self.logger.debug(f"Flow removal for {flow_key} on DP {dp.id} did not lead to internal state cleanup for expected reasons.")

    def _check_and_unblock_traffic(self, datapath, flow_key, ip_proto):
        datapath_id = datapath.id

        unblock_window = self.unblock_thresholds.get(ip_proto, 5)

        while True:
            hub.sleep(self.sleep_time)
            #self.logger.info(f"         [UNBLOCK CHECK {datapath.id:016x}][FLOW_KEY {flow_key}][TYPE {ip_proto}] CONTROLLO SBLOCCO")

            flow_info = self.unblocked_flows.get(datapath_id, {}).get(flow_key)
            if not flow_info: #se il flusso è già stato sbloccato altrove
                return
            count = flow_info['count']

            self.logger.info(f"         [UNBLOCK CHECK {datapath.id:016x}][FLOW_KEY {flow_key}][TYPE {ip_proto}][TYPE {ip_proto}] {count} verifiche positive.")

            if count >= unblock_window:
                self.logger.info(f"         [UNBLOCK CHECK {datapath.id:016x}][FLOW_KEY {flow_key}][TYPE {ip_proto}][TYPE {ip_proto}] {count} Procedo allo sblocco.")
                self.enforcement_queue.put({'type': 'unblock', 'datapath': datapath, 'flow_key': flow_key, 'admin_override': False})
                return
                        
    def _unblock_flows(self, datapath, flow_key, match_params = None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = None
        with self.blocked_flows_lock:
            flow_info_blocked = self.blocked_flows.get(datapath.id, {}).get(flow_key)
            if flow_info_blocked and 'match' in flow_info_blocked:
                match = flow_info_blocked['match']
            
        if match is None and match_params:
            match = self._build_match(parser, **match_params)

        if match is None:
            self.logger.warning(f"             [FLOW UNBLOCK {datapath.id:016x}][FLOW {flow_key}] Could not find stored match for unblocking. Cannot unblock.")
            return
        
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=2,
            match=match,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )
        datapath.send_msg(flow_mod)
        self.logger.info(f"             [FLOW UNBLOCK {datapath.id:016x}][FLOW {flow_key}] Flow unblocked.")
