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

        #--------------------------------------- Gestione delle anomalie e congestione ---------------------------------------
        self.congestion = False

        self.error_percentage_threshold = 0.06 #6% di errore
        # Variabili per la detection di burst/anomalie
        self.BURST_CHANGE_RATE_BW_THRESHOLD = 0.7 # 70% di aumento
        self.BURST_CHANGE_RATE_PKT_THRESHOLD = 0.7 # 70% di aumento
        self.HIGH_PACKET_RATE_THRESHOLD = 10000 # 10000 pacchetti/sec

        #Numero di tentativi per bloccare/sbloccare un flusso in base al suo ip_proto
        self.block_thresholds = {6: 12, 17: 2} 
        self.unblock_thresholds = {6: 4, 17: 4}

        # Coda per le azioni di enforcement (per la modularità)
        self.enforcement_queue = queue.Queue()

        # Inizializzazione WSGI per l'API REST
        self.wsgi = kwargs['wsgi']
        
        # Dati da passare alle API. Includi tutte le strutture necessarie
        self.api_data = {
            'dps': self.datapaths,
            'blocked_flows': self.blocked_flows,
            'enforcement_queue': self.enforcement_queue,
            'blocked_flows_lock': self.blocked_flows_lock,
            'mac_to_ip': self.mac_to_ip, 
            'port_stats': self.port_stats, # statistiche delle porte
            'port_stats_lock': self.port_stats_lock,
            'flow_stats': self.flow_stats, # statistiche dei flussi
            'flow_stats_lock': self.flow_stats_lock,
            'logger': self.logger # logger
        }
        
        # Registra le API con i dati condivisi
        self.wsgi.register(BlocklistApi, {'dps': self.datapaths, 'blocked_flows': self.blocked_flows, 
                             'unblocked_flows': self.unblocked_flows, 
                             'enforcement_queue': self.enforcement_queue, 
                             'blocked_flows_lock': self.blocked_flows_lock, 
                             'unblocked_flows_lock': self.unblocked_flows_lock,
                             'logger': self.logger})
        self.wsgi.register(NetworkStatsApi, {'port_stats': self.port_stats, 'port_stats_lock': self.port_stats_lock,
                                        'flow_stats': self.flow_stats, 'flow_stats_lock': self.flow_stats_lock,
                                        'mac_to_ip': self.mac_to_ip, 'logger': self.logger})
        self.wsgi.register(HostApi, {'mac_to_ip': self.mac_to_ip, 'port_stats': self.port_stats,
                                'port_stats_lock': self.port_stats_lock,
                                'flow_stats': self.flow_stats, 'flow_stats_lock': self.flow_stats_lock,
                                'blocked_flows': self.blocked_flows, 'blocked_flows_lock': self.blocked_flows_lock,
                                'logger': self.logger})

        #--------------------------------------- Gestione della bandwidth dinamica --------------------------------------- 
        self.total_bandwidth = 700000
        self.threshold_bandwidth = 0.8 * self.total_bandwidth
        self.threshold_bandwidth_lock = threading.Lock()
        self.bandwidth_thread = hub.spawn(self._calculate_threshold_bandwidth)

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

            if not throughputs:
                self.logger.info(f"\n ****************[BANDWIDTH UPDATE] Dati insufficienti per l'aggiornamento **************** \n")
                continue  # Nessun dato disponibile

            average_usage = statistics.mean(throughputs)
            std_dev = statistics.stdev(throughputs)

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

                average_packet_size = 1000  #TODO: stimare o calcolare dinamicamente
                self.HIGH_PACKET_RATE_THRESHOLD = int(self.threshold_bandwidth / average_packet_size)

            self.logger.info(f"\n ****************[BANDWIDTH UPDATE] Nuova soglia dinamica: {new_threshold:.2f} B/s ****************\n")
    
    def _check_congestion(self):
        with self.port_stats_lock:
            total = [p['total'] for dp in self.port_stats.values() for p in dp.values() if 'total' in p]
            rx_errors = sum(p['rx_errors'] for dp in self.port_stats.values() for p in dp.values() if 'rx_errors' in p)
            tx_errors = sum(p['tx_errors'] for dp in self.port_stats.values() for p in dp.values() if 'tx_errors' in p)
            rx_packets = sum(p['rx_packets'] for dp in self.port_stats.values() for p in dp.values() if 'rx_packets' in p)
            tx_packets = sum(p['tx_packets'] for dp in self.port_stats.values() for p in dp.values() if 'tx_packets' in p)

        if not total:
            #self.logger.debug("[CHECK CONGESTION] Nessun dato totale disponibile per rilevare congestione.")
            return False
        avg = statistics.mean(total)

        new_threshold = self.threshold_bandwidth

        is_throughput_high = avg > new_threshold * 0.6

        total_errors_current = rx_errors + tx_errors
        total_packets_current = rx_packets + tx_packets

        is_errors_high = False
        if total_packets_current > 0:
            error_percentage = total_errors_current / total_packets_current
            if error_percentage > self.error_percentage_threshold:
                is_errors_high = True
                #self.logger.warning(f"[CHECK CONGESTION] Alta percentuale di errori rilevata: {error_percentage:.2%}")

        congestion = is_throughput_high or is_errors_high
        if self.congestion:
            self.logger.info(f"[CHECK CONGESTION] CONGESTIONE RILEVATA: Throughput alto ({avg:.2f} B/s vs {new_threshold:.2f} B/s) o Errori elevati.")
        else:
            self.logger.info(f"[CHECK CONGESTION] Rete non congestionata. Avg throughput: {avg:.2f} B/s.")
            
        return congestion
    
    def _calculate_bandwidth_and_delay(self, stat, datapath_id):
        match = stat.match

        ip_src = match.get('ipv4_src')
        if ip_src is None:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 
        
        ip_proto = match.get('ip_proto', None)
        ip_dst = match.get('ipv4_dst', None)
        src_port = match.get('src_port', None)
        dst_port = match.get('dst_port', None)

        flow_key = (ip_src, ip_dst, src_port, dst_port, ip_proto) #l'ip_src è sempre presente, gli altri parametri possono non essere presenti

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
                    'last_packet_rate': 0.0,
                    #'ip_proto': ip_proto,
                    #'ip_dst': ip_dst, 
                    #'src_port': src_port, 
                    #'dst_port': dst_port
                }
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 

        elapsed = now - prev['timestamp']
        if elapsed > 1e-6: 
            delta_bytes = byte_count - prev['byte_count']
            delta_packets = packet_count - prev.get('packet_count', 0)

            if delta_bytes < 0:
                delta_bytes = byte_count
                delta_packets = packet_count

            bandwidth = delta_bytes / elapsed * 8 / 1e6 
            packet_rate = delta_packets / elapsed 

            prev_bandwidth = prev.get('last_bandwidth', 0.0)
            if prev_bandwidth > 0:
                bw_change_rate = (bandwidth - prev_bandwidth) / prev_bandwidth
            else:
                bw_change_rate = bandwidth 

            prev_packet_rate = prev.get('last_packet_rate', 0.0)
            if prev_packet_rate > 0:
                pkt_change_rate = (packet_rate - prev_packet_rate) / prev_packet_rate
            else:
                pkt_change_rate = packet_rate

        with self.flow_stats_lock: 
            self.flow_stats[datapath_id][flow_key] = {
                'timestamp': now,
                'byte_count': byte_count,
                'packet_count': packet_count, 
                'last_bandwidth': bandwidth,
                'last_packet_rate': packet_rate,
                #'ip_proto': ip_proto,
                #'ip_dst': ip_dst, 
                #'src_port': src_port, 
                #'dst_port': dst_port 
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

        in_port = msg.match['in_port']
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
            
            prev_stats = self.port_stats[datapath_id].get(port_no)
            if prev_stats:
                elapsed = current_time - prev_stats['timestamp']
                if elapsed > 0:
                    rx_rate = (rx_bytes - prev_stats['rx_bytes']) / elapsed
                    tx_rate = (tx_bytes - prev_stats['tx_bytes']) / elapsed
                    total = rx_rate + tx_rate
                else:
                    continue
            else:
                rx_rate = tx_rate = total = 0.0  # inizializzazione

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
                    'packet_rate_total': rx_packets + tx_packets,
                    'rx_errors': rx_errors,
                    'tx_errors': tx_errors
                }

        self.logger.info(f"     [REQUEST STATS][PORTS STATS - {datapath_id}] STAT TRANSMISSION COMPLETED\n")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev): 
        body = ev.msg.body
        datapath = ev.msg.datapath
        datapath_id = datapath.id
        datapath_id = datapath.id

        self.logger.info(f"\n       [FLOW STATS][{datapath_id}] Byte_count | Duration | Total(B/s) | Bandwidth Variation | Packet Rate | Packet Rate Variation ")
        
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
    
    def _process_flow_for_policy_decision(self, datapath, stat, flow_key, ip_proto):
        datapath_id = datapath.id
        current_time = time.time()

        # Calcolo della soglia dinamica per il blocco
        threshold_bandwidth = self.threshold_bandwidth
        if ip_proto == 17:
            threshold = threshold_bandwidth * 0.4
        else:
            threshold = threshold_bandwidth * 1.0

        # Calcolo delle statistiche del flusso
        bandwidth, duration_sec, bw_change_rate, pkt_change_rate, _, _, packet_rate = self._calculate_bandwidth_and_delay(stat, datapath_id)
        self.logger.info(f"        [FLOW {flow_key}]      {stat.byte_count:.2f}  |       {duration_sec:.2f}  |     {bandwidth:.2f} B/s  | {bw_change_rate:.2f} | {packet_rate:.2f} | {pkt_change_rate:.2f}")
        
        #Verifica dei burst e anomalie
        is_bursty_bandwidth = bw_change_rate > self.BURST_CHANGE_RATE_BW_THRESHOLD
        is_bursty_packet_rate = pkt_change_rate > self.BURST_CHANGE_RATE_PKT_THRESHOLD
        is_high_packet_rate = packet_rate > self.HIGH_PACKET_RATE_THRESHOLD

        #Controllo sullo stato di congestione della rete
        self.congestion = self._check_congestion() 

        #Verifica sullo stato del flusso (bloccato lato controller o admin)
        current_block_status = False
        is_admin_blocked = False

        with self.blocked_flows_lock:
            flow_data = self.blocked_flows.get(datapath_id, {}).get(flow_key)
            if flow_data:
                current_block_status = flow_data['blocked']
                is_admin_blocked = flow_data.get('admin_blocked', False)
        
        #Gestione dei flussi già bloccati dal controller
        if stat.priority == 2:
            #self.logger.info(f"[BLOCKED FLOW STATS][FLOW {flow_key}] Traffico droppato (già bloccato): {bandwidth:.2f} B/s")
            with self.unblocked_flows_lock:
                uflows = self.unblocked_flows.get(datapath_id, {})
                if flow_key in uflows:
                    flow_info = uflows[flow_key]

                    if flow_info and not is_admin_blocked: #i flussi bloccati dall'admin non possono essere sbloccati automaticamente - TODO: inserire lato admin un pulsante che, in fase di blocco, autorizza allo sblocco automatico
                        if bandwidth < threshold and not self.congestion:
                            flow_info['count'] += 1
                            self.logger.info(f" [UNBLOCK CHECK][FLOW {flow_key}] Traffico droppato sotto soglia e rete non congestionata: {flow_info['count']} verifiche positive per lo sblocco.")
                        elif bandwidth >= threshold:
                            flow_info['count'] = 0
                            self.logger.info(f" [UNBLOCK COUNT][FLOW {flow_key}] Reset conteggio sblocco: Traffico droppato ancora alto o rete congestionata.")
        
        #Gestione dei flussi bloccati dall'admin
        if is_admin_blocked:
            self.logger.warning(f" [POLICY DECISION][FLOW {flow_key}] Traffic is admin-blocked. Ensuring block rule is in place.")
            if not current_block_status:
                self.enforcement_queue.put({'type': 'block', 'datapath': datapath, 'flow_key': flow_key, 'admin_override': True})
            return
        
        #Gestione dei flussi non bloccati: per poter bloccare un flusso, la rete deve essere congestionata e il traffico deve superare le soglie di banda o pcket_rate
        if not current_block_status and not is_admin_blocked:
            block_window = self.block_thresholds.get(ip_proto, 5)

            with self.blocked_flows_lock:
                self.blocked_flows.setdefault(datapath_id, {}).setdefault(flow_key, {'count': 0, 'blocked': False, 'type': ip_proto})
                if self.congestion: #se la rete è congestionata
                    self.logger.info(f"[FLOW BLOCK][FLOW {flow_key}] Congestione E anomalia rilevata.")

                    #Verifica se il flusso ha superato le soglie di band o packet_rate oppure ci sono stati burst
                    #TODO: si possono includere altri controlli per identificare altri pattern di attacchi DoS
                    if bandwidth >= threshold or is_bursty_bandwidth or is_bursty_packet_rate or (ip_proto == 17 and is_high_packet_rate):
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
                            self.enforcement_queue.put({'type': 'block', 'datapath': datapath, 'flow_key': flow_key, 'admin_override': False})
                            with self.unblocked_flows_lock:
                                self.unblocked_flows.setdefault(datapath_id, {})
                                self.unblocked_flows[datapath_id][flow_key] = {
                                    'count': 0, 'time': current_time, 'type': ip_proto, 'match': None
                                }
                            current_block_status = True
                            hub.spawn(self._check_and_unblock_traffic, datapath, flow_key, ip_proto)

        """if current_block_status:
            with self.blocked_flows_lock:
                flow_info = self.blocked_flows.get(datapath_id, {}).get(flow_key)
                if flow_info and flow_info['count'] > 0 and not flow_info['blocked'] and not flow_info.get('admin_blocked', False):
                    flow_info['count'] -= 1
                    self.logger.info(f"  [FLOW BLOCK][FLOW {flow_key}] Anomalia risolta: {block_window - flow_info['count']} rilevazioni prima del blocco")"""

    def _enforcement_manager(self): 
        self.logger.info("Enforcement Manager thread started.")

        while True:
            try:
                action = self.enforcement_queue.get() # Blocca finché non c'è un'azione

                action_type = action.get('type')
                datapath = action.get('datapath')
                flow_key = action.get('flow_key')
                admin_override = action.get('admin_override', False)
                match_params = action.get('match_params', False)

                if action_type == 'block':
                    self._limit_traffic(datapath, flow_key, admin_override, match_params)
                    self.logger.info(f"  [ENFORCEMENT] Blocked {flow_key} (Admin: {admin_override}) via manager.")
                elif action_type == 'unblock':
                    self._unblock_flow(datapath, flow_key, match_params)
                    self.logger.info(f"  [ENFORCEMENT] Unblocked {flow_key} (Admin: {admin_override}) via manager.")
                else:
                    self.logger.warning(f"  [ENFORCEMENT] Unknown action type: {action_type}")

                self.enforcement_queue.task_done()
            except Exception as e:
                self.logger.error(f"Error in Enforcement Manager: {e}")

            hub.sleep(0.01) 

    #-------------------------------------------------------- Gestione blocco/sblocco --------------------------------------------------------

    def _build_match(self, parser, **kwargs):
        return parser.OFPMatch(**{k: v for k, v in kwargs.items() if v is not None})
                           
    def _limit_traffic(self, datapath, flow_key, admin_override=False, match_params=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        ip_src, ip_dst, src_port, dst_port, ip_proto = flow_key
  
        match = None
        if match_params:
            match = self._build_match(parser, **match_params)
            """Campi match_params:  'eth_type': 0x0800, 
                                    'ipv4_src': ip_src,
                                    'ip_proto': ip_proto,
                                    'ipv4_dst': ipv4_dst,
                                    'eth_src': eth_src,
                                    'in_port': in_port """
        else:
            match = self._build_match(
                parser,
                eth_type=0x0800,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst,
                ip_proto=ip_proto,
                src_port=src_port,
                dst_port=dst_port
            )

        with self.blocked_flows_lock:
            if datapath.id in self.blocked_flows and flow_key in self.blocked_flows[datapath.id]:
                self.blocked_flows[datapath.id][flow_key]['match'] = match
                self.blocked_flows[datapath.id][flow_key]['blocked'] = True
                self.blocked_flows[datapath.id][flow_key]['time'] = time.time()
                self.blocked_flows[datapath.id][flow_key]['admin_blocked'] = admin_override

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
        self.logger.info(f"             [FLOW BLOCK {datapath.id:016x}][IP {ip_src}][TYPE {ip_proto}] Flow blocked.")  

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _flow_removed_handler(self, ev): 
        msg = ev.msg
        dp  = msg.datapath
        ofp = dp.ofproto

        reason = {
            ofp.OFPRR_IDLE_TIMEOUT:  "IDLE TIMEOUT",
            ofp.OFPRR_HARD_TIMEOUT:  "HARD TIMEOUT",
            ofp.OFPRR_DELETE:        "DELETE",
            ofp.OFPRR_GROUP_DELETE:  "GROUP DEL"
        }.get(msg.reason, "UNKNOWN")

        if msg.priority == 2: #TODO: RICONTROLLARE 
            # Qui dovresti ricostruire la flow_key completa dal msg.match
            # # msg.match non sempre contiene src_port, dst_port, ip_proto
            ip_src = msg.match.get('ipv4_src')
            ip_dst = msg.match.get('ipv4_dst', None)
            ip_proto = msg.match.get('ip_proto', None)
            src_port = msg.match.get('src_port', None)
            dst_port = msg.match.get('dst_port', None)
            
            flow_key = (ip_src, ip_dst, src_port, dst_port, ip_proto) # Ricostruisci la chiave
            
            if ip_src: # Assicurati che almeno ip_src esista
                self.logger.info(f"[FLOW REMOVED][FLOW {flow_key}] Rule removed due to: {reason}") # Log con flow_key
                with self.blocked_flows_lock:
                    # Qui devi usare flow_key, non ip_src
                    if dp.id in self.blocked_flows and flow_key in self.blocked_flows[dp.id]:
                        if reason == "DELETE" or reason == "IDLE TIMEOUT" or reason == "HARD TIMEOUT":
                            self.logger.info(f"Cleaning up internal state for {flow_key} on DP {dp.id}.") # Log con flow_key
                            del self.blocked_flows[dp.id][flow_key]
                            with self.unblocked_flows_lock:
                                self.unblocked_flows[dp.id].pop(flow_key, None)

    def _check_and_unblock_traffic(self, datapath, flow_key, ip_proto):
        datapath_id = datapath.id

        unblock_window = self.unblock_thresholds.get(ip_proto, 5)

        while True:
            hub.sleep(self.sleep_time)
            #self.logger.info(f"         [UNBLOCK CHECK {datapath.id:016x}][IP {ip_src}][TYPE {ip_proto}] CONTROLLO SBLOCCO")

            flow_info = self.unblocked_flows.get(datapath_id, {}).get(flow_key)
            if not flow_info: #se il flusso è già stato sbloccato altrove
                return
            count = flow_info['count']

            #self.logger.info(f"         [UNBLOCK CHECK {datapath.id:016x}][IP {ip_src}][TYPE {ip_proto}] {count} verifiche positive.")

            if count >= unblock_window:
                self._unblock_flow(datapath, flow_key)
                with self.unblocked_flows_lock:
                    self.unblocked_flows[datapath_id].pop(flow_key, None)
                with self.blocked_flows_lock:
                    self.blocked_flows[datapath_id].pop(flow_key, None)
                return
            
    def _unblock_flow(self, datapath, flow_key, match_params = None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = None
        if match_params:
            match = self._build_match(parser, **match_params)
        else:
            with self.blocked_flows_lock:
                flow_info_blocked = self.blocked_flows.get(datapath.id, {}).get(flow_key)
                if flow_info_blocked and 'match' in flow_info_blocked:
                    match = flow_info_blocked['match']
            
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
        with self.blocked_flows_lock:
            if datapath.id in self.blocked_flows and flow_key in self.blocked_flows[datapath.id]:
                del self.blocked_flows[datapath.id][flow_key]
                self.logger.info(f"             [FLOW UNBLOCK {datapath.id:016x}][FLOW {flow_key}] Removed from blocked_flows dictionary.")

if __name__ == '__main__':
    manager.main()