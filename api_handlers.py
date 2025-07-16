import json
import time
import threading
import inspect

from webob import Response

from ryu.app.wsgi import ControllerBase, route 


# Mappa per i protocolli (può essere utile sia per il controller che per il dashboard)
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    None: "N/A" # In caso di protocollo non specificato nel match o non riconosciuto
}

# --- BlocklistApi ---
class BlocklistApi(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(BlocklistApi, self).__init__(req, link, data, **config)
        self.dps = data['dps']  # {dpid: datapath_object}
        # {dpid: {flow_key (tuple): {info_blocco}}}
        self.blocked_flows = data['blocked_flows']  
        self.enforcement_queue = data['enforcement_queue']
        self.blocked_flows_lock = data['blocked_flows_lock']
        self.logger = data['logger']  # Logger instance

    @route('blocklist', '/blocklist', methods=['POST'])
    def add_to_blocklist(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode('utf-8'))
            
            ip_src = body.get('ip_address') # Primary target
            ip_dst = body.get('ip_dst')     # Optional: Destination IP
            src_port = body.get('src_port') # Optional: Source Port (int)
            dst_port = body.get('dst_port') # Optional: Destination Port (int)
            ip_proto = body.get('ip_proto') # int (6 for TCP, 17 for UDP, etc.)
            
            dpid_str = body.get('dpid')     # Optional: specific Datapath ID as string (e.g., '0000000000000001')
            eth_src = body.get('eth_src')   # Optional: Source MAC
            in_port = body.get('in_port')   # Optional: Ingress Port (int)
            reason = body.get('reason', 'Manual block from Dashboard')

            if not ip_src:
                return Response(status=400, body=json.dumps({"error": "Missing 'ip_address' (source IP for block)."}), content_type='application/json; charset=utf-8')

            # Costruisci la flow_key completa. I valori None indicano "any" per quel campo.
            flow_key = (ip_src, ip_dst, src_port, dst_port, ip_proto)

            datapaths_to_block = []
            if dpid_str:
                # If a specific DPID is provided, try to find it
                try:
                    dpid = int(dpid_str, 16) # Convert hex string to int
                    if dpid in self.dps:
                        datapaths_to_block.append(self.dps[dpid])
                        self.logger.info(f"API Request: Blocking flow {flow_key} on specific DP {dpid_str}")
                    else:
                        return Response(status=404, body=json.dumps({"error": f"Datapath ID {dpid_str} not found."}), content_type='application/json; charset=utf-8')
                except ValueError:
                    return Response(status=400, body=json.dumps({"error": "Invalid Datapath ID format. Expected hexadecimal string."}), content_type='application/json; charset=utf-8')
            else:
                # If no specific DPID, block on all known datapaths
                datapaths_to_block = list(self.dps.values())
                self.logger.info(f"API Request: Blocking flow {flow_key} globally on all connected DPs.")

            if not datapaths_to_block:
                return Response(status=404, body=json.dumps({"error": "No datapaths found to apply block."}), content_type='application/json; charset=utf-8')

            blocked_datapaths_ids = []
            with self.blocked_flows_lock:
                for datapath in datapaths_to_block:
                    dpid = datapath.id
                    
                    # Store comprehensive match details based on the flow_key components
                    # and other optional parameters. These are the exact match criteria for the flow rule.
                    match_details = {'eth_type': 0x0800} # Assuming IPv4 traffic
                    if ip_src:
                        match_details['ipv4_src'] = ip_src
                    if ip_dst:
                        match_details['ipv4_dst'] = ip_dst
                    if ip_proto is not None: # Use is not None as 0 is a valid proto number sometimes
                        match_details['ip_proto'] = ip_proto
                    if src_port is not None:
                        # Assuming TCP/UDP, specific match field depends on ip_proto
                        if ip_proto == 6: # TCP
                            match_details['tcp_src'] = src_port
                        elif ip_proto == 17: # UDP
                            match_details['udp_src'] = src_port
                    if dst_port is not None:
                        if ip_proto == 6: # TCP
                            match_details['tcp_dst'] = dst_port
                        elif ip_proto == 17: # UDP
                            match_details['udp_dst'] = dst_port
                    if eth_src:
                        match_details['eth_src'] = eth_src
                    if in_port is not None:
                        match_details['in_port'] = in_port

                    # Usa la flow_key completa come chiave nel dizionario blocked_flows
                    self.blocked_flows.setdefault(dpid, {})[flow_key] = {
                        'blocked': True,
                        'admin_blocked': True, # Indica un blocco manuale/amministrativo
                        'time': time.time(),
                        'reason': reason,
                        'match_params': match_details, # Store the match parameters used for the flow rule
                        'flow_key': (ip_src, ip_dst, src_port, dst_port, ip_proto)
                    }
                    
                    self.enforcement_queue.put({
                        'type': 'block',
                        'datapath': datapath,
                        'match_params': match_details, # Pass the full match details for enforcement
                        'admin_override': True, # Flag per indicare un blocco amministrativo
                        'flow_key': (ip_src, ip_dst, src_port, dst_port, ip_proto)
                    })
                    self.logger.info(f"API Request: Enqueued block for flow {flow_key} (admin override, Match: {match_details}) on DP {dpid:016x}")
                    blocked_datapaths_ids.append(f'{dpid:016x}')

            return Response(status=200, body=json.dumps({"message": f"Flow {str(flow_key)} added to blocklist on datapaths: {', '.join(blocked_datapaths_ids)}"}), content_type='application/json; charset=utf-8')

        except json.JSONDecodeError:
            self.logger.error("Error decoding JSON body.", exc_info=True)
            return Response(status=400, body=json.dumps({"error": "Invalid JSON format."}), content_type='application/json; charset=utf-8')
        except Exception as e:
            self.logger.error(f"Error adding to blocklist: {e}", exc_info=True)
            return Response(status=500, body=json.dumps({"error": str(e)}), content_type='application/json; charset=utf-8')

    @route('blocklist', '/blocklist/{ip_address}', methods=['DELETE'])
    def remove_from_blocklist(self, req, ip_address, **kwargs):
        try:
            # Extract optional query parameters for specific unblock
            query_params = req.GET

            # Build a partial flow_key from query parameters to match what to unblock
            # Note: ip_address from path is always ip_src for removal logic here
            ip_src = ip_address 
            ip_dst = query_params.get('ip_dst')
            src_port = int(query_params['src_port']) if 'src_port' in query_params else None
            dst_port = int(query_params['dst_port']) if 'dst_port' in query_params else None
            ip_proto = int(query_params['ip_proto']) if 'ip_proto' in query_params else None

            # Construct the flow_key filter. None values act as wildcards.
            flow_key_filter = (ip_src, ip_dst, src_port, dst_port, ip_proto)
            
            # Specific DPID for unblock (optional)
            dpid_filter_str = query_params.get('dpid')
            dpid_filter = int(dpid_filter_str, 16) if dpid_filter_str else None

            if not ip_src: # Should not happen due to route parameter but good for robustness
                return Response(status=400, body=json.dumps({"error": "Missing 'ip_address' to remove."}), content_type='application/json; charset=utf-8')

            unblocked_datapaths = []
            flows_to_remove_from_state = [] # To store (dpid_int, flow_key_to_remove) pairs

            with self.blocked_flows_lock:
                for dpid_int, flows_on_dpid in list(self.blocked_flows.items()):
                    if dpid_filter is not None and dpid_int != dpid_filter:
                        continue # Skip if a specific DPID is filtered and it's not this one

                    # Iterate through all stored blocked flows for this DPID
                    for stored_flow_key, flow_info in list(flows_on_dpid.items()):
                        # Check if the stored flow_key matches the filter (allowing Nones as wildcards)
                        # stored_flow_key: (ip_src, ip_dst, src_port, dst_port, ip_proto)
                        # flow_key_filter: (ip_src_filter, ip_dst_filter, src_port_filter, dst_port_filter, ip_proto_filter)
                        match = True
                        for i in range(5): # Iterate over components of the flow_key tuple
                            if flow_key_filter[i] is not None and flow_key_filter[i] != stored_flow_key[i]:
                                match = False
                                break
                        
                        if match:
                            # Mark as unblocked in state (important for the RyuApp to act)
                            flow_info['admin_blocked'] = False
                            flow_info['blocked'] = False # This might be set to False by the detection system

                            # Enqueue unblock command with the exact match parameters that were used for blocking
                            self.enforcement_queue.put({
                                'type': 'unblock',
                                'datapath': self.dps.get(dpid_int),
                                'match_params': flow_info.get('match_params', {}), # Pass the exact stored match params
                                'flow_key': stored_flow_key # Useful for logging/tracking
                            })
                            self.logger.info(f"API Request: Enqueued unblock for flow {stored_flow_key} (admin override) on DP {dpid_int:016x}")
                            unblocked_datapaths.append(f'{dpid_int:016x}')
                            flows_to_remove_from_state.append((dpid_int, stored_flow_key)) # Mark for removal from dict

                # Remove the flows from the blocked_flows dictionary AFTER iterating to avoid RuntimeError
                for dpid_int, flow_key_to_remove in flows_to_remove_from_state:
                    if dpid_int in self.blocked_flows and flow_key_to_remove in self.blocked_flows[dpid_int]:
                        del self.blocked_flows[dpid_int][flow_key_to_remove]
                        if not self.blocked_flows[dpid_int]: # If no more blocked flows for this DP, remove DP entry
                            del self.blocked_flows[dpid_int]

            if not unblocked_datapaths:
                # Provide a more specific error message if a filter was used
                if dpid_filter or any(param is not None for param in flow_key_filter[1:]): # check if any component after ip_src is not None
                    return Response(status=404, body=json.dumps({"error": f"Specific blocked flow for IP {ip_address} with provided filters not found on any datapath."}), content_type='application/json; charset=utf-8')
                else:
                    return Response(status=404, body=json.dumps({"error": f"IP {ip_address} not found in blocklist (or no matching flow) on any datapath."}), content_type='application/json; charset=utf-8')

            return Response(status=200, body=json.dumps({"message": f"Flow(s) from IP {ip_address} removed from blocklist on datapaths: {', '.join(unblocked_datapaths)}"}), content_type='application/json; charset=utf-8')

        except ValueError as ve:
            self.logger.error(f"Error parsing unblock parameters: {ve}", exc_info=True)
            return Response(status=400, body=json.dumps({"error": f"Invalid parameter format: {str(ve)}. Check src_port, dst_port, ip_proto, dpid."}), content_type='application/json; charset=utf-8')
        except Exception as e:
            self.logger.error(f"Error removing from blocklist: {e}", exc_info=True)
            return Response(status=500, body=json.dumps({"error": str(e)}), content_type='application/json; charset=utf-8')

    @route('blocklist', '/blocklist/all', methods=['GET'])
    def get_blocklist_status(self, req, **kwargs):
        try:
            status = {}
            with self.blocked_flows_lock:
                for dpid_int, flows_on_dpid in self.blocked_flows.items():
                    dpid_str = f'{dpid_int:016x}'
                    status[dpid_str] = []
                    # Iterate through the actual flow_key in the stored data
                    for flow_key, info in flows_on_dpid.items():
                        # Only show flows that are currently marked as blocked (either by system or admin)
                        if info.get('blocked', False) or info.get('admin_blocked', False):
                            
                            # Extract components for easier display
                            ip_src, ip_dst, src_port, dst_port, ip_proto = flow_key
                            protocol_name = PROTO_MAP.get(ip_proto, 'N/A')
                            
                            status[dpid_str].append({
                                'flow_key': str(flow_key), # String representation of the tuple
                                'ip_src': ip_src,
                                'ip_dst': ip_dst,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'ip_proto': ip_proto,
                                'protocol_name': protocol_name,
                                'blocked': info.get('blocked', False),
                                'admin_blocked': info.get('admin_blocked', False),
                                'time': info.get('time', 'N/A'),
                                'reason': info.get('reason', 'N/A'),
                                'match_params': info.get('match_params', {}) # The exact match used for flow rule
                            })
            return Response(status=200, body=json.dumps(status), content_type='application/json; charset=utf-8')
        except Exception as e:
            self.logger.error(f"Error getting blocklist status: {e}", exc_info=True)
            return Response(status=500, body=json.dumps({"error": str(e)}), content_type='application/json; charset=utf-8')

# --- NetworkStatsApi ---
class NetworkStatsApi(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetworkStatsApi, self).__init__(req, link, data, **config)
        self.port_stats = data['port_stats'] # {dpid: {port_no: {...}}}
        self.port_stats_lock = data['port_stats_lock']
        # self.flow_stats: {datapath_id: {flow_key: {'timestamp': ..., 'byte_count': ..., 'packet_count': ..., 'last_bandwidth': ..., 'last_packet_rate': ..., 'ip_proto': ..., 'ip_dst': ..., 'src_port': ..., 'dst_port': ...}}}
        self.flow_stats = data['flow_stats'] 
        self.flow_stats_lock = data['flow_stats_lock']
        self.logger = data['logger']
        self.mac_to_ip = data['mac_to_ip'] # {dpid: {mac: {'ip_src': ..., 'in_port': ...}}}

    @route('net_stats', '/network/stats', methods=['GET'])
    def get_network_overview_stats(self, req, **kwargs):
        try:
            total_hosts = 0
            protocol_distribution = {}
            total_traffic_bps = 0.0 # Per la banda totale
            total_packet_rate_pps = 0.0 # Per il tasso di pacchetti totale

            # Conteggio degli host scoperti tramite mac_to_ip
            unique_ips = set()
            for dpid, mac_info in self.mac_to_ip.items():
                for mac, info in mac_info.items():
                    if 'ip_src' in info and info['ip_src'] != 'N/A':
                        unique_ips.add(info['ip_src'])
            total_hosts = len(unique_ips)

            # Calcolo della distribuzione dei protocolli e aggregazione del traffico
            with self.flow_stats_lock:
                for dpid, flows_on_dpid in self.flow_stats.items():
                    # flows_on_dpid è un dizionario con flow_key come chiave
                    for flow_key_tuple, stats in flows_on_dpid.items():
                        # flow_key_tuple è (ip_src, ip_dst, src_port, dst_port, ip_proto)
                        # Quindi, ip_proto è il quinto elemento della tupla
                        ip_proto = flow_key_tuple[4] # Get ip_proto from flow_key tuple

                        if ip_proto is not None:
                            proto_name = PROTO_MAP.get(ip_proto, 'Other')
                            protocol_distribution[proto_name] = protocol_distribution.get(proto_name, 0) + stats.get('packet_count', 0)
                        else:
                            protocol_distribution['Unknown/Other'] = protocol_distribution.get('Unknown/Other', 0) + stats.get('packet_count', 0)
                        
                        # Aggrega la banda e il packet rate per l'overview totale
                        total_traffic_bps += stats.get('last_bandwidth', 0.0) * 1_000_000 # Converti Mbps in bps
                        total_packet_rate_pps += stats.get('last_packet_rate', 0.0)

            # Se non ci sono flussi, inizializza con 0 per i protocolli comuni
            if not protocol_distribution:
                protocol_distribution = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

            return Response(status=200, body=json.dumps({
                "total_hosts": total_hosts,
                "protocol_distribution_packet_count": protocol_distribution,
                "total_network_traffic_bps": total_traffic_bps, # In bits per second
                "total_network_packet_rate_pps": total_packet_rate_pps # In packets per second
            }), content_type='application/json; charset=utf-8')
        except Exception as e:
            self.logger.error(f"Error getting network overview stats: {e}", exc_info=True)
            return Response(status=500, body=json.dumps({"error": str(e)}), content_type='application/json; charset=utf-8')

    @route('net_stats', '/stats/flows', methods=['GET'])
    def get_flow_stats(self, req, **kwargs):
        try:
            all_flow_stats = {}
            with self.flow_stats_lock:
                for dpid, flows_on_dpid in self.flow_stats.items():
                    dpid_str = f'{dpid:016x}'
                    all_flow_stats[dpid_str] = []
                    # flows_on_dpid è un dizionario con flow_key come chiave
                    for flow_key_tuple, stats in flows_on_dpid.items():
                        # Estrai i componenti della flow_key
                        ip_src, ip_dst, src_port, dst_port, ip_proto = flow_key_tuple
                        
                        protocol_name = PROTO_MAP.get(ip_proto, 'N/A')
                        
                        all_flow_stats[dpid_str].append({
                            'flow_key': str(flow_key_tuple), # Per facilitare la visualizzazione
                            'src_ip': ip_src,
                            'dst_ip': ip_dst,
                            'protocol_num': ip_proto,
                            'protocol_name': protocol_name,
                            'src_port': src_port, # Potrebbe essere None
                            'dst_port': dst_port, # Potrebbe essere None
                            'packet_count': stats.get('packet_count', 0),
                            'byte_count': stats.get('byte_count', 0),
                            'last_update_timestamp': stats.get('timestamp', 'N/A'),
                            'current_bandwidth_mbps': stats.get('last_bandwidth', 0.0),
                            'current_packet_rate_pps': stats.get('last_packet_rate', 0.0),
                        })
            return Response(status=200, body=json.dumps(all_flow_stats), content_type='application/json; charset=utf-8')
        except Exception as e:
            self.logger.error(f"Error getting flow stats: {e}", exc_info=True)
            return Response(status=500, body=json.dumps({"error": str(e)}), content_type='application/json; charset=utf-8')

# --- HostApi ---
class HostApi(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(HostApi, self).__init__(req, link, data, **config)
        self.mac_to_ip = data['mac_to_ip'] # {dpid: {mac: {'ip_src': ..., 'in_port': ...}}}
        self.port_stats = data['port_stats'] # {dpid: {port_no: {...}}}
        self.port_stats_lock = data['port_stats_lock']
        self.flow_stats = data['flow_stats'] # {datapath_id: {flow_key: {...}}} - flow_key = (ip_src, ip_dst, src_port, dst_port, ip_proto)
        self.flow_stats_lock = data['flow_stats_lock']
        self.blocked_flows = data['blocked_flows'] # {datapath_id: {flow_key: {...}}}
        self.blocked_flows_lock = data['blocked_flows_lock']
        self.logger = data['logger']

    @route('hosts', '/hosts/all', methods=['GET'])
    def get_all_hosts(self, req, **kwargs):
        try:
            hosts_info_list = []
            
            # Utilizziamo un set per tenere traccia degli IP già elaborati,
            # dato che un IP può apparire in più flow_keys o dpid.
            processed_ips = set() 

            # Prima passata per raccogliere informazioni base da mac_to_ip
            for dpid, mac_info_by_mac in self.mac_to_ip.items():
                dpid_str = f'{dpid:016x}'
                for mac, info in mac_info_by_mac.items():
                    ip_src = info.get('ip_src') # Questo è l'IP dell'host
                    if not ip_src or ip_src in processed_ips:
                        continue # Salta se non c'è IP o già elaborato

                    processed_ips.add(ip_src) # Aggiungi l'IP ai processati

                    in_port = info.get('in_port', 'N/A')
                    mac_address_str = ':'.join(f'{b:02x}' for b in mac) if isinstance(mac, bytes) else str(mac)

                    # Inizializza i totali per l'host per port_throughput e flow_rates
                    port_throughput = {'rx_bytes': 0.0, 'tx_bytes': 0.0, 'throughput_rx': 0.0, 'throughput_tx': 0.0,
                                       'throughput_total_bps': 0.0, 'rx_packets': 0.0, 'tx_packets': 0.0,
                                       'packet_rate_total_pps': 0.0, 'rx_errors': 0.0, 'tx_errors': 0.0}
                    
                    host_flow_rates = {'total_bandwidth_mbps': 0.0, 
                                       'total_packet_rate_pps': 0.0,
                                       'total_byte_count': 0.0,
                                       'total_packet_count': 0.0
                                      }

                    is_host_blocked = False

                    # Ottieni le statistiche della porta (se disponibili e pertinenti per l'host)
                    with self.port_stats_lock:
                        if dpid in self.port_stats and in_port != 'N/A' and in_port in self.port_stats[dpid]:
                            port_stats_for_host_port = self.port_stats[dpid][in_port]
                            port_throughput['rx_bytes'] = port_stats_for_host_port.get('rx_bytes', 0.0)
                            port_throughput['tx_bytes'] = port_stats_for_host_port.get('tx_bytes', 0.0)
                            port_throughput['throughput_rx'] = port_stats_for_host_port.get('throughput_rx', 0.0)
                            port_throughput['throughput_tx'] = port_stats_for_host_port.get('throughput_tx', 0.0)
                            port_throughput['throughput_total_bps'] = port_stats_for_host_port.get('total', 0.0)
                            port_throughput['rx_packets'] = port_stats_for_host_port.get('rx_packets', 0.0)
                            port_throughput['tx_packets'] = port_stats_for_host_port.get('tx_packets', 0.0)
                            port_throughput['packet_rate_total_pps'] = port_stats_for_host_port.get('packet_rate_total', 0.0)
                            port_throughput['rx_errors'] = port_stats_for_host_port.get('rx_errors', 0.0)
                            port_throughput['tx_errors'] = port_stats_for_host_port.get('tx_errors', 0.0)

                    # Aggrega le statistiche dei flussi per questo host (sia come src che dst)
                    with self.flow_stats_lock:
                        if dpid in self.flow_stats:
                            for flow_key_tuple, flow_info in self.flow_stats[dpid].items():
                                ip_src_flow, ip_dst_flow, src_port_flow, dst_port_flow, ip_proto_flow = flow_key_tuple
                                if ip_src_flow == ip_src or ip_dst_flow == ip_src: # Se l'host è sorgente o destinazione di un flusso
                                    host_flow_rates['total_bandwidth_mbps'] += flow_info.get('last_bandwidth', 0.0)
                                    host_flow_rates['total_packet_rate_pps'] += flow_info.get('last_packet_rate', 0.0)
                                    host_flow_rates['total_byte_count'] += flow_info.get('byte_count', 0.0)
                                    host_flow_rates['total_packet_count'] += flow_info.get('packet_count', 0.0)

                    # Controlla se l'host è bloccato (iterando su tutti i flussi bloccati che lo coinvolgono)
                    with self.blocked_flows_lock:
                        if dpid in self.blocked_flows:
                            for flow_key_blocked, blocked_info in self.blocked_flows[dpid].items():
                                ip_src_blocked, ip_dst_blocked, _, _, _ = flow_key_blocked
                                if (ip_src_blocked == ip_src or ip_dst_blocked == ip_src) and \
                                   (blocked_info.get('blocked', False) or blocked_info.get('admin_blocked', False)):
                                    is_host_blocked = True
                                    break # Basta un flusso bloccato per etichettare l'host come bloccato

                    hosts_info_list.append({
                        'dpid': dpid_str,
                        'mac': mac_address_str,
                        'ip': ip_src,
                        'port': in_port,
                        'current_port_throughput_bps': port_throughput['throughput_total_bps'],
                        'current_port_packet_rate_pps': port_throughput['packet_rate_total_pps'],
                        'current_host_total_bandwidth_mbps': host_flow_rates['total_bandwidth_mbps'], # Sum of all flows involving this host
                        'current_host_total_packet_rate_pps': host_flow_rates['total_packet_rate_pps'], # Sum of all flows involving this host
                        'is_blocked': is_host_blocked
                    })
            
            return Response(status=200, body=json.dumps(hosts_info_list), content_type='application/json; charset=utf-8')
        except Exception as e:
            self.logger.error(f"Error getting all hosts: {e}", exc_info=True)
            return Response(status=500, body=json.dumps({"error": str(e)}), content_type='application/json; charset=utf-8')

    @route('hosts', '/hosts/{ip_address}/details', methods=['GET'])
    def get_host_details(self, req, ip_address, **kwargs): # Changed 'flow_key' to 'ip_address'
        try:
            if not ip_address:
                return Response(status=400, body=json.dumps({"error": "Missing IP address"}), content_type='application/json; charset=utf-8')

            host_details = {}
            found_host_in_mac_table = False
            
            # Trova l'host nella tabella mac_to_ip per ottenere il dpid e la porta
            for dpid, mac_info_by_mac in self.mac_to_ip.items():
                for mac, info in mac_info_by_mac.items():
                    if info.get('ip_src') == ip_address:
                        found_host_in_mac_table = True
                        dpid_str = f'{dpid:016x}'
                        in_port = info.get('in_port', 'N/A')
                        mac_address_str = ':'.join(f'{b:02x}' for b in mac) if isinstance(mac, bytes) else str(mac)

                        host_details = {
                            'dpid': dpid_str,
                            'mac': mac_address_str,
                            'ip': ip_address,
                            'port': in_port,
                            'current_port_throughput_bps': 0.0,
                            'current_port_packet_rate_pps': 0.0,
                            'total_flow_bandwidth_mbps': 0.0, # Total aggregated bandwidth for this host
                            'total_flow_packet_rate_pps': 0.0, # Total aggregated packet rate for this host
                            'flows': [] # Lista per i dettagli dei singoli flussi
                        }

                        # Ottieni le statistiche della porta
                        with self.port_stats_lock:
                            if dpid in self.port_stats and in_port != 'N/A' and in_port in self.port_stats[dpid]:
                                port_stats_for_host_port = self.port_stats[dpid][in_port]
                                host_details['current_port_throughput_bps'] = port_stats_for_host_port.get('total', 0.0)
                                host_details['current_port_packet_rate_pps'] = port_stats_for_host_port.get('packet_rate_total', 0.0)

                        # Ottieni i dettagli di tutti i flussi che coinvolgono questo host
                        with self.flow_stats_lock:
                            if dpid in self.flow_stats:
                                for flow_key_tuple, flow_info in self.flow_stats[dpid].items():
                                    ip_src_flow, ip_dst_flow, src_port_flow, dst_port_flow, ip_proto_flow = flow_key_tuple
                                    
                                    if ip_src_flow == ip_address or ip_dst_flow == ip_address: # Se l'host è sorgente o destinazione
                                        protocol_name = PROTO_MAP.get(ip_proto_flow, f'Proto:{ip_proto_flow}')
                                        
                                        is_flow_blocked = False
                                        with self.blocked_flows_lock:
                                            if dpid in self.blocked_flows and flow_key_tuple in self.blocked_flows[dpid]:
                                                if self.blocked_flows[dpid][flow_key_tuple].get('blocked', False) or \
                                                   self.blocked_flows[dpid][flow_key_tuple].get('admin_blocked', False):
                                                    is_flow_blocked = True

                                        host_details['flows'].append({
                                            'flow_key': str(flow_key_tuple), # Converte la tupla in stringa per la visualizzazione JSON
                                            'src_ip': ip_src_flow,
                                            'dst_ip': ip_dst_flow,
                                            'protocol': protocol_name,
                                            'protocol_num': ip_proto_flow,
                                            'src_port': src_port_flow,
                                            'dst_port': dst_port_flow,
                                            'packets': flow_info.get('packet_count', 0),
                                            'bytes': flow_info.get('byte_count', 0),
                                            'last_update_timestamp': flow_info.get('timestamp', 'N/A'),
                                            'bandwidth_mbps': flow_info.get('last_bandwidth', 0.0),
                                            'packet_rate_pps': flow_info.get('last_packet_rate', 0.0),
                                            'is_blocked': is_flow_blocked
                                        })
                                        # Aggiorna i totali per l'host
                                        host_details['total_flow_bandwidth_mbps'] += flow_info.get('last_bandwidth', 0.0)
                                        host_details['total_flow_packet_rate_pps'] += flow_info.get('last_packet_rate', 0.0)
                        break # Ho trovato l'host e processato i suoi flussi, posso uscire dal loop esterno
            
            if not found_host_in_mac_table:
                return Response(status=404, body=json.dumps({"error": f"Host with IP {ip_address} not found"}), content_type='application/json; charset=utf-8')

            return Response(status=200, body=json.dumps(host_details), content_type='application/json; charset=utf-8')
        except Exception as e:
            self.logger.error(f"Error getting host details for {ip_address}: {e}", exc_info=True)
            return Response(status=500, body=json.dumps({"error": str(e)}), content_type='application/json; charset=utf-8')