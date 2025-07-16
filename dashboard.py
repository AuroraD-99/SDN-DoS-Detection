import streamlit as st
import requests
import time
import pandas as pd
import altair as alt
import json
import ast 
import urllib.parse

# Assuming Ryu controller is running on localhost:8080
RYU_API_BASE = "http://localhost:8080"

st.set_page_config(layout="wide", page_title="SDN DoS Mitigation Dashboard")

# Dictionary to map protocol numbers to names
PROTO_OPTIONS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    None: "N/A" # In caso di protocollo non specificato nel match o non riconosciuto
}

# --- Functions for interacting with the Ryu API ---
@st.cache_data(ttl=5) # Cache per le statistiche di rete che non cambiano istantaneamente
def get_network_stats():
    """
    Retrieves overall network statistics from the NetworkStatsApi endpoint.
    """
    try:
        response = requests.get(f"{RYU_API_BASE}/network/stats", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to Ryu Network Stats API. Is the controller running or is the endpoint available?")
        return {"total_hosts_discovered": "N/A", "protocol_distribution_packet_count": {}}
    except requests.exceptions.Timeout:
        st.error("Timeout: The controller did not respond in time when fetching network stats.")
        return {"total_hosts_discovered": "N/A", "protocol_distribution_packet_count": {}}
    except Exception as e:
        st.error(f"An unexpected error occurred while retrieving network stats: {e}")
        return {"total_hosts_discovered": "N/A", "protocol_distribution_packet_count": {}}

@st.cache_data(ttl=5) # Cache per i flussi che si aggiornano regolarmente
def get_all_flows():
    """
    Retrieves the list of all flows on the network from the controller.
    This function expects the /stats/flows endpoint to return a dict
    where keys are DPIDs and values are lists of flow dictionaries.
    """
    try:
        response = requests.get(f"{RYU_API_BASE}/stats/flows", timeout=10) # Aggiungi timeout
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to Ryu flows API. Is the controller running or is the endpoint available?")
        return {}
    except requests.exceptions.Timeout:
        st.error("Timeout: The controller did not respond in time when fetching flows.")
        return {}
    except Exception as e:
        st.error(f"An unexpected error occurred while retrieving flows: {e}")
        return {}

# @st.cache_data # Considera di usare la cache se i dati non cambiano troppo spesso o per sessione utente
def add_to_blocklist(payload):
    """
    Sends a request to the controller API to add a flow to the blocklist.
    Payload should match the expected structure of BlocklistApi POST.
    """
    controller_api_url = f"{RYU_API_BASE}/blocklist" 
    try:
        # L'API del controller si aspetta un payload JSON
        response = requests.post(controller_api_url, json=payload, timeout=5)
        response.raise_for_status() # Lancia un'eccezione per codici di stato HTTP errati (4xx o 5xx)
        st.success(response.json().get("message", "Flow blocked successfully!"))
        st.cache_data.clear() 
        return response.json()
    except requests.exceptions.Timeout:
        st.error("Error: The controller did not respond in time. Ensure it is running.")
        return {"error": "Controller timeout"}
    except requests.exceptions.RequestException as e:
        error_message = f"Error in API request to block flow: {e}"
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json().get('error', e.response.text)
                st.error(f"{error_message} Details: {error_details}")
                return {"error": error_details}
            except json.JSONDecodeError:
                st.error(f"{error_message} Raw response: {e.response.text}")
                return {"error": e.response.text}
        else:
            st.error(error_message)
            return {"error": str(e)}

def remove_from_blocklist(ip_src=None, ip_dst=None, src_port=None, dst_port=None, ip_proto=None, dpid=None):
    """
    Invia una richiesta DELETE all'API Ryu per rimuovere flussi dalla blocklist.
    L'IP sorgente è passato nel path, gli altri parametri come query string.
    
    :param ip_src: Indirizzo IP sorgente del flusso da sbloccare. (Obbligatorio per la chiamata API)
    :param ip_dst: Indirizzo IP di destinazione opzionale.
    :param src_port: Porta sorgente opzionale.
    :param dst_port: Porta di destinazione opzionale.
    :param ip_proto: Numero di protocollo IP opzionale (es. 6 per TCP, 17 per UDP).
    :param dpid: DataPath ID opzionale (in formato esadecimale stringa).
    """
    if not ip_src:
        # st.error is assumed to be defined if using Streamlit
        st.error("Errore: per sbloccare un flusso è necessario specificare un IP sorgente.")
        return {"status": "error", "message": "Missing ip_src for unblock operation."}

    # Build query string parameters
    query_params = {}
    if ip_dst: # Add if not None and not an empty string
        query_params['ip_dst'] = ip_dst
    
    # For ports, convert to int then str, ensuring it's not None
    if src_port is not None:
        try:
            query_params['src_port'] = str(int(src_port))
        except (ValueError, TypeError):
            st.warning(f"Porta sorgente non valida: {src_port}. Ignorata.")
    if dst_port is not None:
        try:
            query_params['dst_port'] = str(int(dst_port))
        except (ValueError, TypeError):
            st.warning(f"Porta destinazione non valida: {dst_port}. Ignorata.")
    
    if ip_proto is not None:
        try:
            query_params['ip_proto'] = str(int(ip_proto)) # Ensure it's an integer
        except (ValueError, TypeError):
            st.warning(f"Protocollo IP non valido: {ip_proto}. Ignorato.")
    
    if dpid: # Add if not None and not an empty string
        query_params['dpid'] = dpid # DPID should already be a hex string

    # Construct the final URL
    base_url = f"{RYU_API_BASE}/blocklist/{ip_src}"
    if query_params:
        query_string = urllib.parse.urlencode(query_params)
        full_url = f"{base_url}?{query_string}"
    else:
        full_url = base_url # This is the case causing you trouble

    # Add this line for debugging
    st.info(f"Invio richiesta DELETE a: {full_url}") 
    try:
        response = requests.delete(full_url, timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        
        response_data = response.json()
        st.success(f"Richiesta di sblocco inviata: {response_data.get('message', 'Operazione completata con successo.')}")
        # Assuming st.cache_data.clear() is relevant for Streamlit caching
        # st.cache_data.clear() 
        return response_data
    except requests.exceptions.HTTPError as http_err:
        error_msg = f"Errore HTTP durante lo sblocco: {http_err.response.status_code} - {http_err.response.text}"
        st.error(error_msg)
        return {"status": "error", "message": error_msg}
    except requests.exceptions.ConnectionError as conn_err:
        st.error(f"Errore di connessione all'API Ryu: {conn_err}. Assicurati che il controller sia in esecuzione.")
        return {"status": "error", "message": str(conn_err)}
    except requests.exceptions.Timeout as timeout_err:
        st.error(f"Timeout della richiesta API Ryu: {timeout_err}. Il controller potrebbe essere lento a rispondere.")
        return {"status": "error", "message": str(timeout_err)}
    except requests.exceptions.RequestException as e:
        st.error(f"Errore generico durante l'invio della richiesta di sblocco: {e}")
        return {"status": "error", "message": str(e)}

@st.cache_data(ttl=5) # Puoi aggiungere una cache con TTL breve per aggiornamenti rapidi
def get_blocklist_status():
    """
    Retrieves the current status of the blocklist from the controller.
    """
    controller_api_url = f"{RYU_API_BASE}/blocklist/all"
    try:
        response = requests.get(controller_api_url, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        st.error("Error: The controller did not respond in time to get the blocklist. Ensure it is running.")
        return {}
    except requests.exceptions.RequestException as e:
        error_message = f"Error in API request to get blocklist: {e}"
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json().get('error', e.response.text)
                st.error(f"{error_message} Details: {error_details}")
                return {}
            except json.JSONDecodeError:
                st.error(f"{error_message} Raw response: {e.response.text}")
                return {}
        else:
            st.error(error_message)
            return {}

def get_flow_details(src_ip, dst_ip=None, protocol_num=None): 
    """
    Retrieves details for a specific flow.
    NOTE: L'API del controller non ha un endpoint specifico per 'flow details' come per 'host details'.
    Dobbiamo estrarre i dettagli dai dati di 'get_all_flows'.
    """
    all_flows_raw = get_all_flows()
    found_flow_details = []

    for dpid, flows_on_dpid in all_flows_raw.items():
        for flow in flows_on_dpid:
            # Check for source IP match
            if flow.get('src_ip') == src_ip:
                # Optional: Filter by destination IP if provided
                if dst_ip and flow.get('dst_ip') != dst_ip:
                    continue
                # Optional: Filter by protocol if provided
                if protocol_num is not None and flow.get('protocol_num') != protocol_num:
                    continue

                found_flow_details.append(flow)

    return found_flow_details if found_flow_details else None

def get_host_details(ip_address):
    try:
        response = requests.get(f"{RYU_API_BASE}/hosts/{ip_address}/details", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Errore durante il recupero dei dettagli per l'host {ip_address}: {e}")
        return None

# --- Functions for Dashboard Sections ---
def show_network_stats_section():
    """Shows current network statistics."""
    st.header("Statistiche Attuali della Rete 📊")

    stats = get_network_stats()

    st.subheader("Riepilogo Generale")
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Numero Totale di Host Rilevati:** {stats.get('total_hosts', 'N/A')}")
    with col2:
        if st.button("Visualizza Dettagli Flussi e Host"):
            st.session_state['current_page'] = "Flow Details"
            st.session_state['selected_flow_src_ip'] = None # Resetta la selezione precedente
            st.session_state['rerun_triggered'] = True
            st.rerun()
    st.info(f"**Traffico Totale di Rete:** {stats.get('total_network_traffic_bps', 0.0):.2f} bps")
    st.info(f"**Tasso di Pacchetti Totale di Rete:** {stats.get('total_network_packet_rate_pps', 0.0):.2f} pps")

    st.subheader("Distribuzione del Traffico per Protocollo")
    protocol_dist = stats.get('protocol_distribution_packet_count', {})

    if protocol_dist:
        df_protocol_dist = pd.DataFrame(list(protocol_dist.items()), columns=['Protocol', 'Packet Count'])
        df_protocol_dist = df_protocol_dist.sort_values(by='Packet Count', ascending=False)

        chart_protocol_dist = alt.Chart(df_protocol_dist).mark_bar().encode(
            x=alt.X('Protocol', axis=alt.Axis(title='Protocollo')),
            y=alt.Y('Packet Count', axis=alt.Axis(title='Conteggio Pacchetti')),
            tooltip=['Protocol', 'Packet Count']
        ).properties(
            title='Distribuzione del Traffico per Protocollo'
        )
        st.altair_chart(chart_protocol_dist, use_container_width=True)
    else:
        st.info("Nessuna statistica di protocollo disponibile al momento.")

def show_block_flow_section(): 
    """Shows the section for manually blocking a flow with detailed options."""
    st.header("Block a Flow Manually 🚫")

    all_flows_data = get_all_flows()
    unique_ips = set()
    unique_dpids = set() 
    
    # Processa i dati dei flussi per popolare le opzioni dei selectbox
    for dpid, flows_list in all_flows_data.items():
        unique_dpids.add(dpid) 
        if isinstance(flows_list, list):
            for flow in flows_list:
                # Assicurati di usare 'src_ip' e 'dst_ip' come chiavi nel dizionario del flusso
                if flow.get('src_ip') and flow.get('src_ip') != 'N/A':
                    unique_ips.add(flow['src_ip'])
                if flow.get('dst_ip') and flow.get('dst_ip') != 'N/A':
                    unique_ips.add(flow['dst_ip'])

    sorted_ips = sorted(list(unique_ips))
    sorted_dpids = sorted(list(unique_dpids)) 

    with st.form("block_flow_form"):
        st.subheader("Flow Matching Criteria:")

        col1, col2 = st.columns(2)
        with col1:
            block_ip_src = st.selectbox(
                "Source IP Address (Required)",
                options=[""] + sorted_ips,
                help="Select a source IP address from detected flows or type a new one.",
                key="block_ip_src_select_form" 
            )
            block_ip_dst = st.text_input(
                "Destination IP Address (Optional)",
                value="", 
                help="Enter a specific destination IP address to block.",
                key="block_ip_dst_input_form" 
            )
            block_src_port = st.text_input(
                "Source Port (Optional)",
                value="", 
                help="Enter a specific source port.",
                key="block_src_port_input_form" 
            )
            block_dst_port = st.text_input(
                "Destination Port (Optional)",
                value="", 
                help="Enter a specific destination port.",
                key="block_dst_port_input_form" 
            )
        with col2:
            block_dpid = st.selectbox(
                "Datapath ID (Optional)",
                options=[""] + sorted_dpids,
                help="Select a specific Datapath ID to apply the block. If empty, block on all connected datapaths.",
                key="block_dpid_select_form" 
            )
            
            # Qui usiamo le chiavi di PROTO_MAP per la selezione, inclusa "Any"
            block_proto_selection_keys = list(PROTO_OPTIONS.keys())
            block_ip_proto_display = st.selectbox(
                "Protocol (Optional)",
                options=block_proto_selection_keys,
                format_func=lambda x: PROTO_OPTIONS.get(x, str(x)), # Usa PROTO_MAP per il display
                help="Select the protocol (TCP, UDP, ICMP, etc.). 'Any' blocks all protocols for the given IPs.",
                key="block_proto_select_form" 
            )

        st.markdown("---")
        st.subheader("Advanced Matching (Optional):")
        col5, col6 = st.columns(2)
        with col5:
            block_eth_src = st.text_input(
                "Source MAC Address (Optional)",
                value="", 
                help="Enter a specific source MAC address.",
                key="block_eth_src_input_form" 
            )
        with col6:
            block_in_port = st.text_input(
                "Ingress Port (Optional)",
                value="", 
                help="Enter a specific ingress port number on the datapath.",
                key="block_in_port_input_form" 
            )

        submitted = st.form_submit_button("Block Flow")
        if submitted:
            if not block_ip_src:
                st.warning("Please specify a **Source IP Address** to block.")
            else:
                payload = {
                    "ip_address": block_ip_src, # Corrisponde a ipv4_src nel payload
                    "reason": "Manual block from dashboard"
                }

                if block_ip_dst:
                    payload["ip_dst"] = block_ip_dst
                
                if block_src_port:
                    try:
                        payload["src_port"] = int(block_src_port)
                    except ValueError:
                        st.error("Source Port must be a valid integer.")
                        return
                
                if block_dst_port:
                    try:
                        payload["dst_port"] = int(block_dst_port)
                    except ValueError:
                        st.error("Destination Port must be a valid integer.")
                        return

                # Converti il protocollo selezionato nel suo valore numerico se non è "Any"
                if block_ip_proto_display != "Any":
                    # Trova la chiave numerica corrispondente al valore di visualizzazione
                    # Questo è necessario perché PROTO_MAP ha numeri come chiavi e nomi come valori
                    # st.selectbox restituisce la CHIAVE del dizionario `options`
                    numeric_proto = PROTO_OPTIONS.get(block_ip_proto_display)
                    if numeric_proto is not None:
                        payload["ip_proto"] = numeric_proto
                    else:
                        st.error(f"Unknown protocol: {block_ip_proto_display}")
                        return
                    
                if block_dpid:
                    payload["dpid"] = block_dpid 
                if block_eth_src:
                    payload["eth_src"] = block_eth_src
                
                if block_in_port:
                    try:
                        payload["in_port"] = int(block_in_port)
                    except ValueError:
                        st.error("Ingress Port must be a valid integer.")
                        return
                
                st.json(payload) 
                add_to_blocklist(payload)
                # Non è necessario un time.sleep lungo, rerun è sufficiente
                st.rerun() 

def show_blocked_flows_list_section():
    """Shows the current list of blocked flows with additional info and unblock buttons."""
    st.header("Flussi Attualmente Bloccati 🛡️",
              help="Questa lista mostra tutti i flussi che sono stati bloccati, sia manualmente (Bloccati da Amministratore) che automaticamente dal sistema (Bloccati Dinamicamente). "
                   "Vengono mostrati i dettagli dei criteri di match esatti per ogni flusso bloccato.")

    blocklist_data_raw = get_blocklist_status()

    display_data = []
    blocked_ips_for_unblock_all_buttons = set() # Usiamo un set per gli IP sorgente bloccati per evitare duplicati

    if not blocklist_data_raw:
        st.info("Nessun flusso bloccato al momento.")
        return

    for dp_id, flows_list in blocklist_data_raw.items():
        if isinstance(flows_list, list):
            for flow_info in flows_list:
                flow_key_str = flow_info.get('flow_key', "('', '', None, None, None)")
                try:
                    flow_key_tuple = ast.literal_eval(flow_key_str)
                    ip_src = flow_key_tuple[0]
                    ip_dst = flow_key_tuple[1]
                    src_port = flow_key_tuple[2]
                    dst_port = flow_key_tuple[3]
                    ip_proto_num = flow_key_tuple[4]

                    protocol_name = PROTO_OPTIONS.get(ip_proto_num, 'Sconosciuto')

                except (ValueError, SyntaxError) as e:
                    st.warning(f"Impossibile analizzare flow_key '{flow_key_str}': {e}. Questo flusso verrà saltato.")
                    continue

                match_params = flow_info.get('match_params', {})

                # Costruiamo la stringa dei dettagli di match in modo più esaustivo
                match_details_str_parts = []
                if 'eth_type' in match_params:
                    match_details_str_parts.append(f"Eth Type: {hex(match_params['eth_type'])}")
                if 'ipv4_src' in match_params:
                    match_details_str_parts.append(f"Src IP: {match_params['ipv4_src']}")
                if 'ipv4_dst' in match_params:
                    match_details_str_parts.append(f"Dst IP: {match_params['ipv4_dst']}")
                if 'ip_proto' in match_params:
                    proto_display_name = PROTO_OPTIONS.get(match_params['ip_proto'], f"Unknown ({match_params['ip_proto']})")
                    match_details_str_parts.append(f"Proto: {proto_display_name}")
                if 'tcp_src' in match_params:
                    match_details_str_parts.append(f"TCP Src Port: {match_params['tcp_src']}")
                if 'tcp_dst' in match_params:
                    match_details_str_parts.append(f"TCP Dst Port: {match_params['tcp_dst']}")
                if 'udp_src' in match_params:
                    match_details_str_parts.append(f"UDP Src Port: {match_params['udp_src']}")
                if 'udp_dst' in match_params:
                    match_details_str_parts.append(f"UDP Dst Port: {match_params['udp_dst']}")
                if 'in_port' in match_params:
                    match_details_str_parts.append(f"In Port: {match_params['in_port']}")
                if 'eth_src' in match_params:
                    match_details_str_parts.append(f"Src MAC: {match_params['eth_src']}")
                if 'eth_dst' in match_params:
                    match_details_str_parts.append(f"Dst MAC: {match_params['eth_dst']}")

                # Aggiungiamo eventuali altri campi direttamente dal match_params che non sono stati gestiti esplicitamente
                for k, v in match_params.items():
                    if k not in ['eth_type', 'ipv4_src', 'ipv4_dst', 'ip_proto',
                                 'tcp_src', 'tcp_dst', 'udp_src', 'udp_dst',
                                 'in_port', 'eth_src', 'eth_dst', 'priority', 'idle_timeout', 'hard_timeout', 'cookie']:
                        match_details_str_parts.append(f"{k.replace('_', ' ').title()}: {v}")

                match_details_display = ", ".join(sorted(match_details_str_parts)) if match_details_str_parts else "Nessuno (Blocco Generico)"

                display_data.append({
                    "Datapath ID": dp_id,
                    "Source IP": ip_src if ip_src else "Qualsiasi",
                    "Destination IP": ip_dst if ip_dst else "Qualsiasi",
                    "Source Port": src_port if src_port is not None else "Qualsiasi",
                    "Destination Port": dst_port if dst_port is not None else "Qualsiasi",
                    "Protocol": protocol_name,
                    "Block Status": "Bloccato da Amministratore" if flow_info.get('admin_blocked', False) else "Bloccato Dinamicamente",
                    "Match Details": match_details_display,
                    "Ultimo Aggiornamento": time.ctime(flow_info.get('time', 0)) if flow_info.get('time') else 'N/A',
                    "unblock_params": {
                        "ip_src": ip_src,
                        "ip_dst": ip_dst,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "ip_proto": ip_proto_num,
                        "dpid": dp_id
                    }
                })
                if ip_src:
                    blocked_ips_for_unblock_all_buttons.add(ip_src)

        else:
            st.warning(f"Formato dati inatteso per DPID {dp_id}: {type(flows_list)}. Prevista una lista.")

    if display_data:
        df = pd.DataFrame(display_data)

        df['Datapath ID Num'] = df['Datapath ID'].apply(lambda x: int(x, 16) if x and x.strip() else 0)
        df = df.sort_values(by=['Datapath ID Num', 'Source IP']).drop(columns=['Datapath ID Num'])

        st.subheader("Tabella Flussi Attualmente Bloccati")
        
        display_columns = [
            "Datapath ID", "Source IP", "Destination IP", "Source Port",
            "Destination Port", "Protocol", "Block Status", "Match Details",
            "Ultimo Aggiornamento", "Action"
        ]
        column_widths = [0.8, 1, 1, 0.7, 0.7, 0.7, 1, 2, 1.2, 0.8]

        cols_header = st.columns(column_widths)
        for col_idx, header_name in enumerate(display_columns):
            with cols_header[col_idx]:
                st.markdown(f"**{header_name}**")
        st.markdown("---")

        for idx, row in df.iterrows():
            cols = st.columns(column_widths)
            with cols[0]: st.write(row["Datapath ID"])
            with cols[1]: st.write(row["Source IP"])
            with cols[2]: st.write(row["Destination IP"])
            with cols[3]: st.write(row["Source Port"])
            with cols[4]: st.write(row["Destination Port"])
            with cols[5]: st.write(row["Protocol"])
            with cols[6]: st.write(row["Block Status"])
            with cols[7]: st.markdown(f'<div style="word-wrap: break-word;">{row["Match Details"]}</div>', unsafe_allow_html=True)
            with cols[8]: st.write(row["Ultimo Aggiornamento"])
            with cols[9]:
                if st.button("Sblocca", key=f"unblock_single_{row['Source IP']}_{row['Datapath ID']}_{idx}"):
                    params_to_unblock = row['unblock_params']
                    # Filtra None per non passare parametri non specifici
                    filtered_params = {k: v for k, v in params_to_unblock.items() if v is not None}
                    remove_from_blocklist(**filtered_params)
                    st.rerun()

        st.markdown("---")
        st.subheader("Azioni di Sblocco Globali")

        blocked_ips_for_buttons = sorted(list(blocked_ips_for_unblock_all_buttons))

        if blocked_ips_for_buttons:
            st.write("**Sblocca tutti i flussi per specifici IP Sorgente (globalmente su tutti i datapath e match per quell'IP):**")
            num_cols_unblock_ip = min(len(blocked_ips_for_buttons), 5)
            cols_unblock_ip_container = st.columns(num_cols_unblock_ip)

            for i, ip in enumerate(blocked_ips_for_buttons):
                with cols_unblock_ip_container[i % num_cols_unblock_ip]:
                    if st.button(f"Sblocca Tutto per {ip}", key=f"unblock_ip_{ip}"):
                        remove_from_blocklist(ip_src=ip)
                        st.rerun()
        else:
            st.info("Nessun IP attualmente disponibile per lo sblocco per IP.")

        st.markdown("---")
        st.write("**Sblocca tutti i flussi bloccati (Complessivamente):**")
        if 'last_unblock_all_time' not in st.session_state:
            st.session_state['last_unblock_all_time'] = 0

        if st.button("Sblocca Tutti i Flussi Bloccati", key="unblock_all_flows_overall"):
            if st.session_state['last_unblock_all_time'] < time.time() - 2:
                current_blocked_ips = set()
                re_fetched_blocklist = get_blocklist_status()
                for dp_id, flows_list in re_fetched_blocklist.items():
                    if isinstance(flows_list, list):
                        for flow_info in flows_list:
                            flow_key_str = flow_info.get('flow_key', "('', '', None, None, None)")
                            try:
                                flow_key_tuple = ast.literal_eval(flow_key_str)
                                if flow_key_tuple[0]:
                                    current_blocked_ips.add(flow_key_tuple[0])
                            except (ValueError, SyntaxError):
                                continue

                if current_blocked_ips:
                    for ip_to_unblock in current_blocked_ips:
                        remove_from_blocklist(ip_src=ip_to_unblock)
                    st.session_state['last_unblock_all_time'] = time.time()
                    st.success("Tutte le regole di blocco sono state inviate per la rimozione.")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.info("Non ci sono flussi attivi da sbloccare.")
            else:
                st.warning("Per favore, attendi un momento prima di provare a sbloccare tutti i flussi di nuovo.")

    else:
        st.info("Nessun flusso bloccato al momento.")

def show_all_flows_section(): 
    """Shows the list of all flows in the network and allows viewing details."""
    st.header("List of All Network Flows 🌐")

    all_flows_data_raw = get_all_flows()

    if not all_flows_data_raw:
        st.warning("No flows found in the network or error retrieving flows. Ensure Ryu is running and flow statistics are being collected.")
        return

    flat_flows_list = []
    # all_flows_data_raw è un dict {dpid: [flow_info_dict, ...]}
    for dpid, flows_list_for_dpid in all_flows_data_raw.items():
        if isinstance(flows_list_for_dpid, list):
            for flow_info in flows_list_for_dpid:
                flow_info_copy = flow_info.copy()
                flow_info_copy['dpid'] = dpid # Aggiungi il DPID al dizionario del flusso
                
                proto_num = flow_info_copy.get('protocol_num')
                flow_info_copy['protocol_name'] = PROTO_OPTIONS.get(proto_num, 'N/A')
                flat_flows_list.append(flow_info_copy)
        else:
            st.warning(f"Unexpected data format for DPID {dpid}. Expected a list of flows, got {type(flows_list_for_dpid)}.")


    if not flat_flows_list:
        st.info("No detailed flow data available.")
        return

    df_flows = pd.DataFrame(flat_flows_list)

    display_columns = [
        "dpid", "src_ip", "dst_ip", "protocol_name",
        "src_port", "dst_port", "packet_count", "byte_count",
        "current_bandwidth_mbps", "current_packet_rate_pps",
        "last_update_timestamp"
    ]
    df_flows_display = df_flows[df_flows.columns.intersection(display_columns)]

    st.subheader("All Active Flows Table")

    # Headers della tabella
    # Aggiusta le larghezze per includere il bottone di blocco
    #TODO: AGGIUNGERE UN FILTRO PER FILTRARE LA TABELLA IN BASE ALL'IP
    cols_header = st.columns([0.7, 1, 1, 0.8, 0.7, 0.7, 1.2, 1.2, 1.2, 0.5])
    headers = ["DPID", "Source IP", "Dest. IP", "Proto", "Src Port", "Dst Port",
               "Packets", "Bytes", "Bandwidth (Mbps)", "Block"]
    for col_idx, header_name in enumerate(headers):
        with cols_header[col_idx]:
            st.markdown(f"**{header_name}**")
    st.markdown("---") # Linea separatrice

    for idx, row in df_flows_display.iterrows():
        cols = st.columns([0.7, 1, 1, 0.8, 0.7, 0.7, 1.2, 1.2, 1.2, 0.5])
        with cols[0]: st.write(row.get("dpid", "N/A"))
        with cols[1]: st.write(row.get("src_ip", "N/A"))
        with cols[2]: st.write(row.get("dst_ip", "N/A"))
        with cols[3]: st.write(row.get("protocol_name", "N/A"))
        with cols[4]: st.write(row.get("src_port", "N/A"))
        with cols[5]: st.write(row.get("dst_port", "N/A"))
        with cols[6]: st.write(row.get("packet_count", "N/A"))
        with cols[7]: st.write(row.get("byte_count", "N/A"))
        with cols[8]: st.write(f"{row.get('current_bandwidth_mbps', 0.0):.2f}") # Formatta la banda
        with cols[9]:
            # Bottone di blocco per il Source IP di questo flusso
            # Assicurati che l'IP sorgente esista prima di mostrare il bottone
            if row.get("src_ip") and row.get("src_ip") != 'N/A':
                # Costruisci il payload per il blocco con i campi corretti per l'API
                block_payload = {
                    "ip_address": row.get("src_ip"), # Il campo principale per l'identificazione
                    "reason": "Block from all flows table"
                }
                # Aggiungi gli altri campi solo se presenti e validi
                if row.get("dst_ip") and row.get("dst_ip") != 'N/A':
                    block_payload["ipv4_dst"] = row.get("dst_ip") # Usa 'ipv4_dst'
                if row.get("protocol_num") is not None:
                    block_payload["ip_proto"] = row.get("protocol_num")
                if row.get("src_port") is not None and row.get("src_port") != 'N/A':
                    block_payload["src_port"] = row.get("src_port")
                if row.get("dst_port") is not None and row.get("dst_port") != 'N/A':
                    block_payload["dst_port"] = row.get("dst_port")
                if row.get("dpid") and row.get("dpid") != 'N/A':
                    block_payload["dpid"] = row.get("dpid")

                if st.button("Block", key=f"block_flow_from_list_{row['src_ip']}_{idx}"):
                    result = add_to_blocklist(block_payload)
                    st.rerun()
            else:
                st.write("-") # O un messaggio di non disponibile

def show_flow_details_panel(): # Non prende più ip_address come parametro diretto
    """Shows details for flows originating from or destined to a specific IP, and host details."""
    st.subheader("Dettagli Flussi e Host 🔍")

    # Bottone per tornare alla sezione delle statistiche di rete
    if st.button("Torna alle Statistiche di Rete"):
        st.session_state['current_page'] = "Network Stats"
        st.session_state['selected_flow_src_ip'] = None # Deseleziona IP
        st.session_state['rerun_triggered'] = True
        st.rerun()

    st.markdown("---") # Separatore

    all_flows_data_raw = get_all_flows()

    if not all_flows_data_raw:
        st.warning("Nessun flusso trovato nella rete o errore durante il recupero dei flussi. Assicurati che Ryu sia in esecuzione e che le statistiche dei flussi vengano raccolte.")
        return

    flat_flows_list = []
    for dpid, flows_list_for_dpid in all_flows_data_raw.items():
        if isinstance(flows_list_for_dpid, list):
            for flow_info in flows_list_for_dpid:
                flow_info_copy = flow_info.copy()
                flow_info_copy['dpid'] = dpid # Aggiungi il DPID al dizionario del flusso

                proto_num = flow_info_copy.get('protocol_num')
                # Assicurati che PROTO_OPTIONS sia accessibile qui (importato o passato)
                flow_info_copy['protocol_name'] = PROTO_OPTIONS.get(proto_num, 'Sconosciuto')
                flat_flows_list.append(flow_info_copy)
        else:
            st.warning(f"Formato dati inatteso per DPID {dpid}. Prevista una lista di flussi, ottenuto {type(flows_list_for_dpid)}.")

    if not flat_flows_list:
        st.info("Nessun dato dettagliato sui flussi disponibile.")
        return

    df_flows = pd.DataFrame(flat_flows_list)

    # Identifica tutti gli IP unici presenti nei flussi (sorgente o destinazione)
    unique_ips_from_flows = sorted(pd.concat([df_flows['src_ip'], df_flows['dst_ip']]).unique().tolist())

    # Seleziona un IP dalla lista, con l'opzione di preselezione se un IP è già stato scelto
    if 'selected_flow_src_ip' not in st.session_state:
        st.session_state['selected_flow_src_ip'] = None # Inizializza se non esiste

    selected_ip_for_details = st.selectbox(
        "Seleziona un Indirizzo IP per Visualizzare Flussi Associati e Dettagli Host",
        options=[""] + unique_ips_from_flows,
        index=unique_ips_from_flows.index(st.session_state['selected_flow_src_ip']) + 1 if st.session_state['selected_flow_src_ip'] in unique_ips_from_flows else 0,
        help="Seleziona un indirizzo IP per vedere tutti i flussi che originano o sono destinati ad esso, insieme ai dettagli dell'host."
    )

    # Aggiorna session_state solo se l'utente ha fatto una nuova selezione
    if selected_ip_for_details and selected_ip_for_details != st.session_state['selected_flow_src_ip']:
        st.session_state['selected_flow_src_ip'] = selected_ip_for_details
        # Non serve rerun qui, la selezione diretta aggiorna già il widget

    # Ora il resto della logica si basa su `selected_ip_for_details`
    if selected_ip_for_details:
        ip_address = selected_ip_for_details # Usa l'IP selezionato come riferimento
        st.subheader(f"Dettagli per Host e Flussi Associati: {ip_address}")

        # Ottieni i dettagli dell'host dall'API
        host_details_from_api = get_host_details(ip_address)

        if host_details_from_api:
            st.subheader("Informazioni Host")
            st.write(f"**DPID:** {host_details_from_api.get('dpid', 'N/A')}")
            st.write(f"**Indirizzo MAC:** {host_details_from_api.get('mac', 'N/A')}")
            st.write(f"**Porta Associata:** {host_details_from_api.get('port', 'N/A')}")
            st.write(f"**Throughput Totale Corrente (Porta):** {host_details_from_api.get('current_port_throughput_bps', 0.0):.2f} bps")
            st.write(f"**Tasso di Pacchetti Totale Corrente (Porta):** {host_details_from_api.get('current_port_packet_rate_pps', 0.0):.2f} pps")
            st.write(f"**Banda Totale Corrente Flusso (Host):** {host_details_from_api.get('total_flow_bandwidth_mbps', 0.0):.2f} Mbps")
            st.write(f"**Tasso di Pacchetti Totale Corrente Flusso (Host):** {host_details_from_api.get('total_flow_packet_rate_pps', 0.0):.2f} pps")
            st.write(f"**È Bloccato (Host):** {'Sì' if host_details_from_api.get('is_blocked', False) else 'No'}")

            flows_for_ip = host_details_from_api.get('flows', [])

            if flows_for_ip:
                df_selected_flows = pd.DataFrame(flows_for_ip)
                # 'protocol' è già il nome del protocollo in HostApi, non 'protocol_num'
                if 'protocol' in df_selected_flows.columns:
                    df_selected_flows.rename(columns={'protocol': 'protocol_name'}, inplace=True)
                elif 'protocol_name' not in df_selected_flows.columns and 'protocol_num' in df_selected_flows.columns:
                    df_selected_flows['protocol_name'] = df_selected_flows['protocol_num'].apply(lambda x: PROTO_OPTIONS.get(x, 'Sconosciuto'))

                flow_detail_columns = [
                    "src_ip", "dst_ip", "protocol_name",
                    "src_port", "dst_port", "packets", "bytes",
                    "bandwidth_mbps", "packet_rate_pps",
                    "last_update_timestamp", "is_blocked"
                ]
                df_selected_flows_display = df_selected_flows[df_selected_flows.columns.intersection(flow_detail_columns)]

                st.subheader("Flussi Associati")
                st.dataframe(df_selected_flows_display, use_container_width=True, hide_index=True)

                st.markdown("---")
                st.subheader("Analisi del Traffico per Questi Flussi")

                if not df_selected_flows.empty:
                    protocol_flow_counts = df_selected_flows.groupby('protocol_name')['packets'].sum().reset_index()
                    protocol_flow_counts.columns = ['Protocol', 'Packet Count']

                    chart_packets = alt.Chart(protocol_flow_counts).mark_bar().encode(
                        x=alt.X('Protocol', axis=alt.Axis(title='Protocollo')),
                        y=alt.Y('Packet Count', axis=alt.Axis(title='Conteggio Pacchetti')),
                        tooltip=['Protocol', 'Packet Count']
                    ).properties(
                        title=f'Traffico per {ip_address} per Protocollo'
                    )
                    st.altair_chart(chart_packets, use_container_width=True)

                    if 'last_update_timestamp' in df_selected_flows.columns and 'bandwidth_mbps' in df_selected_flows.columns:
                        df_time_series = df_selected_flows.sort_values('last_update_timestamp').reset_index(drop=True)
                        df_time_series['timestamp_datetime'] = pd.to_datetime(df_time_series['last_update_timestamp'], unit='s')

                        df_time_series_filtered = df_time_series[df_time_series['bandwidth_mbps'] > 0]

                        if not df_time_series_filtered.empty:
                            st.subheader("Banda nel Tempo per Questi Flussi")
                            chart_bandwidth = alt.Chart(df_time_series_filtered).mark_line().encode(
                                x=alt.X('timestamp_datetime', axis=alt.Axis(title='Timestamp')),
                                y=alt.Y('bandwidth_mbps', axis=alt.Axis(title='Banda (Mbps)')),
                                color=alt.Color('dst_ip', legend=alt.Legend(title="IP Destinazione")),
                                tooltip=['timestamp_datetime', 'src_ip', 'dst_ip', 'bandwidth_mbps']
                            ).properties(
                                title=f'Banda per i Flussi che coinvolgono {ip_address}'
                            ).interactive()
                            st.altair_chart(chart_bandwidth, use_container_width=True)
                        else:
                            st.info("Nessun dato di banda (o tutti zero) disponibile nel tempo per questi flussi da tracciare.")

                st.markdown("---")
                st.subheader(f"Blocca/Sblocca IP Host: {ip_address}")

                is_host_blocked_overall = host_details_from_api.get('is_blocked', False)

                col_block_flow, col_unblock_flow = st.columns(2)
                if not is_host_blocked_overall:
                    with col_block_flow:
                        if st.button(f"Blocca Host IP {ip_address}", key=f"block_src_ip_{ip_address}"):
                            # Passa un dizionario con ip_address per il blocco generico dell'host
                            add_to_blocklist({"ip_address": ip_address, "reason": "Blocco manuale host dal pannello dettagli"})
                            st.rerun()
                else:
                    with col_unblock_flow:
                        if st.button(f"Sblocca Host IP {ip_address}", key=f"unblock_src_ip_{ip_address}"):
                            # Passa solo l'IP sorgente per lo sblocco generico dell'host
                            remove_from_blocklist(ip_src=ip_address)
                            st.rerun()

            else:
                st.info(f"Nessun dato dettagliato sui flussi disponibile per l'IP host {ip_address}. Controlla se i flussi sono attivi o se l'endpoint API funziona correttamente.")
        else:
            st.info(f"Nessun dettaglio trovato per l'IP host {ip_address}. Potrebbe non essere ancora stato scoperto o l'API non è disponibile.")
    else:
        st.info("Seleziona un indirizzo IP per visualizzare i dettagli.")


# --- Sidebar Navigation with Buttons ---
st.sidebar.title("Dashboard Navigation 🧭")
st.sidebar.markdown("Click a button to view the corresponding section.")

if 'current_page' not in st.session_state:
    st.session_state['current_page'] = "Network Statistics"

if st.sidebar.button("Network Statistics", key="btn_network_stats"):
    st.session_state['current_page'] = "Network Statistics"
    st.session_state['rerun_triggered'] = True
    st.rerun()

if st.sidebar.button("List All Flows", key="btn_all_flows"):
    st.session_state['current_page'] = "List All Flows"
    if 'selected_flow_src_ip' in st.session_state: # Clear selected IP if moving away from details
        del st.session_state['selected_flow_src_ip']
    st.session_state['rerun_triggered'] = True
    st.rerun()

if st.sidebar.button("Block Flow", key="btn_block_flow"):
    st.session_state['current_page'] = "Block Flow"
    st.session_state['rerun_triggered'] = True
    st.rerun()

if st.sidebar.button("List Blocked Flows", key="btn_blocked_flows"):
    st.session_state['current_page'] = "List Blocked Flows"
    st.session_state['rerun_triggered'] = True
    st.rerun()

# --- Main Page Content based on sidebar selection ---
st.title("SDN DoS Mitigation Dashboard")

if st.session_state['current_page'] == "Network Statistics":
    show_network_stats_section()
elif st.session_state['current_page'] == "Block Flow":
    show_block_flow_section()
elif st.session_state['current_page'] == "List Blocked Flows":
    show_blocked_flows_list_section()
elif st.session_state['current_page'] == "List All Flows":
    show_all_flows_section()
elif st.session_state['current_page'] == "Flow Details":
    if 'selected_flow_src_ip' in st.session_state:
        show_flow_details_panel()
    else:
        st.warning("No host IP selected to view details. Returning to 'List All Flows'.")
        st.session_state['current_page'] = "List All Flows"
        st.session_state['rerun_triggered'] = True
        st.rerun() # Reruns to the list all flows section

# Automatic rerun logic
if not st.session_state.get('rerun_triggered', False):
    time.sleep(5) # Attendi 5 secondi prima di aggiornare
    st.rerun()
# Resetta il flag dopo il rerun per permettere il prossimo aggiornamento automatico
if 'rerun_triggered' in st.session_state:
    del st.session_state['rerun_triggered']