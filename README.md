# SDN-DoS-Detection

## Introduzione

Nel panorama delle reti moderne, la complessità crescente e la costante minaccia di attacchi DDoS (Distributed Denial of Service) rendono obsolete le soluzioni di sicurezza tradizionali. Queste ultime, infatti, faticano a gestire la dinamicità e la scalabilità necessarie per proteggere le infrastrutture.

Il progetto proposto è stato sviluppato per sfruttare la flessibilità delle reti **SDN (Software Defined Networking)**, che consentono di separare il piano di controllo e il piano dati, creando un sistema robusto e interattivo per il rilevamento e la mitigazione di attacchi DoS/DDoS in tempo reale.

## Sistema di Rilevamento e Mitigazione per Reti SDN

La mitigazione degli attacchi DoS/DDoS tramite il blocco delle porte degli switch può risultare inefficace e persino dannosa. Questo approccio rischia il fenomeno di **over-blocking**, ovvero l'interruzione indiscriminata di **tutti i flussi** che attraversano una porta satura, compresi quelli legittimi. Inoltre, in ambienti di rete complessi, un attaccante può facilmente cambiare l'indirizzo IP o reindirizzare il traffico attraverso percorsi alternativi, rendendo inutile un blocco locale. Senza una gestione adeguata, le porte bloccate possono rimanere tali, degradando progressivamente le funzionalità di rete.

Per superare queste limitazioni, il sistema proposto integra un approccio di mitigazione basato sul **blocco selettivo dei flussi sospetti**, combinando due livelli di analisi:

  * **Analisi aggregata**: fornisce una visione d'insieme sullo stato di salute della rete, identificando situazioni di congestione o degrado delle prestazioni.
  * **Analisi granulare**: consente di risalire con ai flussi specifici responsabili del traffico anomalo, permettendo un intervento mirato.

Questa doppia prospettiva non solo rileva la presenza di congestione, ma ne identifica anche le possibili cause, consentendo di mitigare l'attacco in modo mirato e riducendo al minimo l'impatto sui flussi legittimi.

## Obiettivi

  * **Rilevare** automaticamente flussi anomali che indicano attacchi DoS/DDoS.
  * **Mitigare** gli attacchi in modo dinamico, con blocco/sblocco automatico o manuale del traffico malevolo.
  * **Fornire** un'interfaccia grafica interattiva per un monitoraggio intuitivo.
  * **Dimostrare** la flessibilità del sistema con diverse topologie di rete emulata.
  * **Offrire** API REST per l'integrazione con altri strumenti o l'automazione.

## Architettura

Il sistema è stato progettato con un'architettura modulare in cui tre componenti collaborano per individuare e bloccare il traffico malevolo.

  * **Ryu Controller**: gestisce il routing di base e implementa la logica di monitoraggio e di enforcement. Applica le politiche di blocco o sblocco dei flussi quando vengono rilevate condizioni specifiche.
  * **Custom API Handlers**: moduli Python che espongono le funzionalità del controller Ryu. Utilizzando un'interfaccia REST, consentono alla dashboard e ad altri servizi esterni di interagire con il sistema.
  * **Dashboard Streamlit**: interfaccia utente grafica che, tramite le API, permette all'amministratore di rete di visualizzare in tempo reale lo stato dei flussi e l'andamento della rete. Da qui, l'amministratore può anche intervenire manualmente per bloccare o sbloccare flussi specifici.

## 🛠️ Guida all'installazione

Questa guida fornisce i passaggi per configurare ed eseguire il sistema. L'installazione richiede l'installazione manuale di tutte le dipendenze.

### Installazione Manuale

1.  **Requisiti:**

      * Python ≥ 3.8
      * Mininet

2.  **Clona il repository:**

    ```bash
    git clone https://github.com/tuo_nome/SDN-DoS-Detection.git
    cd SDN-DoS-Detection
    ```

3.  **Installa le dipendenze Python:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Avvia i componenti in shell separate:**

      * **Controller Ryu:**
        ```bash
        ryu-manager Controller.py 
        ```
      * **Dashboard Streamlit:**
        ```bash
        streamlit run dashboard.py
        ```
      * **Topologia Mininet:**
        ```bash
        sudo python3.9 topology1.py
        ```

## Utilizzo del Sistema

Una volta che tutti i componenti sono attivi (controller, API, dashboard e topologia Mininet), puoi interagire con il sistema in due modi: tramite la dashboard interattiva o direttamente dalla linea di comando.

### Interazione da Dashboard

Accedi all'interfaccia web di Streamlit all'indirizzo `http://localhost:8501`. Qui potrai visualizzare in tempo reale lo stato dei flussi, le statistiche di rete e gestire manualmente la blocklist.

### Interazione da Linea di Comando

In alternativa puoi generare e monitorare il traffico direttamente da Mininet.

1.  **Avvia la topologia:** Assicurati di aver lanciato la topologia Mininet con il comando `sudo python topology1.py`. Dopo un controllo automatico della connettività, sarai nella shell di Mininet.
2.  **Apri terminali per gli host:** Dalla shell di Mininet, puoi aprire un terminale per ogni host usando il comando `xterm h1 h2 h3...`. Questo ti permetterà di interagire con ogni nodo separatamente.
3.  **Configura i server:** Prima di generare il traffico, inizializza i server `iperf` sugli host destinatari. Ad esempio, per l'host `10.0.0.3`:
      * Per il traffico UDP:
        ```bash
        iperf -s -u -p 5001 &
        ```
      * Per il traffico TCP:
        ```bash
        iperf -s -p 5002 &
        ```
    L'opzione `&` esegue il comando in background, lasciando il terminale disponibile.
4.  **Genera il traffico:** Ora, dagli altri host, puoi lanciare il traffico verso il server `10.0.0.3`.
      * Per il traffico UDP (`iperf -u`):
        ```bash
        iperf -c 10.0.0.3 -u -p 5001 -b XM -t Y
        ```
      * Per il traffico TCP:
        ```bash
        iperf -c 10.0.0.3 -p 5002 -b XM -t Y
        ```
    Sostituisci `X` con la larghezza di banda (in Mbps, es. `5M` per il traffico UDP e `5M` per il traffico TCP) e `Y` con la durata (in secondi, es. `60`).

Durante l'esecuzione di questi comandi, potrai osservare come il controller SDN rileva e gestisce i flussi anomali, e come le informazioni si riflettono sulla dashboard.