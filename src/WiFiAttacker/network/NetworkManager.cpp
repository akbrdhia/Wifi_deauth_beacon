#include "WiFiAttacker/network/NetworkManager.h"
#include "WiFiAttacker/utils/PacketUtils.h"

const char* NetworkManager::getEncryptionType(wifi_auth_mode_t encryptionType) {
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

void NetworkManager::initWiFi() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
}

void NetworkManager::scanNetworks() {
    Serial.println("\n[*] Scanning WiFi networks...");
    
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
            
            printNetworkInfo(i, ssid, WiFi.RSSI(i), WiFi.channel(i), WiFi.encryptionType(i));
        }
        Serial.println("╚════╧══════════════════════╧══════╧════╧═════════╝\n");
    }
}

void NetworkManager::printNetworkInfo(int index, const String& ssid, int rssi, int channel, wifi_auth_mode_t encType) {
    Serial.printf("║ %2d │ %s │ %4d │ %2d │ %-7s ║\n",
        index, ssid.c_str(), rssi, channel, getEncryptionType(encType));
}

void NetworkManager::selectTarget(String& targetSSID, uint8_t* targetBSSID, int& currentChannel) {
    esp_wifi_set_promiscuous(false);
    int n = WiFi.scanNetworks();
    
    if (n == 0) {
        Serial.println("[-] No networks available");
        esp_wifi_set_promiscuous(true);
        return;
    }
    
    targetSSID = WiFi.SSID(0);
    memcpy(targetBSSID, WiFi.BSSID(0), 6);
    currentChannel = WiFi.channel(0);
    
    Serial.println("\n[+] Target Selected:");
    Serial.println("    SSID   : " + targetSSID);
    Serial.printf("    BSSID  : %s\n", PacketUtils::macToString(targetBSSID));
    Serial.println("    Channel: " + String(currentChannel));
    Serial.println("    Encrypt: " + String(getEncryptionType(WiFi.encryptionType(0))));
    
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

void NetworkManager::changeChannel(int channel) {
    if (channel < 1 || channel > 13) {
        Serial.println("[-] Invalid channel (1-13)");
        return;
    }
    
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    Serial.println("[+] Channel changed to: " + String(channel));
}