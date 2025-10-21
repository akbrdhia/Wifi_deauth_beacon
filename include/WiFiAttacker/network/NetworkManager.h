#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

class NetworkManager {
public:
    static const char* getEncryptionType(wifi_auth_mode_t encryptionType);
    static void scanNetworks();
    static void selectTarget(String& targetSSID, uint8_t* targetBSSID, int& currentChannel);
    static void changeChannel(int channel);
    static void initWiFi();
    
private:
    static void printNetworkInfo(int index, const String& ssid, int rssi, int channel, wifi_auth_mode_t encType);
};

#endif // NETWORK_MANAGER_H