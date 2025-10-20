#ifndef WIFI_ATTACKER_H
#define WIFI_ATTACKER_H

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_system.h"

class WiFiAttacker {
public:
    WiFiAttacker();
    void setup();
    void loop();
    void printMenu();
    void handleCommand(String cmd);

private:
    // Constants
    static const int MAX_PACKET_SIZE = 128;
    static const int MAX_SSID_LENGTH = 32;
    
    // Attack state
    bool attackRunning;
    int attackType; // 0=none, 1=deauth, 2=beacon spam
    String targetSSID;
    uint8_t targetBSSID[6];
    int currentChannel;

    // Packet templates
    uint8_t deauthPacket[26];
    uint8_t beaconPacket[109];

    // Core functions
    void scanNetworks();
    void selectTarget(int index);
    void startDeauthAttack();
    void sendDeauthPacket();
    void startBeaconSpam();
    void sendBeaconSpam();
    void stopAttack();
    void changeChannel(int channel);
    
    // Helper functions
    const char* getEncryptionType(wifi_auth_mode_t encryptionType);
    void initializePacketTemplates();
};

#endif // WIFI_ATTACKER_H