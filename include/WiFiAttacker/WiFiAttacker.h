#ifndef WIFI_ATTACKER_H
#define WIFI_ATTACKER_H

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include <vector>

struct ClientDevice {
    uint8_t mac[6];
    int8_t rssi;
    uint32_t lastSeen;
    uint16_t packets;
};

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
    int attackType; // 0=none, 1=deauth, 2=beacon spam, 3=targeted deauth
    String targetSSID;
    uint8_t targetBSSID[6];
    int currentChannel;
    
    // NEW: Enhanced attack parameters
    uint16_t sequenceNum;
    uint32_t packetsSent;
    uint32_t attackStartTime;
    uint16_t attackDelay;        // Delay between packets (ms)
    bool sniffingEnabled;
    std::vector<ClientDevice> clients;
    
    // Packet templates
    uint8_t deauthPacket[26];
    uint8_t beaconPacket[109];
    
    // NEW: Reason codes rotation
    const uint8_t reasonCodes[6] = {0x01, 0x02, 0x03, 0x06, 0x07, 0x08};
    uint8_t reasonIndex;
    
    // Core functions
    void scanNetworks();
    void selectTarget(int index);
    void startDeauthAttack();
    void sendDeauthPacket();
    void startBeaconSpam();
    void sendBeaconSpam();
    void stopAttack();
    void changeChannel(int channel);
    
    // NEW: Enhanced attack functions
    void startTargetedDeauth();
    void sendTargetedDeauth(uint8_t* clientMAC);
    void startClientSniffer();
    void stopClientSniffer();
    void listClients();
    void clearClients();
    
    // NEW: Packet manipulation
    void updateSequence(uint8_t* packet);
    void rotateReasonCode();
    
    // Helper functions
    const char* getEncryptionType(wifi_auth_mode_t encryptionType);
    void initializePacketTemplates();
    const char* macToString(const uint8_t* mac);
    void printStats();
    
    // NEW: Sniffer callback
    static void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static WiFiAttacker* instance;
    void processSniffedPacket(void* buf, wifi_promiscuous_pkt_type_t type);
    void addOrUpdateClient(uint8_t* mac, int8_t rssi);
};

#endif // WIFI_ATTACKER_H