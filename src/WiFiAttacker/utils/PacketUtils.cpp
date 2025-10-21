#include "WiFiAttacker/utils/PacketUtils.h"

// Standard beacon frame elements
static const uint8_t beaconFrameTemplate[] = {
    0x00, 0x80,                             // Frame Control (0x0080 for beacon)
    0x00, 0x00,                             // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     // Destination address (broadcast)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     // Source address
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     // BSSID
    0x00, 0x00,                             // Sequence Control
    // Fixed parameters
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Timestamp (8 bytes)
    0x64, 0x00,                             // Beacon Interval (100ms)
    0x01, 0x04,                             // Capability info (ESS + WEP)
    // Tagged parameters
    0x00, 0x00,                             // SSID Parameter (id=0, len=0)
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96,     // Supported rates (1,2,5.5,11 Mbps)
    0x24, 0x30, 0x48, 0x6c,                 // More supported rates
    0x03, 0x01, 0x01                        // DSSS Parameter (Channel)
};

const uint8_t PacketUtils::reasonCodes[6] = {0x01, 0x02, 0x03, 0x04, 0x07, 0x0c};

void PacketUtils::updateSequence(uint8_t* packet, uint16_t& sequenceNum) {
    packet[22] = (sequenceNum & 0x0F) << 4;
    packet[23] = (sequenceNum & 0x0FF0) >> 4;
    sequenceNum = (sequenceNum + 1) % 4096;
}

void PacketUtils::rotateReasonCode(uint8_t& reasonIndex) {
    reasonIndex = (reasonIndex + 1) % 6;
}

const char* PacketUtils::macToString(const uint8_t* mac) {
    static char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return macStr;
}

uint16_t PacketUtils::createBeaconFrame(uint8_t* packet, const char* ssid, uint8_t channel) {
    static uint8_t buffer[128];  // Temporary buffer for building the packet
    uint16_t packetLen = 0;

    // Frame Control & Duration
    buffer[0] = 0x80;  // Type/Subtype: Management frame, Subtype = Beacon
    buffer[1] = 0x00;  // Flags
    buffer[2] = 0x00;  // Duration
    buffer[3] = 0x00;

    // Addresses
    memset(&buffer[4], 0xFF, 6);   // Destination: Broadcast
    
    // Generate random MAC for source/BSSID
    uint8_t randomMac[6];
    for (int i = 0; i < 6; i++) {
        randomMac[i] = random(256);
    }
    randomMac[0] &= 0xFE;  // Ensure unicast
    
    memcpy(&buffer[10], randomMac, 6);  // Source
    memcpy(&buffer[16], randomMac, 6);  // BSSID

    // Sequence number
    buffer[22] = 0x00;
    buffer[23] = 0x00;

    // Fixed parameters
    uint64_t timestamp = (uint64_t)millis() * 1000;
    memcpy(&buffer[24], &timestamp, 8);     // Timestamp
    
    buffer[32] = 0x64;                      // Beacon interval
    buffer[33] = 0x00;
    buffer[34] = 0x11;                      // Capability info
    buffer[35] = 0x00;

    packetLen = 36;

    // Add SSID
    buffer[packetLen++] = 0x00;             // SSID parameter number
    buffer[packetLen++] = strlen(ssid);     // SSID length
    memcpy(&buffer[packetLen], ssid, strlen(ssid));
    packetLen += strlen(ssid);

    // Add supported rates
    buffer[packetLen++] = 0x01;             // Supported rates parameter number
    buffer[packetLen++] = 0x08;             // Length
    buffer[packetLen++] = 0x82;             // 1(B)
    buffer[packetLen++] = 0x84;             // 2(B)
    buffer[packetLen++] = 0x8B;             // 5.5(B)
    buffer[packetLen++] = 0x96;             // 11(B)
    buffer[packetLen++] = 0x0C;             // 6
    buffer[packetLen++] = 0x12;             // 9
    buffer[packetLen++] = 0x18;             // 12
    buffer[packetLen++] = 0x24;             // 18

    // Add channel information
    buffer[packetLen++] = 0x03;             // DSSS Parameter Set
    buffer[packetLen++] = 0x01;             // Length
    buffer[packetLen++] = channel;          // Current channel

    // Copy complete packet to output buffer
    memcpy(packet, buffer, packetLen);
    return packetLen;
}