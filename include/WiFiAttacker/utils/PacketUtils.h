#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <Arduino.h>

class PacketUtils {
public:
    static void updateSequence(uint8_t* packet, uint16_t& sequenceNum);
    static void rotateReasonCode(uint8_t& reasonIndex);
    static const char* macToString(const uint8_t* mac);
    static const uint8_t reasonCodes[6];
    static uint16_t createBeaconFrame(uint8_t* packet, const char* ssid, uint8_t channel);
    
    // Constants
    static const int MAX_PACKET_SIZE = 128;
    static const int MAX_SSID_LENGTH = 32;
};

#endif // PACKET_UTILS_H