#ifndef CLIENT_DEVICE_H
#define CLIENT_DEVICE_H

#include <Arduino.h>

struct ClientDevice {
    uint8_t mac[6];
    int8_t rssi;
    uint32_t lastSeen;
    uint16_t packets;
};

#endif // CLIENT_DEVICE_H3