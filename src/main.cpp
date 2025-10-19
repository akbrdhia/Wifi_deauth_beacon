#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_system.h"

// Simple beacon packet for testing (fixed size)
uint8_t testPacket[] = {
  0x80, 0x00,                         // Frame Control
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast)
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Source MAC
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // BSSID
  0x00, 0x00,                         // Sequence
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
  0x64, 0x00,                         // Beacon interval
  0x31, 0x04,                         // Capability
  0x00, 0x04,                         // SSID parameter (tag + length)
  'T', 'E', 'S', 'T'                  // SSID: "TEST"
};

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("\n=================================");
  Serial.println("  ESP32 Packet Injection Test");
  Serial.println("=================================\n");
  
  // Print ESP32 info
  Serial.println("[*] ESP32 Chip Info:");
  Serial.print("    Model: ");
  Serial.println(ESP.getChipModel());
  Serial.print("    Revision: ");
  Serial.println(ESP.getChipRevision());
  Serial.print("    Cores: ");
  Serial.println(ESP.getChipCores());
  Serial.print("    SDK Version: ");
  Serial.println(ESP.getSdkVersion());
  
  Serial.println("\n[*] Initializing WiFi...");
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  // Try to enable promiscuous mode
  Serial.println("[*] Enabling promiscuous mode...");
  esp_err_t result = esp_wifi_set_promiscuous(true);
  
  if (result == ESP_OK) {
    Serial.println("[+] Promiscuous mode: ENABLED");
  } else {
    Serial.print("[-] Promiscuous mode FAILED! Error code: ");
    Serial.println(result);
  }
  
  // Set channel
  Serial.println("[*] Setting channel to 1...");
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  Serial.println("[+] Channel set");
  
  Serial.println("\n[*] Starting packet injection test...");
  Serial.println("[*] Look for WiFi network named 'TEST' on your phone");
  Serial.println("[*] If you see it, packet injection WORKS!\n");
}

void loop() {
  // Try to send beacon packet
  esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, testPacket, sizeof(testPacket), false);
  
  if (result == ESP_OK) {
    Serial.print(".");
  } else {
    Serial.print("\n[-] Packet send FAILED! Error: ");
    Serial.println(result);
    
    if (result == ESP_ERR_WIFI_IF) {
      Serial.println("    Error: WiFi interface not available");
    } else if (result == ESP_ERR_INVALID_ARG) {
      Serial.println("    Error: Invalid argument");
    } else {
      Serial.println("    Error: Unknown error code");
    }
    
    Serial.println("\n[!] Your ESP32 might not support packet injection!");
    Serial.println("[!] Possible causes:");
    Serial.println("    - ESP32 variant not supported (S2/S3/C3)");
    Serial.println("    - Framework version blocks injection");
    Serial.println("    - WiFi driver issue");
    
    delay(5000);
  }
  
  delay(100); // Send beacon every 100ms
}