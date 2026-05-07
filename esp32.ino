#include <string.h>
#include "esp_wifi.h"
#include <WiFi.h>

#define LED_PIN 2
#define BUFFER_SIZE 20

// ========== PACKET STRUCTURE (44 bytes) ==========
struct Packet {
  uint16_t magic;           
  uint8_t mac[6];           
  int8_t rssi;              
  uint8_t channel;          
  uint8_t attack_type;      
  char ssid[33];            
} __attribute__((packed));

Packet packetBuffer[BUFFER_SIZE];
volatile int bufferHead = 0;
volatile int bufferTail = 0;
volatile int bufferCount = 0;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED; 

// ========== SNIFFER CALLBACK ==========
void wifi_sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  // We no longer reject non-management frames immediately!
  
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t *frame = pkt->payload;
  uint16_t frame_len = pkt->rx_ctrl.sig_len;

  if (frame_len < 24) return; // Minimum 802.11 header length

  uint16_t fc = (frame[1] << 8) | frame[0];
  uint8_t frameType = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;

  uint8_t attack = 0;
  uint8_t mac[6];
  char ssid[33] = "";

  // 1. Check for Management Frames (Connecting / Probing / Attacking)
  if (frameType == 0) {
    if (subtype == 4) attack = 1;       // Probe Request
    else if (subtype == 11) attack = 2; // Auth
    else if (subtype == 0) attack = 3;  // Assoc Request
    else if (subtype == 12) attack = 4; // Deauth
    else return;  

    memcpy(mac, &frame[10], 6); // Source MAC is at addr2

    // Extract SSID only if it's a Probe Request
    if (attack == 1) { 
      uint8_t *body = frame + 24;
      int body_len = frame_len - 24;
      int offset = 0;
      while (offset < body_len) {
        uint8_t tag = body[offset];
        uint8_t tag_len = body[offset + 1];
        if (tag == 0 && tag_len > 0 && tag_len <= 32) {
          memcpy(ssid, &body[offset + 2], tag_len);
          ssid[tag_len] = '\0';
          break;
        }
        offset += 2 + tag_len;
      }
    }
  } 
  // 2. Check for Data Frames (Device is successfully connected and talking)
  else if (frameType == 2) {
    attack = 5; // Custom code '5' means Active Data Traffic
    memcpy(mac, &frame[10], 6); // Transmitter MAC is at addr2
  } 
  // 3. Ignore Control Frames (ACKs, RTS/CTS, etc.)
  else {
    return; 
  }

  // Thread-safe buffer write
  portENTER_CRITICAL_ISR(&mux);
  if (bufferCount < BUFFER_SIZE) {
    Packet *p = &packetBuffer[bufferHead];
    p->magic = 0xBBAA; 
    memcpy(p->mac, mac, 6);
    p->rssi = pkt->rx_ctrl.rssi;
    p->channel = pkt->rx_ctrl.channel;
    p->attack_type = attack;
    strncpy(p->ssid, ssid, 33);
    
    bufferHead = (bufferHead + 1) % BUFFER_SIZE;
    bufferCount++;
  }
  portEXIT_CRITICAL_ISR(&mux);
}

// ========== SETUP ==========
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(); 
  delay(100);

  // Configure Promiscuous Mode to capture BOTH Management and Data frames
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
}

// ========== MAIN LOOP ==========
void loop() {
  // Channel hopping
  static unsigned long lastHop = 0;
  static uint8_t channel = 1;
  if (millis() - lastHop > 300) {
    channel = (channel % 13) + 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
  }

  // Thread-safe buffer read
  bool hasData = false;
  Packet p;
  portENTER_CRITICAL(&mux);
  if (bufferCount > 0) {
    p = packetBuffer[bufferTail];
    bufferTail = (bufferTail + 1) % BUFFER_SIZE;
    bufferCount--;
    hasData = true;
  }
  portEXIT_CRITICAL(&mux);

  // Send over USB
  static unsigned long ledTimer = 0;
  static bool ledOn = false;

  if (hasData) {
    Serial.write((uint8_t*)&p, sizeof(Packet));
    digitalWrite(LED_PIN, HIGH);
    ledTimer = millis();
    ledOn = true;
  }
  
  if (ledOn && (millis() - ledTimer > 10)) {
    digitalWrite(LED_PIN, LOW);
    ledOn = false;
  }
  
  delay(5); 
}