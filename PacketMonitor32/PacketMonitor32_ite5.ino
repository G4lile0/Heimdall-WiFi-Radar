//https://github.com/lpodkalicki/blog/blob/master/esp32/016_wifi_sniffer/main/main.c
// packet monitor from spacehuhn

/* uncomment if the default 4 bit mode doesn't work */
/* ------------------------------------------------ */
// #define BOARD_HAS_1BIT_SDMMC true // forces 1bit mode for SD MMC
/* ------------------------------------------------ */

#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <string>
#include <cstddef>
#include <Wire.h>
#include <Preferences.h>
using namespace std;


// g4lile0 ESPNow

#include <esp_now.h>
#include <WiFi.h>

#define CHANNEL 1

// Init ESP Now with fallback
void InitESPNow() {
  if (esp_now_init() == ESP_OK) {
    Serial.println("ESPNow Init Success");
  }
  else {
    Serial.println("ESPNow Init Failed");
    // Retry InitESPNow, add a counte and then restart?
    // InitESPNow();
    // or Simply Restart
    ESP.restart();
  }
}


// config AP SSID
void configDeviceAP() {
  char* SSID = "Slave_1";
  bool result = WiFi.softAP(SSID, "Slave_1_Password", CHANNEL, 0);
  if (!result) {
    Serial.println("AP Config failed.");
  } else {
    Serial.println("AP Config Success. Broadcasting with AP: " + String(SSID));
  }
}




/* ===== compile settings ===== */
#define MAX_CH 14 // 1 - 14 channels (1-11 for US, 1-13 for EU and 1-14 for Japan)
#define SNAP_LEN 2324 // max len of each recieved packet

#define BUTTON_PIN 0 // button to change the channel

#define USE_DISPLAY // comment out if you don't want to use the OLED display
#define FLIP_DISPLAY // comment out if you don't like to flip it
#define SDA_PIN 4
#define SCL_PIN 15
#define MAX_X 128
#define MAX_Y 51

#if CONFIG_FREERTOS_UNICORE
#define RUNNING_CORE 0
#else
#define RUNNING_CORE 1
#endif

#ifdef USE_DISPLAY
#include "SSD1306.h"
#endif

#include "FS.h"
#include "SD_MMC.h"
#include "Buffer.h"

esp_err_t event_handler(void* ctx, system_event_t* event) {
  return ESP_OK;
}



/* =====g4lile0 ===== */




#define DATA_LENGTH           112

#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04

struct RxControl {
 signed rssi:8; // signal intensity of packet
 unsigned rate:4;
 unsigned is_group:1;
 unsigned:1;
 unsigned sig_mode:2; // 0:is 11n packet; 1:is not 11n packet;
 unsigned legacy_length:12; // if not 11n packet, shows length of packet.
 unsigned damatch0:1;
 unsigned damatch1:1;
 unsigned bssidmatch0:1;
 unsigned bssidmatch1:1;
 unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
 unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
 unsigned HT_length:16;// if is 11n packet, shows length of packet.
 unsigned Smoothing:1;
 unsigned Not_Sounding:1;
 unsigned:1;
 unsigned Aggregation:1;
 unsigned STBC:2;
 unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
 unsigned SGI:1;
 unsigned rxend_state:8;
 unsigned ampdu_cnt:8;
 unsigned channel:4; //which channel this packet in.
 unsigned:12;
};

struct SnifferPacket{
    struct RxControl rx_ctrl;
    uint8_t data[DATA_LENGTH];
    uint16_t cnt;
    uint16_t len;
};




/* ===== run-time variables ===== */
Buffer sdBuffer;
#ifdef USE_DISPLAY
SSD1306  display(0x3c, SDA_PIN, SCL_PIN);
#endif
Preferences preferences;

bool useSD = false;
bool buttonPressed = false;
bool buttonEnabled = true;
uint32_t lastDrawTime;
uint32_t lastButtonTime;
uint32_t tmpPacketCounter;
uint32_t pkts[MAX_X]; // here the packets per second will be saved
uint32_t deauths = 0; // deauth frames per second
unsigned int ch = 1; // current 802.11 channel
int rssiSum;

/* ===== functions ===== */
double getMultiplicator() {
  uint32_t maxVal = 1;
  for (int i = 0; i < MAX_X; i++) {
    if (pkts[i] > maxVal) maxVal = pkts[i];
  }
  if (maxVal > MAX_Y) return (double)MAX_Y / (double)maxVal;
  else return 1;
}

void setChannel(int newChannel) {
  ch = newChannel;
  if (ch > MAX_CH || ch < 1) ch = 1;

  preferences.begin("packetmonitor32", false);
  preferences.putUInt("channel", ch);
  preferences.end();

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous);
  esp_wifi_set_promiscuous(true);
}

bool setupSD() {
  if (!SD_MMC.begin()) {
    Serial.println("Card Mount Failed");
    return false;
  }

  uint8_t cardType = SD_MMC.cardType();

  if (cardType == CARD_NONE) {
    Serial.println("No SD_MMC card attached");
    return false;
  }

  Serial.print("SD_MMC Card Type: ");
  if (cardType == CARD_MMC) {
    Serial.println("MMC");
  } else if (cardType == CARD_SD) {
    Serial.println("SDSC");
  } else if (cardType == CARD_SDHC) {
    Serial.println("SDHC");
  } else {
    Serial.println("UNKNOWN");
  }

  uint64_t cardSize = SD_MMC.cardSize() / (1024 * 1024);
  Serial.printf("SD_MMC Card Size: %lluMB\n", cardSize);

  return true;
}

void wifi_promiscuous(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  if (type == WIFI_PKT_MGMT && (pkt->payload[0] == 0xA0 || pkt->payload[0] == 0xC0 )) deauths++;

  if (type == WIFI_PKT_MISC) return; // wrong packet type
  if (ctrl.sig_len > SNAP_LEN) return; // packet too long

  uint32_t packetLength = ctrl.sig_len;
  if (type == WIFI_PKT_MGMT) packetLength -= 4; // fix for known bug in the IDF https://github.com/espressif/esp-idf/issues/886


  

//, CHAN=%02d, RSSI=%02d,"
//  Serial.print(pkt->payload);
  tmpPacketCounter++;
  rssiSum += ctrl.rssi;




  unsigned int frameControl = ((unsigned int)pkt->payload[1] << 8) + pkt->payload[0];

  uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
  uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

  // Only look for probe request packets
  if (frameType != TYPE_MANAGEMENT ||
  frameSubType != SUBTYPE_PROBE_REQUEST)
        return;

//  if (frameType != TYPE_MANAGEMENT )  return;



//  Serial.print(ctrl.rssi, DEC);
     
//Serial.print(".");

Serial.println("");
//Serial.printf("PACKET TYPE=%s CHAN=%02d, RSSI=%02d ",wifi_sniffer_packet_type2str(type),ctrl.channel,ctrl.rssi);
Serial.printf("PACKET TYPE=%s CHAN=%02d, RSSI=%02d ",wifi_sniffer_packet_type2str(type),pkt->rx_ctrl.channel,pkt->rx_ctrl.rssi);


        
  if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);

  Serial.print("RSSI: ");
  Serial.print(pkt->rx_ctrl.rssi, DEC);

  char addr[] = "00:00:00:00:00:00";
  getMAC(addr, pkt->payload, 10);
  Serial.print(" Peer MAC: ");
  Serial.print(addr);


  uint8_t SSID_length = pkt->payload[25];
  Serial.print(" SSID: ");
  printDataSpan(26, SSID_length, pkt->payload);

}



static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);


}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data) {
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    Serial.write(data[i]);
  }
}


char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}



void draw() {
#ifdef USE_DISPLAY
  double multiplicator = getMultiplicator();
  int len;
  int rssi;

  if (pkts[MAX_X - 1] > 0) rssi = rssiSum / (int)pkts[MAX_X - 1];
  else rssi = rssiSum;

  display.clear();
  display.drawString(0, 0, (String)ch + " | " + (String)rssi + " | Pkts " + (String)tmpPacketCounter + " [" + deauths + "]" + (useSD ? " | SD" : ""));
  display.drawLine(0, 63 - MAX_Y, MAX_X, 63 - MAX_Y);
  for (int i = 0; i < MAX_X; i++) {
    len = pkts[i] * multiplicator;
    display.drawLine(i, 63, i, 63 - (len > MAX_Y ? MAX_Y : len));
    if (i < MAX_X - 1) pkts[i] = pkts[i + 1];
  }
  display.display();
#endif
}

// callback when data is recv from Master
void OnDataRecv(const uint8_t *mac_addr, const uint8_t *data, int data_len) {
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
  Serial.print("Last Packet Recv from: "); Serial.println(macStr);
  Serial.print("Last Packet Recv Data: "); Serial.println(*data);
  Serial.println("");
}


/* ===== main program ===== */
void setup() {

  // Serial
  Serial.begin(115200);

 // EspNOW g4lile0

 Serial.println("ESPNow/Basic/Slave Example");
  //Set device in AP mode to begin with
 // WiFi.mode(WIFI_AP);
  // configure device AP mode
//  configDeviceAP();
  // This is the mac address of the Slave in AP Mode
//  Serial.print("AP MAC: "); Serial.println(WiFi.softAPmacAddress());
  // Init ESPNow with a fallback logic
  //InitESPNow();
  // Once ESPNow is successfully Init, we will register for recv CB to
  // get recv packer info.
  //esp_now_register_recv_cb(OnDataRecv);




  // Settings
  preferences.begin("packetmonitor32", false);
  ch = preferences.getUInt("channel", 1);
  preferences.end();




  // System & WiFi
  nvs_flash_init();
  tcpip_adapter_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  //ESP_ERROR_CHECK(esp_wifi_set_country(WIFI_COUNTRY_EU));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());

  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

  // SD card
  sdBuffer = Buffer();

  if (setupSD())
    sdBuffer.open(&SD_MMC);

  // I/O
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  // display
#ifdef USE_DISPLAY
  pinMode(16,OUTPUT);
  digitalWrite(16, LOW);    // set GPIO16 low to reset OLED
  delay(50); 
  digitalWrite(16, HIGH); // while OLED is running, must set GPIO16 in high
  display.init();
#ifdef FLIP_DISPLAY
  display.flipScreenVertically();
#endif

  /* show start screen */
  display.clear();
  display.setFont(ArialMT_Plain_16);
  display.drawString(6, 6, "PacketMonitor32");
  display.setFont(ArialMT_Plain_10);
  display.drawString(24, 34, "Made with <3 by");
  display.drawString(29, 44, "@Spacehuhn");
  display.display();

  delay(1000);
#endif

  // second core
  xTaskCreatePinnedToCore(
    coreTask,               /* Function to implement the task */
    "coreTask",             /* Name of the task */
    2500,                   /* Stack size in words */
    NULL,                   /* Task input parameter */
    0,                      /* Priority of the task */
    NULL,                   /* Task handle. */
    RUNNING_CORE);          /* Core where the task should run */

  // start Wifi sniffer
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous);
  esp_wifi_set_promiscuous(true);
}

void loop() {
  vTaskDelay(portMAX_DELAY);
}

void coreTask( void * p ) {

  uint32_t currentTime;

  while (true) {

    currentTime = millis();

    /* bit of spaghetti code, have to clean this up later :D */

    // check button
    if (digitalRead(BUTTON_PIN) == LOW) {
      if (buttonEnabled) {
        if (!buttonPressed) {
          buttonPressed = true;
          lastButtonTime = currentTime;
        } else if (currentTime - lastButtonTime >= 2000) {
          if (useSD) {
            useSD = false;
            sdBuffer.close(&SD_MMC);
            draw();
          } else {
            if (setupSD())
              sdBuffer.open(&SD_MMC);
            draw();
          }
          buttonPressed = false;
          buttonEnabled = false;
        }
      }
    } else {
      if (buttonPressed) {
        setChannel(ch + 1);
        draw();
      }
      buttonPressed = false;
      buttonEnabled = true;
    }

    // save buffer to SD
    if (useSD)
      sdBuffer.save(&SD_MMC);

    // draw Display
    if ( currentTime - lastDrawTime > 1000 ) {
      lastDrawTime = currentTime;
      // Serial.printf("\nFree RAM %u %u\n", heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT), heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT));// for debug purposes

      pkts[MAX_X - 1] = tmpPacketCounter;

      draw();

//      Serial.println((String)pkts[MAX_X - 1]);

      tmpPacketCounter = 0;
      deauths = 0;
      rssiSum = 0;
    }

    // Serial input
    if (Serial.available()) {
      ch = Serial.readString().toInt();
      if (ch < 1 || ch > 14) ch = 1;
      setChannel(ch);
    }

  }

}
