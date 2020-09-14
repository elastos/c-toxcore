/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Functionality related to dealing with the config file.
 */
#include "config.h"

#include "config_defaults.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#include <libconfig.h>

#include "../../bootstrap_node_packets.h"

/**
 * Parses tcp relay ports from `cfg` and puts them into `tcp_relay_ports` array.
 *
 * Supposed to be called from get_general_config only.
 *
 * Important: iff `tcp_relay_port_count` > 0, then you are responsible for freeing `tcp_relay_ports`.
 */
static void parse_tcp_relay_ports_config(config_t *cfg, uint16_t **tcp_relay_ports, int *tcp_relay_port_count)
{
    const char *NAME_TCP_RELAY_PORTS = "tcp_relay_ports";

    *tcp_relay_port_count = 0;

    config_setting_t *ports_array = config_lookup(cfg, NAME_TCP_RELAY_PORTS);

    if (ports_array == nullptr) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in the configuration file.\n", NAME_TCP_RELAY_PORTS);
        log_write(LOG_LEVEL_WARNING, "Using default '%s':\n", NAME_TCP_RELAY_PORTS);

        uint16_t default_ports[DEFAULT_TCP_RELAY_PORTS_COUNT] = {DEFAULT_TCP_RELAY_PORTS};

        int i;

        for (i = 0; i < DEFAULT_TCP_RELAY_PORTS_COUNT; i ++) {
            log_write(LOG_LEVEL_INFO, "Port #%d: %u\n", i, default_ports[i]);
        }

        // similar procedure to the one of reading config file below
        *tcp_relay_ports = (uint16_t *)malloc(DEFAULT_TCP_RELAY_PORTS_COUNT * sizeof(uint16_t));

        for (i = 0; i < DEFAULT_TCP_RELAY_PORTS_COUNT; i ++) {

            (*tcp_relay_ports)[*tcp_relay_port_count] = default_ports[i];

            if ((*tcp_relay_ports)[*tcp_relay_port_count] < MIN_ALLOWED_PORT
                    || (*tcp_relay_ports)[*tcp_relay_port_count] > MAX_ALLOWED_PORT) {
                log_write(LOG_LEVEL_WARNING, "Port #%d: Invalid port: %u, should be in [%d, %d]. Skipping.\n", i,
                          (*tcp_relay_ports)[*tcp_relay_port_count], MIN_ALLOWED_PORT, MAX_ALLOWED_PORT);
                continue;
            }

            (*tcp_relay_port_count) ++;
        }

        // the loop above skips invalid ports, so we adjust the allocated memory size
        if ((*tcp_relay_port_count) > 0) {
            *tcp_relay_ports = (uint16_t *)realloc(*tcp_relay_ports, (*tcp_relay_port_count) * sizeof(uint16_t));
        } else {
            free(*tcp_relay_ports);
            *tcp_relay_ports = nullptr;
        }

        return;
    }

    if (config_setting_is_array(ports_array) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_ERROR, "'%s' setting should be an array. Array syntax: 'setting = [value1, value2, ...]'.\n",
                  NAME_TCP_RELAY_PORTS);
        return;
    }

    int config_port_count = config_setting_length(ports_array);

    if (config_port_count == 0) {
        log_write(LOG_LEVEL_ERROR, "'%s' is empty.\n", NAME_TCP_RELAY_PORTS);
        return;
    }

    *tcp_relay_ports = (uint16_t *)malloc(config_port_count * sizeof(uint16_t));

    int i;

    for (i = 0; i < config_port_count; i ++) {
        config_setting_t *elem = config_setting_get_elem(ports_array, i);

        if (elem == nullptr) {
            // it's NULL if `ports_array` is not an array (we have that check earlier) or if `i` is out of range, which should not be
            log_write(LOG_LEVEL_WARNING, "Port #%d: Something went wrong while parsing the port. Stopping reading ports.\n", i);
            break;
        }

        if (config_setting_is_number(elem) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Port #%d: Not a number. Skipping.\n", i);
            continue;
        }

        (*tcp_relay_ports)[*tcp_relay_port_count] = config_setting_get_int(elem);

        if ((*tcp_relay_ports)[*tcp_relay_port_count] < MIN_ALLOWED_PORT
                || (*tcp_relay_ports)[*tcp_relay_port_count] > MAX_ALLOWED_PORT) {
            log_write(LOG_LEVEL_WARNING, "Port #%d: Invalid port: %u, should be in [%d, %d]. Skipping.\n", i,
                      (*tcp_relay_ports)[*tcp_relay_port_count], MIN_ALLOWED_PORT, MAX_ALLOWED_PORT);
            continue;
        }

        (*tcp_relay_port_count) ++;
    }

    // the loop above skips invalid ports, so we adjust the allocated memory size
    if ((*tcp_relay_port_count) > 0) {
        *tcp_relay_ports = (uint16_t *)realloc(*tcp_relay_ports, (*tcp_relay_port_count) * sizeof(uint16_t));
    } else {
        free(*tcp_relay_ports);
        *tcp_relay_ports = nullptr;
    }
}

int get_general_config(const char *cfg_file_path, char **pid_file_path, char **keys_file_path, int *port,
                       int *enable_ipv6, int *enable_ipv4_fallback, int *enable_lan_discovery, int *enable_tcp_relay,
                       uint16_t **tcp_relay_ports, int *tcp_relay_port_count, int *enable_motd, char **motd)
{
    config_t cfg;

    const char *NAME_PORT                 = "port";
    const char *NAME_PID_FILE_PATH        = "pid_file_path";
    const char *NAME_KEYS_FILE_PATH       = "keys_file_path";
    const char *NAME_ENABLE_IPV6          = "enable_ipv6";
    const char *NAME_ENABLE_IPV4_FALLBACK = "enable_ipv4_fallback";
    const char *NAME_ENABLE_LAN_DISCOVERY = "enable_lan_discovery";
    const char *NAME_ENABLE_TCP_RELAY     = "enable_tcp_relay";
    const char *NAME_ENABLE_MOTD          = "enable_motd";
    const char *NAME_MOTD                 = "motd";

    config_init(&cfg);

    // Read the file. If there is an error, report it and exit.
    if (config_read_file(&cfg, cfg_file_path) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_ERROR, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    // Get port
    if (config_lookup_int(&cfg, NAME_PORT, port) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_PORT);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %d\n", NAME_PORT, DEFAULT_PORT);
        *port = DEFAULT_PORT;
    }

    // Get PID file location
    const char *tmp_pid_file;

    if (config_lookup_string(&cfg, NAME_PID_FILE_PATH, &tmp_pid_file) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_PID_FILE_PATH);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_PID_FILE_PATH, DEFAULT_PID_FILE_PATH);
        tmp_pid_file = DEFAULT_PID_FILE_PATH;
    }

    *pid_file_path = (char *)malloc(strlen(tmp_pid_file) + 1);
    strcpy(*pid_file_path, tmp_pid_file);

    // Get keys file location
    const char *tmp_keys_file;

    if (config_lookup_string(&cfg, NAME_KEYS_FILE_PATH, &tmp_keys_file) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_KEYS_FILE_PATH);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_KEYS_FILE_PATH, DEFAULT_KEYS_FILE_PATH);
        tmp_keys_file = DEFAULT_KEYS_FILE_PATH;
    }

    *keys_file_path = (char *)malloc(strlen(tmp_keys_file) + 1);
    strcpy(*keys_file_path, tmp_keys_file);

    // Get IPv6 option
    if (config_lookup_bool(&cfg, NAME_ENABLE_IPV6, enable_ipv6) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_IPV6);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_IPV6, DEFAULT_ENABLE_IPV6 ? "true" : "false");
        *enable_ipv6 = DEFAULT_ENABLE_IPV6;
    }

    // Get IPv4 fallback option
    if (config_lookup_bool(&cfg, NAME_ENABLE_IPV4_FALLBACK, enable_ipv4_fallback) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_IPV4_FALLBACK);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_IPV4_FALLBACK,
                  DEFAULT_ENABLE_IPV4_FALLBACK ? "true" : "false");
        *enable_ipv4_fallback = DEFAULT_ENABLE_IPV4_FALLBACK;
    }

    // Get LAN discovery option
    if (config_lookup_bool(&cfg, NAME_ENABLE_LAN_DISCOVERY, enable_lan_discovery) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_LAN_DISCOVERY);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_LAN_DISCOVERY,
                  DEFAULT_ENABLE_LAN_DISCOVERY ? "true" : "false");
        *enable_lan_discovery = DEFAULT_ENABLE_LAN_DISCOVERY;
    }

    // Get TCP relay option
    if (config_lookup_bool(&cfg, NAME_ENABLE_TCP_RELAY, enable_tcp_relay) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_TCP_RELAY);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_TCP_RELAY,
                  DEFAULT_ENABLE_TCP_RELAY ? "true" : "false");
        *enable_tcp_relay = DEFAULT_ENABLE_TCP_RELAY;
    }

    if (*enable_tcp_relay) {
        parse_tcp_relay_ports_config(&cfg, tcp_relay_ports, tcp_relay_port_count);
    } else {
        *tcp_relay_port_count = 0;
    }

    // Get MOTD option
    if (config_lookup_bool(&cfg, NAME_ENABLE_MOTD, enable_motd) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_MOTD);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_MOTD,
                  DEFAULT_ENABLE_MOTD ? "true" : "false");
        *enable_motd = DEFAULT_ENABLE_MOTD;
    }

    if (*enable_motd) {
        // Get MOTD
        const char *tmp_motd;

        if (config_lookup_string(&cfg, NAME_MOTD, &tmp_motd) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_MOTD);
            log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_MOTD, DEFAULT_MOTD);
            tmp_motd = DEFAULT_MOTD;
        }

        size_t tmp_motd_length = strlen(tmp_motd) + 1;
        size_t motd_length = tmp_motd_length > MAX_MOTD_LENGTH ? MAX_MOTD_LENGTH : tmp_motd_length;
        *motd = (char *)malloc(motd_length);
        strncpy(*motd, tmp_motd, motd_length);
        (*motd)[motd_length - 1] = '\0';
    }

    config_destroy(&cfg);

    log_write(LOG_LEVEL_INFO, "Successfully read:\n");
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_PID_FILE_PATH,        *pid_file_path);
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_KEYS_FILE_PATH,       *keys_file_path);
    log_write(LOG_LEVEL_INFO, "'%s': %d\n", NAME_PORT,                 *port);
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_IPV6,          *enable_ipv6          ? "true" : "false");
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_IPV4_FALLBACK, *enable_ipv4_fallback ? "true" : "false");
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_LAN_DISCOVERY, *enable_lan_discovery ? "true" : "false");

    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_TCP_RELAY,     *enable_tcp_relay     ? "true" : "false");

    // show info about tcp ports only if tcp relay is enabled
    if (*enable_tcp_relay) {
        if (*tcp_relay_port_count == 0) {
            log_write(LOG_LEVEL_ERROR, "No TCP ports could be read.\n");
        } else {
            log_write(LOG_LEVEL_INFO, "Read %d TCP ports:\n", *tcp_relay_port_count);
            int i;

            for (i = 0; i < *tcp_relay_port_count; i ++) {
                log_write(LOG_LEVEL_INFO, "Port #%d: %u\n", i, (*tcp_relay_ports)[i]);
            }
        }
    }

    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_MOTD,          *enable_motd          ? "true" : "false");

    if (*enable_motd) {
        log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_MOTD, *motd);
    }

    return 1;
}

#ifdef CARRIER_BUILD
int get_turn_config(const char *cfg_file_path, int *port, char **realm,
                    char **pid_file_path, char **userdb, int *verbose, char **external_ip)
{
    config_t cfg;

    const char *NAME_TURN                 = "turn";

    const char *NAME_PORT                 = "port";
    const char *NAME_REALM                = "realm";
    const char *NAME_PID_FILE_PATH        = "pid_file_path";
    const char *NAME_USER_DB              = "userdb";
    const char *NAME_VERBOSE              = "verbose";
    const char *NAME_EXTERNAL_IP          = "external_ip";

    config_init(&cfg);

    // Read the file. If there is an error, report it and exit.
    if (config_read_file(&cfg, cfg_file_path) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_ERROR, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    config_setting_t *turn_cfg = config_lookup(&cfg, NAME_TURN);

    if (turn_cfg == NULL) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in the configuration file. Skipping bootstrapping.\n",
                  NAME_TURN);
        config_destroy(&cfg);
        return 1;
    }

    // Get port
    if (config_setting_lookup_int(turn_cfg, NAME_PORT, port) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No TURN '%s' setting in turn config file.\n", NAME_PORT);
        *port = 0;
    }

    // Get realm
    const char *tmp_realm;

    if (config_setting_lookup_string(turn_cfg, NAME_REALM, &tmp_realm) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No TURN '%s' setting in configuration file.\n", NAME_REALM);
        tmp_realm = NULL;
    }

    if (tmp_realm) {
        *realm = (char *)malloc(strlen(tmp_realm) + 1);
        strcpy(*realm, tmp_realm);
    } else {
        *realm = NULL;
    }

    // Get PID file location
    const char *tmp_pid_file;

    if (config_setting_lookup_string(turn_cfg, NAME_PID_FILE_PATH, &tmp_pid_file) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No TURN '%s' setting in configuration file.\n", NAME_PID_FILE_PATH);
        tmp_pid_file = NULL;
    }

    if (tmp_pid_file) {
        *pid_file_path = (char *)malloc(strlen(tmp_pid_file) + 1);
        strcpy(*pid_file_path, tmp_pid_file);
    } else {
        *pid_file_path = NULL;
    }

    // Get user db location
    const char *tmp_userdb;

    if (config_setting_lookup_string(turn_cfg, NAME_USER_DB, &tmp_userdb) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No TURN '%s' setting in configuration file.\n", NAME_USER_DB);
        tmp_userdb = NULL;
    }

    if (tmp_userdb) {
        *userdb = (char *)malloc(strlen(tmp_userdb) + 1);
        strcpy(*userdb, tmp_userdb);
    } else {
        *userdb = NULL;
    }

    if (config_setting_lookup_bool(turn_cfg, NAME_VERBOSE, verbose) == CONFIG_FALSE) {
         *verbose = 0;
    }

    // Get external IP
    const char *tmp_external_ip;

    if (config_setting_lookup_string(turn_cfg, NAME_EXTERNAL_IP, &tmp_external_ip) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No TURN '%s' setting in configuration file.\n", NAME_EXTERNAL_IP);
        tmp_external_ip = NULL;
    }

    if (tmp_external_ip) {
        *external_ip = (char *)malloc(strlen(tmp_external_ip) + 1);
        strcpy(*external_ip, tmp_external_ip);
    } else {
        *external_ip = NULL;
    }

    config_destroy(&cfg);

    log_write(LOG_LEVEL_INFO, "Successfully read TURN config:\n");
    if (*port)
        log_write(LOG_LEVEL_INFO, "'%s': %d\n", NAME_PORT,                 *port);
    if (*realm)
        log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_REALM,                *realm);
    if (*pid_file_path)
        log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_PID_FILE_PATH,        *pid_file_path);
    if (*userdb)
        log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_USER_DB,              *userdb);
    if (*verbose)
        log_write(LOG_LEVEL_INFO, "'%s': %d\n", NAME_VERBOSE,              *verbose);
    if (*external_ip)
        log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_EXTERNAL_IP,          *external_ip);

    return 1;
}

static uint8_t *base58_string_to_bin(const char *base58_string)
{
    uint8_t *ret = (uint8_t *)malloc(64);
    ssize_t len = 64;

    len = base58_decode(base58_string, strlen(base58_string), ret, 64);
    if (len != 32) {
        return NULL;
    }

    return ret;
}
#else
/**
 *
 * Converts a hex string with even number of characters into binary.
 *
 * Important: You are responsible for freeing the return value.
 *
 * @return binary on success,
 *         NULL on failure.
 */
static uint8_t *bootstrap_hex_string_to_bin(const char *hex_string)
{
    if (strlen(hex_string) % 2 != 0) {
        return nullptr;
    }

    size_t len = strlen(hex_string) / 2;
    uint8_t *ret = (uint8_t *)malloc(len);

    const char *pos = hex_string;
    size_t i;

    for (i = 0; i < len; ++i, pos += 2) {
        unsigned int val;
        sscanf(pos, "%02x", &val);
        ret[i] = val;
    }

    return ret;
}
#endif

int bootstrap_from_config(const char *cfg_file_path, DHT *dht, int enable_ipv6)
{
    const char *NAME_BOOTSTRAP_NODES = "bootstrap_nodes";

    const char *NAME_PUBLIC_KEY = "public_key";
    const char *NAME_PORT       = "port";
    const char *NAME_ADDRESS    = "address";

    config_t cfg;

    config_init(&cfg);

    if (config_read_file(&cfg, cfg_file_path) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_ERROR, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    config_setting_t *node_list = config_lookup(&cfg, NAME_BOOTSTRAP_NODES);

    if (node_list == nullptr) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in the configuration file. Skipping bootstrapping.\n",
                  NAME_BOOTSTRAP_NODES);
        config_destroy(&cfg);
        return 1;
    }

    if (config_setting_length(node_list) == 0) {
        log_write(LOG_LEVEL_WARNING, "No bootstrap nodes found. Skipping bootstrapping.\n");
        config_destroy(&cfg);
        return 1;
    }

    int bs_port;
    const char *bs_address;
    const char *bs_public_key;

    config_setting_t *node;

    int i = 0;

    while (config_setting_length(node_list)) {
        int address_resolved;
        uint8_t *bs_public_key_bin;

        node = config_setting_get_elem(node_list, 0);

        if (node == nullptr) {
            config_destroy(&cfg);
            return 0;
        }

        // Check that all settings are present
        if (config_setting_lookup_string(node, NAME_PUBLIC_KEY, &bs_public_key) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i,
                      NAME_PUBLIC_KEY);
            goto next;
        }

        if (config_setting_lookup_int(node, NAME_PORT, &bs_port) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i, NAME_PORT);
            goto next;
        }

        if (config_setting_lookup_string(node, NAME_ADDRESS, &bs_address) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i, NAME_ADDRESS);
            goto next;
        }

#ifndef CARRIER_BUILD
        // Process settings
        if (strlen(bs_public_key) != CRYPTO_PUBLIC_KEY_SIZE * 2) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Invalid '%s': %s. Skipping the node.\n", i, NAME_PUBLIC_KEY,
                      bs_public_key);
            goto next;
        }
#endif

        if (bs_port < MIN_ALLOWED_PORT || bs_port > MAX_ALLOWED_PORT) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Invalid '%s': %d, should be in [%d, %d]. Skipping the node.\n", i,
                      NAME_PORT,
                      bs_port, MIN_ALLOWED_PORT, MAX_ALLOWED_PORT);
            goto next;
        }

#ifdef CARRIER_BUILD
        bs_public_key_bin = base58_string_to_bin(bs_public_key);
#else
        bs_public_key_bin = bootstrap_hex_string_to_bin(bs_public_key);
#endif
        address_resolved = dht_bootstrap_from_address(dht, bs_address, enable_ipv6, net_htons(bs_port),
                           bs_public_key_bin);
        free(bs_public_key_bin);

        if (!address_resolved) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Invalid '%s': %s. Skipping the node.\n", i, NAME_ADDRESS, bs_address);
            goto next;
        }

        log_write(LOG_LEVEL_INFO, "Successfully added bootstrap node #%d: %s:%d %s\n", i, bs_address, bs_port, bs_public_key);

next:
        // config_setting_lookup_string() allocates string inside and doesn't allow us to free it direcly
        // though it's freed when the element is removed, so we free it right away in order to keep memory
        // consumption minimal
        config_setting_remove_elem(node_list, 0);
        i++;
    }

    config_destroy(&cfg);

    return 1;
}

#ifdef CARRIER_BUILD
#include <stdint.h>

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t b58digits_map[] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

char *base58_encode(const void *data, size_t len, char *text, size_t *textlen)
{
    const uint8_t *bin = data;
    int carry;
    ssize_t i, j, high, zcount = 0;
    size_t size;

    while (zcount < len && !bin[zcount])
        ++zcount;

    size = (len - zcount) * 138 / 100 + 1;
    uint8_t *buf = (uint8_t *)alloca(size * sizeof(uint8_t));
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < len; ++i, high = j) {
        for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    for (j = 0; j < size && !buf[j]; ++j);

    if (*textlen <= zcount + size - j) {
        *textlen = zcount + size - j + 1;
        return NULL;
    }

    if (zcount)
        memset(text, '1', zcount);
    for (i = zcount; j < size; ++i, ++j)
        text[i] = b58digits_ordered[buf[j]];
    text[i] = '\0';
    *textlen = i + 1;

    return text;
}

ssize_t base58_decode(const char *text, size_t textlen, void *data, size_t datalen)
{
    size_t tmp = datalen;
    size_t *binszp = &tmp;
    size_t binsz = *binszp;
    const unsigned char *textu = (void*)text;
    unsigned char *binu = data;
    size_t outisz = (binsz + 3) / 4;
    uint32_t *outi = (uint32_t *)alloca(outisz * sizeof(uint32_t));
    uint64_t t;
    uint32_t c;
    size_t i, j;
    uint8_t bytesleft = binsz % 4;
    uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
    unsigned zerocount = 0;

    if (!textlen)
        textlen = strlen(text);

    memset(outi, 0, outisz * sizeof(*outi));

    // Leading zeros, just count
    for (i = 0; i < textlen && textu[i] == '1'; ++i)
        ++zerocount;

    for ( ; i < textlen; ++i) {
        if (textu[i] & 0x80)
            // High-bit set on invalid digit
            return -1;
        if (b58digits_map[textu[i]] == -1)
            // Invalid base58 digit
            return -1;
        c = (unsigned)b58digits_map[textu[i]];
        for (j = outisz; j--; ) {
            t = ((uint64_t)outi[j]) * 58 + c;
            c = (t & 0x3f00000000) >> 32;
            outi[j] = t & 0xffffffff;
        }
        if (c)
            // Output number too big (carry to the next int32)
            return -1;
        if (outi[0] & zeromask)
            // Output number too big (last int32 filled too far)
            return -1;
    }

    j = 0;
    switch (bytesleft) {
    case 3:
        *(binu++) = (outi[0] &   0xff0000) >> 16;
    case 2:
        *(binu++) = (outi[0] &     0xff00) >>  8;
    case 1:
        *(binu++) = (outi[0] &       0xff);
        ++j;
    default:
        break;
    }

    for (; j < outisz; ++j) {
        *(binu++) = (outi[j] >> 0x18) & 0xff;
        *(binu++) = (outi[j] >> 0x10) & 0xff;
        *(binu++) = (outi[j] >>    8) & 0xff;
        *(binu++) = (outi[j] >>    0) & 0xff;
    }

    // Count canonical base58 byte count
    binu = data;
    for (i = 0; i < binsz; ++i) {
        if (binu[i])
            break;
        --*binszp;
    }
    *binszp += zerocount;

    return *binszp;
}
#endif
