#ifndef WEBAPI_H
#define WEBAPI_H

/* Here we define our constants, helper functions and directives
 * for simplicity and readability.
 */

#define TOKEN_SEED_FILE "/tmp/mnbox_tmp_api"
#define SHUTDOWN_FLAG_FILE "/tmp/shutdown_flag"
#ifndef NDEBUG
#define TOKEN_EXPIRY_TIME 60*60*60 /* If we are testing we can make expiry time almost infinite */
#else
#define TOKEN_EXPIRY_TIME 10*60
#endif
#define MINIBOX_CONFIG_FILE "/etc/minibox.cfg"
#define MINIBOX_NEW_CONFIG_FILE "/etc/minibox.cfg.new"
#define MINIBOX_DYNAMIC_FILE "/var/run/minibox.dynamic"
#define MINIBOX_STATIC_FILE "/etc/minibox.static"
#define UDHCPD_PID_FILE "/var/run/udhcpd.pid"
#define PPPD_PID_FILE "/var/run/pppd.pid"
#define HTTPD_PID_FILE "/var/run/httpd.pid"
#define PPP_INTERFACE "ppp0"

#define DEFAULT_USE_VLAN 0
#define DEFAULT_VLAN_ID 1
#define DEFAULT_VLAN_PCP 0
#define DEFAULT_PPPOE_USER ""
#define DEFAULT_PPPOE_PASS ""
#define DEFAULT_PPPOE_SERVICE ""
#define DEFAULT_PPPOE_MAC ""
#define DEFAULT_PPPOE_MTU 1492
#define DEFAULT_LAN_MASK 32
#define DEFAULT_LAN_IP "203.0.113.113"
#define DEFAULT_LAN_DHCP 1
#define DEFAULT_LAN_LEASE 60
#define DEFAULT_MANGLE_TTL 1

/* Cools macros and helper functions */
#define UINT_LENGTH(n) ((n)==0 ? 1 : ((int)floor(log10(n)) + 1))
static int is_valid_ip_address(const char *ip) { struct sockaddr_in sa; return inet_pton(AF_INET, ip, &(sa.sin_addr)); }
static int is_valid_user(const char* user) { struct spwd *shadow_entry = getspnam(user); return shadow_entry != NULL; }
static int is_valid_mac(const char* mac) {return (ether_aton(mac) != NULL) || strcmp(mac, "") != 0; }

/* Globals and definitions */

/* WebAPI internal error numbers:
 * 01 - JSON creation failed
 * 02 - JSON is malformed, call cJSON_GetErrorPtr() to get the root of the issue
 * 03 - JSON has no specified field
 * 10 - HTTP body is malformed
 * 20 - Token is invalid
 * 21 - Config file does not exist
 * 22 - User does not exist
 * 99 - Fatal error (something with C or the system is messed up)
 */
typedef enum
{
    NO_ERROR = 0,
    JSON_CREATION_FAILED = 1,
    JSON_MALFORMED = 2,
    JSON_MISSING_FIELD = 3,

    HTTP_BODY_MALFORMED = 10,
    TOKEN_INVALID = 20,
    CONFIG_NOT_FOUND = 21,
    USER_NOT_FOUND = 22,
    IF_NOT_FOUND = 23,

    FATAL_ERROR = 99
} webapi_error;
webapi_error webapi_errno = NO_ERROR;

/* Most of the time we are assigning existing values
 * of cJSON structs so no need of cleaning username and password
 */
typedef struct
{
    const char *username;
    const char *password;
} webapi_userinfo;

typedef struct
{
    uint32_t use_vlan;
    uint32_t vlan_id;
    uint32_t vlan_pcp;
    char* pppoe_user;
    char* pppoe_password;
    char* pppoe_service;
    char* pppoe_mac;
    uint32_t pppoe_mtu;
    uint32_t lan_mask;
    char* lan_ip;
    uint32_t lan_dhcp;
    uint32_t lan_lease;
    uint32_t mangle_ttl;
} minibox_config;
static void free_minibox_config(minibox_config* config)
{
    if (config == NULL) return;
    if (config->pppoe_user != NULL)
        free(config->pppoe_user);
    if (config->pppoe_password != NULL)
    {
        /* We'll first securely erase it from memory */
        crypto_wipe(config->pppoe_password, strlen(config->pppoe_password));
        free(config->pppoe_password);
    }
    if (config->pppoe_service != NULL)
        free(config->pppoe_service);
    if (config->pppoe_mac != NULL)
        free(config->pppoe_mac);
    if (config->lan_ip != NULL)
        free(config->lan_ip);
    free(config);
}

typedef struct
{
    char* pppoe_if;
    char* lan_if;
} minibox_static_config;
static void free_minibox_static_config(minibox_static_config* config)
{
    if (config == NULL) return;
    if (config->pppoe_if != NULL)
        free(config->pppoe_if);
    if (config->lan_if != NULL)
        free(config->lan_if);
    free(config);
}

typedef struct
{
    char* ppp_ip;
    char* ppp_gw;
    char* ppp_dns;
} minibox_ipinfo;
static void free_minibox_ipinfo(minibox_ipinfo* ipinfo)
{
    if (ipinfo == NULL) return;
    if (ipinfo->ppp_ip != NULL)
        free(ipinfo->ppp_ip);
    if (ipinfo->ppp_gw != NULL)
        free(ipinfo->ppp_gw);
    if (ipinfo->ppp_dns != NULL)
        free(ipinfo->ppp_dns);
    free(ipinfo);
}


/* HTTP Codes */
#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_INTERNAL_SERVER_ERROR 500

#define HTTP_STATUS(code) \
    (code == HTTP_OK ? "OK" : \
    code == HTTP_BAD_REQUEST ? "Bad Request" : \
    code == HTTP_FORBIDDEN ? "Forbidden" : \
    code == HTTP_NOT_FOUND ? "Not Found" : \
    code == HTTP_METHOD_NOT_ALLOWED ? "Method Not Allowed" :\
    code == HTTP_INTERNAL_SERVER_ERROR ? "Internal Server Error" : \
    "Unknown Status")

/* Constant messages - mostly error ones */

#define MSG_API_POST_ONLY           "Only the POST method is supported"
#define MSG_API_TOKEN_INVALID       "The token is invalid"
#define MSG_API_ACTION_NOT_FOUND    "Specified action not found"
#define MSG_API_USER_INVALID        "Specified username or password is invalid"
#define MSG_API_USER_NOT_FOUND      "Specified user not found"

#define MSG_VERY_FATAL_READ_CONFIG  "Very fatal error occured while reading the burned-in static configuration"

#define MSG_FATAL_ERROR_BODY        "Fatal error occurred while processing the body"
#define MSG_FATAL_ERROR_TOKEN       "Fatal error occurred while processing the token"
#define MSG_FATAL_ERROR_GEN_TOKEN   "Fatal error occurred while generating new token"
#define MSG_FATAL_ERROR_RESPONSE    "Fatal error occurred while generating the response"
#define MSG_FATAL_ERROR_READ_CONFIG "Fatal error occurred while reading the configuration"
#define MSG_FATAL_ERROR_MEM_ALLOC   "Fatal error occurred while allocating memory"
#define MSG_FATAL_ERROR_READ_IPINFO "Fatal error occurred while reading the IP info"
#define MSG_FATAL_ERROR_SET_CONFIG  "Fatal error occurred while setting the configuration"
#define MSG_FATAL_ERROR_SET_PASSWORD "Fatal error occurred while setting the password"
#define MSG_FATAL_ERROR_FATAL_ERROR "Fatal error occurred while generating an error message. Funny huh."
#define MSG_FATAL_ERROR_SUCCESS_MSG "Fatal error occurred while generating an success message"
#define MSG_FATAL_ERROR_FORK        "Fatal error occurred while forking"

#define MSG_HTTP_BODY_MALFORMED     "HTTP body malformed"

#define MSG_JSON_MALFORMED          "JSON body malformed"
#define MSG_JSON_MISSING_ACTION     "Missing field: action"
#define MSG_JSON_MISSING_US_PAS     "Missing field: user or password"

/* arc4random_buf() implementation for musl */

#if defined(__linux__) && defined(__GLIBC__)
#define IS_MUSL 0
#else
#define IS_MUSL 1
#endif

#if IS_MUSL

static void arc4random_buf_musl(void *buf, size_t n)
{
    int fd;
    ssize_t r;
    unsigned char* p = buf;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;

    while (n > 0)
    {
        r = read(fd, p, n);
        if (r <= 0)
        {
            close(fd);
            return;
        }
        p += r;
        n -= r;
    }

    close(fd);
}

#define arc4random_buf arc4random_buf_musl

#endif //IS_MUSL

#endif //WEBAPI_H
