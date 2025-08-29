#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shadow.h>
#include <unistd.h>
#include <crypt.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/wait.h>
#include <errno.h>

#include "cJSON.h"
#include "monocypher.h"
#include "b64.h"

#include "webapi.h"

/* HTTP handling functions */
void http_return_error(int code, const char* message);
int http_return_success(cJSON* data);
int http_validate_token_header();

/* JSON handling functions */
void json_erase_password(const cJSON* body);
cJSON* json_prepare_error_message(const char* message);
cJSON* json_prepare_success(cJSON* data);
cJSON* json_fetch_http_body(void);
const char* json_get_action(const cJSON* body);
webapi_userinfo* json_get_userinfo(const cJSON* body);
minibox_config* json_get_config(const cJSON* body);

/* minibox-specific handling functions */
int minibox_verify_system_password(const char* username, const char* password);
uint8_t* minibox_get_session_token();
char* minibox_generate_token(const char* username);
int minibox_verify_token(const char* token);
minibox_config* minibox_get_config();
minibox_static_config* minibox_get_static_config();
char* minibox_get_interface_status(const char* interface);
minibox_ipinfo* minibox_get_ipinfo();
int minibox_set_config(const minibox_config* new_config);
int minibox_set_password(const char* username, const char* password);
int minibox_create_shutdown_flag();

/* Action processing entry points */
int process_authenticate(const cJSON* body);
int process_get_config();
int process_set_config(const cJSON* body);
int process_get_services();
int process_get_interfaces();
int process_get_ipinfo();
int process_change_password(const cJSON* body);
int process_restart();
int process_shutdown();

/* Main entrypoint to the CGI application */
int main(void)
{
    int status = 0;
    const char* http_method = NULL;
    cJSON* http_body = NULL;
    const char* api_action = NULL;
    int valid_token;

    /* First we need to know if we got a POST, because we are a POST-only API
     * This is also a nice check if we've been invoked from CGI interface and
     * not from shell.
     */
    http_method = getenv("REQUEST_METHOD");
    if (http_method == NULL || strcmp(http_method, "POST") != 0)
    {
        http_return_error(HTTP_METHOD_NOT_ALLOWED, MSG_API_POST_ONLY);
        goto end;
    }

    /* Parse our body */
    http_body = json_fetch_http_body();
    if (http_body == NULL)
    {
        switch (webapi_errno)
        {
            case HTTP_BODY_MALFORMED: http_return_error(HTTP_BAD_REQUEST, MSG_HTTP_BODY_MALFORMED); status = -1; goto end;
            case JSON_MALFORMED: http_return_error(HTTP_BAD_REQUEST, MSG_JSON_MALFORMED); status = -1; goto end;
            case FATAL_ERROR: http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_BODY); status = -1; goto end;
            default: status = -1; goto end;
        }
    }

    /* Get action from our body */
    api_action = json_get_action(http_body);
    if (api_action == NULL)
    {
        switch (webapi_errno)
        {
            case JSON_MISSING_FIELD: http_return_error(HTTP_BAD_REQUEST, MSG_JSON_MISSING_ACTION); status = -1; goto end;
            case JSON_MALFORMED: http_return_error(HTTP_BAD_REQUEST, MSG_JSON_MALFORMED); status = -1; goto end;
            default: status = -1; goto end;
        }
    }

    /* Here are the token validation procedure, but we enforce the token later */
    valid_token = http_validate_token_header();

    /* Our only token-optional action - authentication */
    if (strcmp(api_action, "authenticate") == 0)
    {
        status = process_authenticate(http_body);
        goto end;
    }

    /* NOW, we are enforcing the token */
    if (valid_token != 0)
    {
        switch (webapi_errno)
        {
            case TOKEN_INVALID: http_return_error(HTTP_FORBIDDEN, MSG_API_TOKEN_INVALID); status = -1; goto end;
            case FATAL_ERROR: http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_TOKEN); status = -1; goto end;
            default: status = -1; goto end;
        }
    }

    /* First token-enforced endpoint - get_config */
    if (strcmp(api_action, "get_config") == 0)
        status = process_get_config();
    else if (strcmp(api_action, "get_services") == 0)
        status = process_get_services();
    else if (strcmp(api_action, "get_interfaces") == 0)
        status = process_get_interfaces();
    else if (strcmp(api_action, "get_ipinfo") == 0)
        status = process_get_ipinfo();
    else if (strcmp(api_action, "set_config") == 0)
        status = process_set_config(http_body);
    else if (strcmp(api_action, "change_password") == 0)
        status = process_change_password(http_body);
    else if (strcmp(api_action, "restart") == 0)
        status = process_restart();
    else if (strcmp(api_action, "shutdown") == 0)
        status = process_shutdown();
    else
        http_return_error(HTTP_NOT_FOUND, MSG_API_ACTION_NOT_FOUND);

end:
    /* Free everything we got */
    if (status == 0) json_erase_password(http_body);
    cJSON_Delete(http_body);
    return status;
}

int process_authenticate(const cJSON* body)
{
    webapi_userinfo* userinfo;
    int authentication_status;
    char* token;
    cJSON* response;
    int status;

    /* Get the userinfo from json. We sure to deallocate the struct */
    userinfo = json_get_userinfo(body);
    if (userinfo == NULL)
    {
        free(userinfo);
        switch (webapi_errno)
        {
            case JSON_MISSING_FIELD: http_return_error(HTTP_BAD_REQUEST, MSG_JSON_MISSING_US_PAS); break;
            case JSON_MALFORMED: http_return_error(HTTP_BAD_REQUEST, MSG_JSON_MALFORMED); break;
            default: break;
        }

        return -1;
    }

    /* Check if we are in */
    authentication_status = minibox_verify_system_password(userinfo->username, userinfo->password);
    if (authentication_status != 0)
    {
        http_return_error(HTTP_FORBIDDEN, MSG_API_USER_INVALID);
        free(userinfo);
        return -1;
    }

    /* Generate token for the user */
    token = minibox_generate_token(userinfo->username);
    if (token == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_GEN_TOKEN);
        free(userinfo);
        free(token);
        return -1;
    }

    /* Generate response */
    response = cJSON_CreateObject();
    if (response == NULL || cJSON_AddStringToObject(response, "token", token) == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_RESPONSE);
        free(userinfo);
        free(token);
        cJSON_Delete(response);
        return -1;
    }

    /* Send response with the token
     * We don't need to delete cJSON response
     * because the function will do it for us
     */
    status = http_return_success(response);

    free(userinfo);
    free(token);
    return status;
}

int process_get_config()
{
    minibox_config* config;
    cJSON* response;
    int status;

    /* Get Minibox config */
    config = minibox_get_config();
    if (config == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_RESPONSE);
        return -1;
    }

    /* Build response JSON */
    response = cJSON_CreateObject();
    if (response == NULL)
    {
end:
        if (response != NULL) cJSON_Delete(response);
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_RESPONSE);
        free_minibox_config(config);
        return -1;
    }

    /* It does look somewhat beautiful */
    if (cJSON_AddBoolToObject(response,     "use_vlan", config->use_vlan) == NULL) { goto end; }
    if (cJSON_AddNumberToObject(response,   "vlan_id", config->vlan_id) == NULL) { goto end; }
    if (cJSON_AddNumberToObject(response,   "vlan_pcp", config->vlan_pcp) == NULL) { goto end; }
    if (cJSON_AddStringToObject(response,   "pppoe_user", config->pppoe_user) == NULL) { goto end; }
    /* No we don't. */
    /* Fun fact: some ISPs' routers don't populate PPPoE password in WebUI,
     * but they DO fetch the password in plaintext from the internal API. Look sometimes
     * at the network tab in devtools while configuring your ISP-provided router.
     * Maybe you'll find a goldmine there. Nevertheless, we are patching this "security hole"
     */
    if (cJSON_AddNullToObject(response,     "pppoe_password") == NULL) { goto end; }
    if (cJSON_AddStringToObject(response,   "pppoe_service", config->pppoe_service) == NULL) { goto end; }
    if (cJSON_AddNumberToObject(response,   "pppoe_mtu", config->pppoe_mtu) == NULL) { goto end; }
    if (cJSON_AddStringToObject(response,   "pppoe_mac", config->pppoe_mac) == NULL) { goto end; }
    if (cJSON_AddNumberToObject(response,   "lan_mask", config->lan_mask) == NULL) {  goto end; }
    if (cJSON_AddStringToObject(response,   "lan_ip", config->lan_ip) == NULL) {  goto end; }
    if (cJSON_AddBoolToObject(response,     "lan_dhcp", config->lan_dhcp) == NULL) {  goto end; }
    if (cJSON_AddNumberToObject(response,   "lan_lease", config->lan_lease) == NULL) {  goto end; }
    if (cJSON_AddBoolToObject(response,     "mangle_ttl", config->mangle_ttl) == NULL) {  goto end; }

    /* Send response
     * We don't need to delete cJSON response
     * because the function will do it for us
     */
    status = http_return_success(response);

    /* Free what we need */
    free_minibox_config(config);

    return status;
}

/* We assume that if PID file exists than we are good */
int process_get_services()
{
    int status;
    cJSON* response;

    response = cJSON_CreateObject();
    if (response == NULL)
    {
end:
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_RESPONSE);
        if (response != NULL) cJSON_Delete(response);
        return -1;
    }

    if (cJSON_AddBoolToObject(response, "pppd", access(PPPD_PID_FILE, F_OK) == 0) == NULL) { goto end;}
    if (cJSON_AddBoolToObject(response, "udhcpd", access(UDHCPD_PID_FILE, F_OK) == 0) == NULL) { goto end;}
    if (cJSON_AddBoolToObject(response, "httpd", access(HTTPD_PID_FILE, F_OK) == 0) == NULL) { goto end;}

    /* Send response
     * We don't need to delete cJSON response
     * because the function will do it for us
     */
    status = http_return_success(response);

    return status;

}

int process_get_interfaces()
{
    int status;
    cJSON* response = NULL;
    minibox_config* config;
    minibox_static_config* static_config;
    char* vlan_if = NULL;

    char* base_if_status = NULL;
    char* vlan_if_status = NULL;
    char* lan_if_status = NULL;
    char* ppp_if_status = NULL;

    /* Get static config */
    static_config = minibox_get_static_config();
    if (static_config == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_VERY_FATAL_READ_CONFIG);
        free_minibox_static_config(static_config);
        return -1;
    }

    /* Get config */
    config = minibox_get_config();
    if (config == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_READ_CONFIG);
        free_minibox_static_config(static_config);
        free_minibox_config(config);
        return -1;
    }

    /* If we have enabled VLANs we also need to check VLAN if */
    if (config->use_vlan)
    {
        vlan_if = (char *)malloc(UINT_LENGTH(config->vlan_id) + strlen(static_config->lan_if) + 2); /* dot and \0 */
        if (vlan_if == NULL)
        {
            http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_MEM_ALLOC);
            free_minibox_static_config(static_config);
            free_minibox_config(config);
            free(vlan_if);
            return -1;
        }

        snprintf(vlan_if, 10, "%s.%d", static_config->pppoe_if, config->vlan_id);
    }

    /* Get all interfaces' status */
    if ((base_if_status = minibox_get_interface_status(static_config->pppoe_if)) == NULL && webapi_errno != IF_NOT_FOUND) { goto end; }
    if (config->use_vlan && (vlan_if_status = minibox_get_interface_status(vlan_if)) == NULL && webapi_errno != IF_NOT_FOUND) { goto end; }
    if ((lan_if_status = minibox_get_interface_status(static_config->lan_if)) == NULL && webapi_errno != IF_NOT_FOUND) { goto end; }
    if ((ppp_if_status = minibox_get_interface_status(PPP_INTERFACE)) == NULL && webapi_errno != IF_NOT_FOUND) { goto end; }

    /* Generate JSON response */
    response = cJSON_CreateObject();
    if (response == NULL)
    {
end:
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_RESPONSE);
        if (response != NULL) cJSON_Delete(response);
        free_minibox_static_config(static_config);
        free_minibox_config(config);
        free(vlan_if);
        free(base_if_status);
        free(ppp_if_status);
        free(vlan_if_status);
        free(lan_if_status);
        return -1;
    }

    /* Add everything to our JSON */
    if (base_if_status != NULL && cJSON_AddStringToObject(response, static_config->pppoe_if, base_if_status) == NULL) { goto end; }
    if (vlan_if_status != NULL && cJSON_AddStringToObject(response, vlan_if, vlan_if_status) == NULL) { goto end; }
    if (lan_if_status != NULL && cJSON_AddStringToObject(response, static_config->lan_if, lan_if_status) == NULL) {  goto end; }
    if (ppp_if_status != NULL && cJSON_AddStringToObject(response, PPP_INTERFACE, ppp_if_status) == NULL) {  goto end; }

    /* Send response
     * We don't need to delete cJSON response
     * because the function will do it for us
     */
    status = http_return_success(response);

    /* Free everything */
    free_minibox_static_config(static_config);
    free_minibox_config(config);
    free(vlan_if);
    free(base_if_status);
    free(ppp_if_status);
    free(vlan_if_status);
    free(lan_if_status);

    return status;
}

int process_get_ipinfo()
{
    int status;
    cJSON *response;
    minibox_ipinfo* ipinfo;

    ipinfo = minibox_get_ipinfo();
    if (ipinfo == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_READ_IPINFO);
        free_minibox_ipinfo(ipinfo);
        return -1;
    }

    response = cJSON_CreateObject();
    if (response == NULL)
    {
end:
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_RESPONSE);
        if (response != NULL) cJSON_Delete(response);
        free_minibox_ipinfo(ipinfo);
        return -1;
    }

    // ReSharper disable once CppDFAConstantConditions
    if (ipinfo->ppp_ip != NULL && cJSON_AddStringToObject(response, "ppp_ip", ipinfo->ppp_ip) == NULL) { goto end;}
    // ReSharper disable once CppDFAConstantConditions
    if (ipinfo->ppp_gw != NULL && cJSON_AddStringToObject(response, "ppp_gw", ipinfo->ppp_gw) == NULL) { goto end;}
    // ReSharper disable once CppDFAConstantConditions
    if (ipinfo->ppp_dns != NULL && cJSON_AddStringToObject(response, "ppp_dns", ipinfo->ppp_dns) == NULL) { goto end;}

    /* Send response
     * We don't need to delete cJSON response
     * because the function will do it for us
     */
    status = http_return_success(response);

    /* Free everything */
    free_minibox_ipinfo(ipinfo);

    return status;
}

/* Here's the real deal because we need to sanitize the input.
 * I hate dealing with user input.
 */
int process_set_config(const cJSON* body)
{
    minibox_config* config;
    int status;

    /* Check if we got a NULL */
    config = json_get_config(body);
    if (config == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_READ_CONFIG);
        free_minibox_config(config);
        return -1;
    }

    status = minibox_set_config(config);
    if (status < 0)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_SET_CONFIG);
        free_minibox_config(config);
        return -1;
    }

    status = http_return_success(NULL);

    /* Free what we need */
    free_minibox_config(config);

    return status;
}

int process_change_password(const cJSON* body)
{
    webapi_userinfo* userinfo;
    int status;

    userinfo = json_get_userinfo(body);
    if (userinfo == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_BODY);
        free(userinfo);
        return -1;
    }

    /* Check if user exists */
    if (!is_valid_user(userinfo->username))
    {
        http_return_error(HTTP_NOT_FOUND, MSG_API_USER_NOT_FOUND);
        free(userinfo);
        return -1;
    }

    status = minibox_set_password(userinfo->username, userinfo->password);
    if (status < 0)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_SET_PASSWORD);
        free(userinfo);
        return -1;
    }
    status = http_return_success(NULL);
    free(userinfo);

    return status;
}

int process_restart()
{
    int status;

#ifndef NDEBUG
    fprintf(stderr, "DBG: Simulating restart!\n");
#else
    /* Now we are doing the real thing */
    /* We assume that /usr/sbin/reboot exists and is executable */
    pid_t pid;

    /* Fork ourselves! */
    pid = fork();

    /* If something went wrong */
    if (pid < 0)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_FORK);
        return -1;
    }

    /* If we are the child */
    if (pid == 0)
    {
        /* Detach from the process group */
        setsid();

        /* Sleep for one second to be safe */
        sleep(1);

        /* Execute the reboot binary */
        execlp("/usr/sbin/reboot", "reboot", "-d", "5", NULL);

        /* If we got here, something went REALLY wrong */
        fprintf(stderr, "execlp failed: %s\n", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    /* If we are the parent, we have plenty of time to exit */

#endif
    minibox_create_shutdown_flag();
    status = http_return_success(NULL);
    return status;
}

int process_shutdown()
{
    int status;
#ifndef NDEBUG
    fprintf(stderr, "DBG: Simulating poweroff!\n");
#else
    /* Now we are doing the real thing */
    /* We assume that /usr/sbin/poweroff exists and is executable */
    pid_t pid;

    /* Fork ourselves! */
    pid = fork();

    /* If something went wrong */
    if (pid < 0)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_FORK);
        return -1;
    }

    /* If we are the child */
    if (pid == 0)
    {
        /* Detach from the process group */
        setsid();

        /* Sleep for one second to be safe */
        sleep(1);

        /* Execute the poweroff binary */
        execlp("/usr/sbin/poweroff", "poweroff", "-d", "5", NULL);

        /* If we got here, something went REALLY wrong */
        fprintf(stderr, "execlp failed: %s\n", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    /* If we are the parent, we have plenty of time to exit */

#endif
    minibox_create_shutdown_flag();
    status = http_return_success(NULL);
    return status;
}

/* This function does not return anything */
void http_return_error(const int code, const char* message)
{
    cJSON* json_message;
    char* serialized_message;

    /* Throw generic error if no message specified */
    if (message == NULL)
        message = "Unknown error occurred.";

    /* We need to make sure if we got valid json message */
    json_message = json_prepare_error_message(message);
    if (json_message == NULL)
    {
        printf("HTTP/1.1 %d %s\r\n", HTTP_INTERNAL_SERVER_ERROR, HTTP_STATUS(HTTP_INTERNAL_SERVER_ERROR));
        printf("Content-type: application/json\r\n\r\n");
        printf("{\"status\": \"error\", \"message\":\"%s\"}", MSG_FATAL_ERROR_FATAL_ERROR);
        fflush(stdout);
        return;
    }

    serialized_message = cJSON_Print(json_message);
    if (serialized_message == NULL)
    {
        printf("HTTP/1.1 %d %s\r\n", HTTP_INTERNAL_SERVER_ERROR, HTTP_STATUS(HTTP_INTERNAL_SERVER_ERROR));
        printf("Content-type: application/json\r\n\r\n");
        printf("{\"status\": \"error\", \"message\":\"%s\"}", MSG_FATAL_ERROR_FATAL_ERROR);
        fflush(stdout);
        return;
    }

    printf("HTTP/1.1 %d %s\r\n", code, HTTP_STATUS(code));
    printf("Content-type: application/json\r\n\r\n");
    printf("%s\n", serialized_message);
    fflush(stdout);

    /* We are responsible for cJSON and serialized message freeing */
    free(serialized_message);
    cJSON_Delete(json_message);
}

/* This function return 0 if successfully sent and -1 if error'ed
 * Also this function deletes data cJSON at the end
 */
int http_return_success(cJSON* data)
{
    cJSON* response;
    char* serialized_response;

    /* We need to make sure if we got valid json message
     * before everything else.
     */
    response = json_prepare_success(data);
    if (response == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_SUCCESS_MSG);
        return -1;
    }

    serialized_response = cJSON_Print(response);
    if (serialized_response == NULL)
    {
        http_return_error(HTTP_INTERNAL_SERVER_ERROR, MSG_FATAL_ERROR_SUCCESS_MSG);
        return -1;
    }

    /* Send the response */
    printf("HTTP/1.1 %d %s\r\n", HTTP_OK, HTTP_STATUS(HTTP_OK));
    printf("Content-type: application/json\r\n\r\n");
    printf("%s\n", serialized_response);
    fflush(stdout);

    /* We are responsible for cJSON and serialized message freeing */
    free(serialized_response);
    cJSON_Delete(response);

    return 0;
}

int http_validate_token_header()
{
    const char* token_header;

    token_header = getenv("HTTP_X_MINIBOX_AUTH");
    if (token_header == NULL)
    {
        webapi_errno = TOKEN_INVALID;
        return -1;
    }

    return minibox_verify_token(token_header);
}

/* Erases password from memory */
void json_erase_password(const cJSON* body)
{
    if (cJSON_HasObjectItem(body, "data") &&
        cJSON_HasObjectItem(cJSON_GetObjectItem(body,"data"), "password") &&
        cJSON_GetObjectItem(cJSON_GetObjectItem(body,"data"), "password")->valuestring != NULL)
        crypto_wipe(cJSON_GetObjectItem(cJSON_GetObjectItem(body,"data"), "password")->valuestring,
            strlen(cJSON_GetObjectItem(cJSON_GetObjectItem(body,"data"), "password")->valuestring));
}

cJSON* json_prepare_error_message(const char* message)
{
    cJSON* root;

    root = cJSON_CreateObject();
    if (root == NULL)
    {
        webapi_errno = JSON_CREATION_FAILED;
        return NULL;
    }

    if (cJSON_AddStringToObject(root, "status", "error") == NULL)
    {
        webapi_errno = JSON_CREATION_FAILED;
        cJSON_Delete(root);
        return NULL;
    }

    if (cJSON_AddStringToObject(root, "message", message) == NULL)
    {
        webapi_errno = JSON_CREATION_FAILED;
        cJSON_Delete(root);
        return NULL;
    }

    return root;
}

/* Specified data WILL BE now owned by the success JSON, so cJSON_Delete() WILL delete it! */
cJSON* json_prepare_success(cJSON* data)
{
    cJSON* root;

    root = cJSON_CreateObject();
    if (root == NULL)
    {
        webapi_errno = JSON_CREATION_FAILED;
        return NULL;
    }

    if (cJSON_AddStringToObject(root, "status", "success") == NULL)
    {
        webapi_errno = JSON_CREATION_FAILED;
        cJSON_Delete(root);
        return NULL;
    }

    /* If we got NULL data, we make an empty object */
    if (data == NULL)
    {
        cJSON_AddItemToObject(root, "data", cJSON_CreateObject());
        return root;
    }

    if (cJSON_AddItemToObject(root, "data", data) == 0)
    {
        webapi_errno = JSON_CREATION_FAILED;
        cJSON_Delete(root);
        return NULL;
    }

    return root;
}

/* Fetches http body from stdin and returns it as cJSON */
cJSON* json_fetch_http_body(void)
{
    char* stdined_body;
    size_t content_length;
    cJSON* root;

    /* Fetch info about content length */
    content_length = (size_t)strtol(getenv("CONTENT_LENGTH"), NULL, 0);
    if (content_length <= 0 || content_length > 1024 * 1024)
    {
        webapi_errno = HTTP_BODY_MALFORMED;
        return NULL;
    }

    /* Calloc and read what we need */
    stdined_body = (char*)malloc(content_length+1);
    if (stdined_body == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(stdined_body);
        return NULL;
    }

    while (fread(stdined_body, 1, content_length, stdin) != content_length) {}
    stdined_body[content_length] = '\0';

    /* Parse as JSON */
    root = cJSON_Parse(stdined_body);
    if (root == NULL)
    {
        free(stdined_body);
        webapi_errno = JSON_MALFORMED;
        return NULL;
    }

    /* Free our pointer */
    free(stdined_body);

    return root;
}

const char* json_get_action(const cJSON* body)
{
    cJSON* action;

    if (!cJSON_HasObjectItem(body, "action"))
    {
        webapi_errno = JSON_MISSING_FIELD;
        return NULL;
    }

    action = cJSON_GetObjectItemCaseSensitive(body, "action");
    if (!cJSON_IsString(action) || action->valuestring == NULL)
    {
        webapi_errno = JSON_MALFORMED;
        return NULL;
    }

    return action->valuestring;
}

/* Fetches userinfo from JSON, user need to deallocate it using free() */
webapi_userinfo* json_get_userinfo(const cJSON* body)
{
    webapi_userinfo* userinfo;
    const cJSON* data;
    const cJSON* username;
    const cJSON* password;

    userinfo = (webapi_userinfo*)malloc(sizeof(webapi_userinfo));
    if (userinfo == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(userinfo);
        return NULL;
    }

    if (!cJSON_HasObjectItem(body, "data"))
    {
        webapi_errno = JSON_MISSING_FIELD;
        free(userinfo);
        return NULL;
    }

    data = cJSON_GetObjectItemCaseSensitive(body, "data");
    if (!cJSON_IsObject(data) || data->child == NULL)
    {
        webapi_errno = JSON_MALFORMED;
        free(userinfo);
        return NULL;
    }

    if (!cJSON_HasObjectItem(data, "username") || !cJSON_HasObjectItem(data, "password"))
    {
        webapi_errno = JSON_MISSING_FIELD;
        free(userinfo);
        return NULL;
    }

    username = cJSON_GetObjectItemCaseSensitive(data, "username");
    if (!cJSON_IsString(username) || username->valuestring == NULL)
    {
        webapi_errno = JSON_MALFORMED;
        free(userinfo);
        return NULL;
    }

    password = cJSON_GetObjectItemCaseSensitive(data, "password");
    if (!cJSON_IsString(password) || password->valuestring == NULL)
    {
        webapi_errno = JSON_MALFORMED;
        free(userinfo);
        return NULL;
    }

    userinfo->username = username->valuestring;
    userinfo->password = password->valuestring;

    return userinfo;
}

/* Deserializes configuration from JSON.
 * It COPIES everything so don't forget to
 * DEALLOCATE returned config struct.
 */
minibox_config* json_get_config(const cJSON* body)
{
    minibox_config* new_config;
    minibox_config* existing_config = NULL;

    cJSON* data;
    const cJSON* use_vlan; const cJSON* vlan_id; const cJSON* vlan_pcp; const cJSON* pppoe_user; const cJSON* pppoe_pass;
    const cJSON* pppoe_service; const cJSON* pppoe_mac; const cJSON* pppoe_mtu; const cJSON* lan_mask; const cJSON* lan_ip;
    const cJSON* lan_dhcp; const cJSON* lan_lease; const cJSON* mangle_ttl;

    /* Prepare everything */
    new_config = (minibox_config*)malloc(sizeof(minibox_config));
    if (new_config == NULL) { webapi_errno = FATAL_ERROR; free_minibox_config(new_config); return NULL; }
    if (!cJSON_HasObjectItem(body, "data")) { webapi_errno = JSON_MISSING_FIELD; free_minibox_config(new_config); return NULL; }

    data = cJSON_GetObjectItemCaseSensitive(body, "data");
    if (!cJSON_IsObject(data) || data->child == NULL) { webapi_errno = JSON_MALFORMED; free_minibox_config(new_config); return NULL; }

    /* Load current config for cherry-picking */
    existing_config = minibox_get_config();

    /* Load every variable */
    use_vlan = cJSON_GetObjectItem(data, "use_vlan");
    if (!cJSON_IsBool(use_vlan))
        if (existing_config != NULL) new_config->use_vlan = existing_config->use_vlan;
        else new_config->use_vlan = DEFAULT_USE_VLAN;
    else
        new_config->use_vlan = use_vlan->valueint;

    vlan_id = cJSON_GetObjectItem(data, "vlan_id");
    if (!cJSON_IsNumber(vlan_id) || (vlan_id->valueint < 0 || vlan_id->valueint > 4096))
        if (existing_config != NULL) new_config->vlan_id = existing_config->vlan_id;
        else new_config->vlan_id = DEFAULT_VLAN_ID;
    else
        new_config->vlan_id = vlan_id->valueint;

    vlan_pcp = cJSON_GetObjectItem(data, "vlan_pcp");
    if (!cJSON_IsNumber(vlan_pcp) || (vlan_pcp->valueint < 0 || vlan_pcp->valueint > 7))
        if (existing_config != NULL) new_config->vlan_pcp = existing_config->vlan_pcp;
        else new_config->vlan_pcp = DEFAULT_VLAN_PCP;
    else
        new_config->vlan_pcp = vlan_pcp->valueint;

    /* We are copying strings to avoid memory corruptions */
    pppoe_user = cJSON_GetObjectItem(data, "pppoe_user");
    if (!cJSON_IsString(pppoe_user) || pppoe_user->valuestring == NULL)
    {
        if (existing_config != NULL)
            new_config->pppoe_user = strndup(existing_config->pppoe_user, 256);
        else
            new_config->pppoe_user = DEFAULT_PPPOE_USER;
    }
    else
        new_config->pppoe_user = strndup(pppoe_user->valuestring, 256);

    /* We are copying strings to avoid memory corruptions */
    pppoe_pass = cJSON_GetObjectItem(data, "pppoe_password");
    if (!cJSON_IsString(pppoe_pass) || pppoe_pass->valuestring == NULL)
    {
        if (existing_config != NULL)
            new_config->pppoe_password = strndup(existing_config->pppoe_password, 256);
        else
            new_config->pppoe_password = DEFAULT_PPPOE_PASS;
    }
    else
        new_config->pppoe_password = strndup(pppoe_pass->valuestring, 256);

    pppoe_service = cJSON_GetObjectItem(data, "pppoe_service");
    if (!cJSON_IsString(pppoe_service) || pppoe_service->valuestring == NULL)
    {
        if (existing_config != NULL)
            new_config->pppoe_service = strndup(existing_config->pppoe_service, 256);
        else
            new_config->pppoe_service = DEFAULT_PPPOE_SERVICE;
    }
    else
        new_config->pppoe_service = strndup(pppoe_service->valuestring, 256);

    pppoe_mac = cJSON_GetObjectItem(data, "pppoe_mac");
    if (!cJSON_IsString(pppoe_mac) || pppoe_mac->valuestring == NULL || !is_valid_mac(pppoe_mac->valuestring))
    {
        if (existing_config != NULL)
            new_config->pppoe_mac = strndup(existing_config->pppoe_mac, 256);
        else
            new_config->pppoe_mac = DEFAULT_PPPOE_MAC;
    }
    else
        new_config->pppoe_mac = strndup(pppoe_mac->valuestring, 256);

    pppoe_mtu = cJSON_GetObjectItem(data, "pppoe_mtu");
    if (!cJSON_IsNumber(pppoe_mtu) || pppoe_mtu->valueint <= 0)
        if (existing_config != NULL) new_config->pppoe_mtu = existing_config->pppoe_mtu;
        else new_config->pppoe_mtu = DEFAULT_PPPOE_MTU;
    else
        new_config->pppoe_mtu = pppoe_mtu->valueint;

    lan_mask = cJSON_GetObjectItem(data, "lan_mask");
    if (!cJSON_IsNumber(lan_mask) || (lan_mask->valueint <= 0 || lan_mask->valueint > 32))
        if (existing_config != NULL) new_config->lan_mask = existing_config->lan_mask;
        else new_config->lan_mask = DEFAULT_LAN_MASK;
    else
        new_config->lan_mask = lan_mask->valueint;

    lan_ip = cJSON_GetObjectItem(data, "lan_ip");
    if (!cJSON_IsString(lan_ip) || lan_ip->valuestring == NULL || !is_valid_ip_address(lan_ip->valuestring))
    {
        if (existing_config != NULL)
            new_config->lan_ip = strndup(existing_config->lan_ip, 256);
        else
            new_config->lan_ip = DEFAULT_LAN_IP;
    }
    else
        new_config->lan_ip = strndup(lan_ip->valuestring, 256);

    lan_dhcp = cJSON_GetObjectItem(data, "lan_dhcp");
    if (!cJSON_IsBool(lan_dhcp))
        if (existing_config != NULL) new_config->lan_dhcp = existing_config->lan_dhcp;
        else new_config->lan_dhcp = DEFAULT_LAN_DHCP;
    else
        new_config->lan_dhcp = lan_dhcp->valueint;

    lan_lease = cJSON_GetObjectItem(data, "lan_lease");
    if (!cJSON_IsNumber(lan_lease) || lan_lease->valueint < 0)
        if (existing_config != NULL) new_config->lan_lease = existing_config->lan_lease;
        else new_config->lan_lease = DEFAULT_LAN_LEASE;
    else
        new_config->lan_lease = lan_lease->valueint;

    mangle_ttl = cJSON_GetObjectItem(data, "mangle_ttl");
    if (!cJSON_IsBool(mangle_ttl))
        if (existing_config != NULL) new_config->mangle_ttl = existing_config->mangle_ttl;
        else new_config->mangle_ttl = DEFAULT_MANGLE_TTL;
    else
        new_config->mangle_ttl = mangle_ttl->valueint;


    /* Free everything */
    free_minibox_config(existing_config);

    return new_config;
}

/* Checks if specified username and password are correct
 * Return -1 on failure and 0 on success
 */
int minibox_verify_system_password(const char* username, const char* password)
{
    struct spwd *shadow_entry;
    const char* encrypted;
    char* calulcated_hash;

    shadow_entry = getspnam(username);
    if (shadow_entry == NULL)
        return -1;

    encrypted = shadow_entry->sp_pwdp;
    if (encrypted == NULL || encrypted[0] == '\0' || encrypted[0] == '\0')
        return -1;

    calulcated_hash = crypt(password, encrypted);
    if (calulcated_hash == NULL)
        return -1;

    return crypto_verify32((const uint8_t*)encrypted, (const uint8_t*)calulcated_hash);
}

/* Gets random token for MAC authentication.
 * Generates new if not exist
 * You need to free the token!
 */
uint8_t* minibox_get_session_token()
{
    int fd;
    ssize_t ret;
    uint8_t token[32];
    uint8_t* return_token;

    fd = open(TOKEN_SEED_FILE, O_RDWR | O_CREAT, 0600);
    if (fd < 0)
    {
        webapi_errno = FATAL_ERROR;
        return NULL;
    }
    ret = read(fd, &token[0], sizeof(token));
    /* We got a malformed or not existent token
     * Let's generate new!
     */
    if (ret < 32)
    {
        arc4random_buf(&token[0], sizeof(token));

        ret = write(fd, &token[0], sizeof(token));
        if (ret < 32)
        {
            webapi_errno = FATAL_ERROR;
            close(fd);
            return NULL;
        }

        fsync(fd);
    }

    /* Close the file as we don't need it */
    close(fd);

    return_token = (uint8_t*)malloc(32);
    if (return_token == NULL)
    {
        webapi_errno = FATAL_ERROR;
        return NULL;
    }
    memcpy(return_token, &token[0], sizeof(token));

    return return_token;
}

/* Generates null terminated base64 MAC token */
char* minibox_generate_token(const char* username)
{
    uint8_t* session_token; /* 32 bytes */
    char* message;
    int message_size;
    char* b64_hash;
    time_t current_time;

    /* Get session token */
    session_token = minibox_get_session_token();
    if (session_token == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(session_token);
        return NULL;
    }

    /* Get current time */
    time(&current_time);

    /* Prepare MAC message */
    message = (char*)malloc(1024);
    if (message == NULL)
    {
        webapi_errno = FATAL_ERROR;
        crypto_wipe(session_token, 32);
        free(session_token);
        free(message);
        return NULL;
    }
    message_size = sprintf(message, "%s|%ld|", username, current_time);
    if (message_size < 0)
    {
        webapi_errno = FATAL_ERROR;
        crypto_wipe(session_token, 32);
        free(session_token);
        free(message);
        return NULL;
    }

    /* Generate blake2b hash */
    crypto_blake2b_keyed((uint8_t*)&message[message_size+1], 64,
        session_token, 32,
        (const uint8_t*)message, message_size);

    /* Make b64 hash from it.
     * We are using message + \0 + 512b hash
     */
    b64_hash = b64_encode((const uint8_t*)message, message_size+1+64);

    /* Free everything we allocated */
    crypto_wipe(session_token, 32);
    free(session_token);
    free(message);

    return b64_hash;
}

int minibox_verify_token(const char* token)
{
    uint8_t* decoded_token;
    size_t token_size;
    size_t username_size;
    size_t timestamp_size;

    uint8_t* session_token;
    uint8_t blake_hash[64];
    time_t token_timestamp;
    char* username;

    time_t current_time;
    uint8_t computed_blake_hash[64];
    int validity;

    /* Check if the token we got is good */
    if (token == NULL)
    {
        webapi_errno = TOKEN_INVALID;
        return -1;
    }

    /* Decode and process our token */
    decoded_token = b64_decode_ex(token, strlen(token), &token_size);
    if (token_size == 0 || token_size > 1024*1024)
    {
        webapi_errno = TOKEN_INVALID;
        free(decoded_token);
        return -1;
    }
    for (username_size = 0; decoded_token[username_size] != '|'; username_size++){}
    for (timestamp_size = 0; decoded_token[username_size+1 + timestamp_size] != '|'; timestamp_size++){}

    username = (char*)malloc(username_size+1);
    if (username == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(decoded_token);
        return -1;
    }
    memcpy(username, decoded_token, username_size);
    username[username_size] = '\0';

    if (sscanf((const char*)&decoded_token[username_size], "|%ld|", &token_timestamp) != 1)
    {
        webapi_errno = TOKEN_INVALID;
        free(decoded_token);
        free(username);
        return -1;
    }

    memcpy(&blake_hash[0], &decoded_token[username_size+timestamp_size+3], 64);

    /* Get our session token */
    session_token = minibox_get_session_token();
    if (session_token == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(decoded_token);
        free(username);
        free(session_token);
        return -1;
    }

    /* Get current time */
    time(&current_time);

    /* Check if our token is expired */
    if (current_time-token_timestamp > TOKEN_EXPIRY_TIME)
    {
        webapi_errno = TOKEN_INVALID;
        free(decoded_token);
        free(username);
        crypto_wipe(session_token, 32);
        free(session_token);
        return -1;
    }

    /* Create new blake hash */
    crypto_blake2b_keyed((uint8_t*)&computed_blake_hash[0], 64,
        session_token, 32,
        decoded_token, username_size + 1 + timestamp_size + 1);

    validity = crypto_verify64(computed_blake_hash, blake_hash);

    if (validity != 0)
        webapi_errno = TOKEN_INVALID;

    free(decoded_token);
    free(username);
    crypto_wipe(session_token, 32);
    free(session_token);
    return validity;
}

/* Reads config file from disk or returns default config
 * We are assuming that no one typed something bigger than
 * 256 bytes. PPPoE has a 16-bit TAG_LENGTH field so...
 */
minibox_config* minibox_get_config()
{
    FILE* config_file;
    minibox_config* config;

    char* read_buffer;
    size_t buffer_size = 256;
    int read_characters;
    char* separator;
    char* key;
    char* raw_value;
    char* value;
    size_t value_size;
    int temp_val;

    /* Allocate new config file and fill with default variables */
    config = (minibox_config*)malloc(sizeof(minibox_config));
    if (config == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(config);
        return NULL;
    }
    *config = (minibox_config){
        .use_vlan = DEFAULT_USE_VLAN,
        .vlan_id = DEFAULT_VLAN_ID,
        .vlan_pcp = DEFAULT_VLAN_PCP,
        .pppoe_user = DEFAULT_PPPOE_USER,
        .pppoe_password = DEFAULT_PPPOE_PASS,
        .pppoe_service = DEFAULT_PPPOE_SERVICE,
        .pppoe_mtu = DEFAULT_PPPOE_MTU,
        .pppoe_mac = DEFAULT_PPPOE_MAC,
        .lan_mask = DEFAULT_LAN_MASK,
        .lan_ip = DEFAULT_LAN_IP,
        .lan_dhcp = DEFAULT_LAN_DHCP,
        .lan_lease = DEFAULT_LAN_LEASE,
        .mangle_ttl = DEFAULT_MANGLE_TTL
    };

    /* Open our glorious configuration file */
    config_file = fopen(MINIBOX_CONFIG_FILE, "r");
    if (config_file == NULL)
    {
        webapi_errno = CONFIG_NOT_FOUND;
        return config;
    }

    /* Try to allocate our buffer */
    read_buffer = (char*)malloc(buffer_size);
    if (read_buffer == NULL)
    {
        webapi_errno = FATAL_ERROR;
        fclose(config_file);
        return config;
    }

    /* Try to read our file in loop */
    while ((read_characters = getline(&read_buffer, &buffer_size, config_file)) != EOF)
    {
        /* Skip empty lines */
        if (read_characters <= 1) continue;

        /* getline() has a nasty habbit of leaving the \n character */
        if (read_buffer[read_characters-1] == '\n') read_buffer[--read_characters] = '\0';

        /* Find our separator */
        separator = strchr(read_buffer, '=');
        if (!separator || separator == read_buffer) continue;

        /* Terminate at our separator */
        *separator = '\0';
        key = read_buffer;
        raw_value = separator + 1;

        /* Trim quotes if present */
        value = raw_value;
        value_size = strlen(raw_value);
        if ((raw_value[0] == '\'' || raw_value[0] == '"') && value_size >= 2 && raw_value[value_size - 1] == raw_value[0])
        {
            raw_value[value_size - 1] = '\0';
            value = raw_value + 1;
        }

        /* Parse keys */
        if (strcmp(key, "USE_VLAN") == 0)
        {
            temp_val = atoi(value);
            if (temp_val == 1 || temp_val == 0) config->use_vlan = temp_val;
        }
        else if (strcmp(key, "VLAN_ID") == 0)
        {
            temp_val = atoi(value);
            if (temp_val > 0 && temp_val < 4096) config->vlan_id = temp_val;
        }
        else if (strcmp(key, "VLAN_PCP") == 0)
        {
            temp_val = atoi(value);
            if (temp_val >= 0 && temp_val <= 7) config->vlan_pcp = temp_val;
        }
        else if (strcmp(key, "PPPOE_USER") == 0)
            config->pppoe_user = strdup(value);
        else if (strcmp(key, "PPPOE_PASS") == 0)
            config->pppoe_password = strdup(value);
        else if (strcmp(key, "PPPOE_SERVICE") == 0)
            config->pppoe_service = strdup(value);
        else if (strcmp(key, "PPPOE_MAC") == 0)
            config->pppoe_mac = strdup(value);
        else if (strcmp(key, "PPPOE_MTU") == 0)
            config->pppoe_mtu = atoi(value);
        else if (strcmp(key, "LAN_MASK") == 0)
        {
            temp_val = atoi(value);
            if (temp_val > 0 && temp_val <= 32) config->lan_mask = temp_val;
        }
        else if (strcmp(key, "LAN_IP") == 0)
            config->lan_ip = strdup(value);
        else if (strcmp(key, "LAN_DHCP") == 0)
        {
            temp_val = atoi(value);
            if (temp_val == 1 || temp_val == 0) config->lan_dhcp = temp_val;
        }
        else if (strcmp(key, "LAN_LEASE") == 0)
            config->lan_lease = atoi(value);
        else if (strcmp(key, "MANGLE_TTL") == 0)
        {
            temp_val = atoi(value);
            if (temp_val == 1 || temp_val == 0) config->mangle_ttl = temp_val;
        }
    }

    /* Free everything */
    fclose(config_file);
    free(read_buffer);
    return config;
}

/* We need to know burned PPPoE and LAN base interface names */
minibox_static_config* minibox_get_static_config()
{
    FILE* config_file;
    minibox_static_config* config;

    char* read_buffer;
    size_t buffer_size = 256;
    int read_characters;
    char* separator;
    char* key;
    char* raw_value;
    char* value;
    size_t value_size;

    int got_pppoe_if = 0;
    int got_lan_if = 0;

    /* Allocate new config file and fill with default variables */
    config = (minibox_static_config*)malloc(sizeof(minibox_static_config));
    if (config == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(config);
        return NULL;
    }

    /* Open our glorious configuration file */
    config_file = fopen(MINIBOX_STATIC_FILE, "r");
    if (config_file == NULL)
    {
        webapi_errno = CONFIG_NOT_FOUND;
        return NULL;
    }

    /* Try to allocate our buffer */
    read_buffer = (char*)malloc(buffer_size);
    if (read_buffer == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(config);
        fclose(config_file);
        return NULL;
    }

    /* Try to read our file in loop */
    while ((read_characters = getline(&read_buffer, &buffer_size, config_file)) != EOF)
    {
        /* Skip empty lines */
        if (read_characters <= 1) continue;

        /* getline() has a nasty habbit of leaving the \n character */
        if (read_buffer[read_characters-1] == '\n') read_buffer[--read_characters] = '\0';

        /* Find our separator */
        separator = strchr(read_buffer, '=');
        if (!separator || separator == read_buffer) continue;

        /* Terminate at our separator */
        *separator = '\0';
        key = read_buffer;
        raw_value = separator + 1;

        /* Trim quotes if present */
        value = raw_value;
        value_size = strlen(raw_value);
        if ((raw_value[0] == '\'' || raw_value[0] == '"') && value_size >= 2 && raw_value[value_size - 1] == raw_value[0])
        {
            raw_value[value_size - 1] = '\0';
            value = raw_value + 1;
        }

        /* Parse keys */
        if (strcmp(key, "PPPOE_IF") == 0)
        { config->pppoe_if = strdup(value); got_pppoe_if = 1; }
        else if (strcmp(key, "LAN_IF") == 0)
        { config->lan_if = strdup(value); got_lan_if = 1; }
    }

    /* Free everything */
    fclose(config_file);
    free(read_buffer);

    if (got_pppoe_if && got_lan_if)
        return config;

    free(config->pppoe_if);
    free(config->lan_if);
    free(config);
    return NULL;
}

char* minibox_get_interface_status(const char* interface)
{
    FILE* interface_file;
    char* interface_operstate_path;
    char* read_buffer;
    size_t buffer_size = 256;

    /* Try to allocate and write interface path */
    interface_operstate_path = (char*)malloc(buffer_size);
    if (interface_operstate_path == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(interface_operstate_path);
        return NULL;
    }
#ifndef NDEBUG
    sprintf(interface_operstate_path, "/tmp/class/net/%s/operstate", interface);
#else
    sprintf(interface_operstate_path, "/sys/class/net/%s/operstate", interface);
#endif

    /* Open our glorious configuration file */
    interface_file = fopen(interface_operstate_path, "r");
    if (interface_file == NULL)
    {
        webapi_errno = IF_NOT_FOUND;
        free(interface_operstate_path);
        return NULL;
    }

    /* Try to allocate our buffer */
    read_buffer = (char*)malloc(buffer_size);
    if (read_buffer == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(read_buffer);
        free(interface_operstate_path);
        fclose(interface_file);
        return NULL;
    }

    /* Read interface status */
    while (getline(&read_buffer, &buffer_size, interface_file) != EOF) {}
    if (read_buffer[strlen(read_buffer) - 1] == '\n') read_buffer[strlen(read_buffer) - 1] = '\0';

    fclose(interface_file);
    free(interface_operstate_path);
    return read_buffer;
}

/* Get PPPoE provided IP, gateway and DNS */
minibox_ipinfo* minibox_get_ipinfo()
{
    FILE* info_file;
    minibox_ipinfo* ipinfo;

    char* read_buffer;
    size_t buffer_size = 256;
    int read_characters;
    char* separator;
    char* key;
    char* raw_value;
    char* value;
    size_t value_size;

    /* Allocate new config file */
    ipinfo = (minibox_ipinfo*)malloc(sizeof(minibox_ipinfo));
    if (ipinfo == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(ipinfo);
        return NULL;
    }
    ipinfo->ppp_dns = NULL; ipinfo->ppp_ip = NULL; ipinfo->ppp_gw = NULL;

    /* Open our glorious configuration file */
    info_file = fopen(MINIBOX_DYNAMIC_FILE, "r");
    if (info_file == NULL)
    {
        webapi_errno = CONFIG_NOT_FOUND;
        free(ipinfo);
        return NULL;
    }

    /* Try to allocate our buffer */
    read_buffer = (char*)malloc(buffer_size);
    if (read_buffer == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(ipinfo);
        fclose(info_file);
        return NULL;
    }

    /* Try to read our file in loop */
    while ((read_characters = getline(&read_buffer, &buffer_size, info_file)) != EOF)
    {
        /* Skip empty lines */
        if (read_characters <= 1) continue;

        /* getline() has a nasty habbit of leaving the \n character */
        if (read_buffer[read_characters-1] == '\n') read_buffer[--read_characters] = '\0';

        /* Find our separator */
        separator = strchr(read_buffer, '=');
        if (!separator || separator == read_buffer) continue;

        /* Terminate at our separator */
        *separator = '\0';
        key = read_buffer;
        raw_value = separator + 1;

        /* Trim quotes if present */
        value = raw_value;
        value_size = strlen(raw_value);
        if ((raw_value[0] == '\'' || raw_value[0] == '"') && value_size >= 2 && raw_value[value_size - 1] == raw_value[0])
        {
            raw_value[value_size - 1] = '\0';
            value = raw_value + 1;
        }

        /* Parse keys */
        if (strcmp(key, "PPP_IP") == 0)
            ipinfo->ppp_ip = strdup(value);
        else if (strcmp(key, "PPP_GW") == 0)
            ipinfo->ppp_gw = strdup(value);
        else if (strcmp(key, "PPP_DNS") == 0)
            ipinfo->ppp_dns = strdup(value);
    }

    /* Free everything */
    fclose(info_file);
    free(read_buffer);

    return ipinfo;
}

/* This is much easier than reading tbh
 * We just need to pop this bad boy into the file
 */
int minibox_set_config(const minibox_config* new_config)
{
    FILE* config_file;
    int written;

    config_file = fopen(MINIBOX_NEW_CONFIG_FILE, "w");
    if (config_file == NULL)
    {
        webapi_errno = FATAL_ERROR;
        free(config_file);
        return -1;
    }

    /* Now we just need to dump everything to the file
     * We are also assuming that everything is fine at this point
     */
    /*
     * USE_VLAN=1/0
     * VLAN_ID=35
     * VLAN_PCP=0 // 0 means disabled
     * PPPOE_USER='' // Need to escape using ''
     * PPPOE_PASS='' // Need to escape
     * PPPOE_SERVICE='' // Need to escape
     * PPPOE_MAC='' // Need to escape, empty means no change
     * PPPOE_MTU=1492
     * LAN_MASK=32
     * LAN_IP='203.0.113.113'
     * LAN_DHCP=1/0
     * LAN_LEASE=60
     * MANGLE_TTL=1
     */
    written = fprintf(config_file,
        "USE_VLAN=%d\n"
        "VLAN_ID=%d\n"
        "VLAN_PCP=%d\n"
        "PPPOE_USER=\'%s\'\n"
        "PPPOE_PASS=\'%s\'\n"
        "PPPOE_SERVICE=\'%s\'\n"
        "PPPOE_MTU=%d\n"
        "PPPOE_MAC=\'%s\'\n"
        "LAN_MASK=%d\n"
        "LAN_IP=\'%s\'\n"
        "LAN_DHCP=%d\n"
        "LAN_LEASE=%d\n"
        "MANGLE_TTL=%d\n",
        new_config->use_vlan, new_config->vlan_id, new_config->vlan_pcp,
        new_config->pppoe_user, new_config->pppoe_password,
        new_config->pppoe_service, new_config->pppoe_mtu, new_config->pppoe_mac,
        new_config->lan_mask, new_config->lan_ip,
        new_config->lan_dhcp, new_config->lan_lease,
        new_config->mangle_ttl);

    /* Flush all disk buffers */
    fflush(config_file);

    /* Now we close the file and exit */
    fclose(config_file);

    return written > 0 ? 0 : -1;
}

int minibox_set_password(const char* username, const char* password)
{
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) != 0)
        return -1;

    /* Fork ourselves */
    pid = fork();
    if (pid < 0)
        return -1;

    /* Child process changes password */
    if (pid == 0)
    {
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        execlp("/usr/sbin/chpasswd", "chpasswd", "-m", NULL);
        perror("execlp");
        exit(1);
    }

    /* Parent writes password to the pipe */
    close(pipefd[0]);
    dprintf(pipefd[1], "%s:%s\n", username, password);
    close(pipefd[1]);

    int status;
    waitpid(pid, &status, 0);

    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int minibox_create_shutdown_flag()
{
    int fd;

    fd = open(SHUTDOWN_FLAG_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        webapi_errno = FATAL_ERROR;
        return -1;
    }

    if (write(fd, "1", 1) != 1)
    {
        webapi_errno = FATAL_ERROR;
        close(fd);
        return -1;
    }

    fsync(fd);

    close(fd);
    return 0;
}