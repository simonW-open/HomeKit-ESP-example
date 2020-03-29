#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#if (ESP_IDF_VERSION_MAJOR >= 4) //Check esp-idf version >= 4

#if (ESP_IDF_VERSION_MINOR > 0)
#include "esp_netif.h"
#include "esp_event.h"
#else
#include "tcpip_adapter.h"
#include "esp_event_loop.h"
#endif // ESP_IDF_VERSION_MINOR

#endif // ESP_IDF_VERSION_MAJOR >= 4

#include "sdkconfig.h"
#include "esp_system.h"
#include "esp_wifi.h"


#include "esp_log.h"
#include "sys/param.h"

#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include "esp_http_server.h"

#include "softAPConfig.h"
#include "index.html.h"

#if defined CONFIG_SAC_AP_SSID_PREFIX
#define SAC_AP_SSID_PREFIX CONFIG_SAC_AP_SSID_PREFIX
#else
#error AP SSID prefix not configed!
#endif

#if defined CONFIG_SAC_AP_AUTHMODE_OPEN
#define SAC_AUTHMODE 0
#elif defined CONFIG_SAC_AP_AUTHMODE_WEP
#define SAC_AUTHMODE 1
#define SAC_AUTH_PSWD CONFIG_SAC_AUTH_PSWD
#elif defined CONFIG_SAC_AP_AUTHMODE_WPA_PSK
#define SAC_AUTHMODE 2 //AP auth mode is WIFI_AUTH_WPA_WPA2_PSK
#define SAC_AUTH_PSWD CONFIG_SAC_AUTH_PSWD
#elif defined CONFIG_SAC_AP_AUTHMODE_WPA2_PSK
#define SAC_AUTHMODE 3 //AP auth mode is WIFI_AUTH_WPA_WPA2_PSK
#define SAC_AUTH_PSWD CONFIG_SAC_AUTH_PSWD
#elif defined CONFIG_SAC_AP_AUTHMODE_WPA_WPA2_PSK
#define SAC_AUTHMODE 4 //AP auth mode is WIFI_AUTH_WPA_WPA2_PSK
#define SAC_AUTH_PSWD CONFIG_SAC_AUTH_PSWD
#else
#define SAC_AUTHMODE 0
#endif

ESP_EVENT_DEFINE_BASE(SAC_EVENT);


static const char *TAG = "cmp.softAPconfig";

typedef struct _softAPConfigContext_struct
{


    softapconfig_event_got_ssid_pswt_t *EventData;

    httpd_handle_t httpdServerTaskHandle;
    TaskHandle_t dnsServerTaskHandle;
} softAPConfigContext;
static softAPConfigContext *context = NULL;

wifi_scan_config_t wifiScanConfiguration = {
    .ssid = NULL,
    .bssid = NULL,
    .channel = 0,
    .show_hidden = 1,
};

typedef struct _wifiScan_Infomation_struct
{
    char SSID[33];
    bool IsSecure;
    struct _wifiScan_Infomation_struct *next;
} wifiInfomation;
wifiInfomation *wifi_infomation = NULL;

SemaphoreHandle_t mutexScan;



/* private functions define */
esp_err_t wifiAPConfiguration(void);
void wifiStaScanSSID(void);
void wifiEventHandler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
void getScanRecord(void);

esp_err_t root_get_handler(httpd_req_t *pvRequest);
esp_err_t echo_post_handler(httpd_req_t *pvRequest);
esp_err_t http_404_error_handler(httpd_req_t *pvRequest, httpd_err_code_t err);

httpd_handle_t httpdServerStart(void);
void httpdServerStop(void);

void dnsServerTask(void *args);
TaskHandle_t dnsServerStart(void);
void dnsServerStop(void);


/* private functions */

esp_err_t wifiAPConfiguration(void)
{
    esp_err_t pError = ESP_OK;
    uint8_t pMACAddress[6] = {0};

    ESP_LOGI(TAG, "Starting config softAP mode.");

#if (ESP_IDF_VERSION_MAJOR >= 4) //Check esp-idf version >= 4

#if (ESP_IDF_VERSION_MINOR > 0)
    esp_netif_create_default_wifi_ap();
#else
#include "tcpip_adapter.h"
#endif // ESP_IDF_VERSION_MINOR

#endif // ESP_IDF_VERSION_MAJOR >= 4

    /** Register WIFI_SCAN_DONE event */
    pError = esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE,&wifiEventHandler, NULL);
    if (pError != ESP_OK)
    {
        ESP_LOGE("cmp.softAPConfig.APInit", "Event register faild. Err: %d", pError);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Register 'WIFI_EVENT -> WIFI_EVENT_SCAN_DONE' success.");
    /** Get MAC address */
    pError = esp_wifi_get_mac(WIFI_IF_AP, pMACAddress);

    if (pError != ESP_OK)
    {
        ESP_LOGE("cmp.softAPConfig.APInit", "WiFi is not initialized or invalid interface.");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Got MAC address success.");

    /** Initialize the configuration of AP mode */
    wifi_config_t wifiConfigAP;
    esp_wifi_get_config(WIFI_IF_AP, &wifiConfigAP);
    ESP_LOGI(TAG, "Starting set ssid.");
    /** Setting the SSID of ap mode */
    wifiConfigAP.ap.ssid_len = snprintf(
        (char *)wifiConfigAP.ap.ssid, sizeof(wifiConfigAP.ap.ssid),
        "%s-%02X%02X%02X", SAC_AP_SSID_PREFIX, pMACAddress[3], pMACAddress[4], pMACAddress[5]);
    /** Setting the auth-mode and password of AP mode */
    ESP_LOGI(TAG, "Starting set password.");
    if (SAC_AUTHMODE)
    {
        wifiConfigAP.ap.authmode = SAC_AUTHMODE;
        strcpy((char *) wifiConfigAP.ap.password, SAC_AUTH_PSWD);
    }
    else
    {
        wifiConfigAP.ap.authmode = WIFI_AUTH_OPEN;
    }
    
    /** Setting the WiFi mode to sta/ap */
    ESP_LOGI(TAG, "Starting set ap/sta mode");
    pError = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (pError != ESP_OK)
    {
        ESP_LOGE("cmp.softAPConfig.APInit", "Error setting the wifi mode. err: %d", pError);
        return ESP_FAIL;
    }
    /** Configuring the AP-mode */
    ESP_LOGI(TAG, "Configuring ap mode.");
    pError = esp_wifi_set_config(ESP_IF_WIFI_AP, &wifiConfigAP);
    if (pError != ESP_OK)
    {
        ESP_LOGE("cmp.softSAPConfig.APInit", "Error configuring th AP-mode. err: %d", pError);
        return ESP_FAIL;
    }
    /** Starting softAP */
/*     ESP_LOGI(TAG, "Starting wifi.");
    pError = esp_wifi_start();
    if (pError != ESP_OK)
    {
        ESP_LOGE("cmp.softAPCOnfig.APInit", "Error Starting softAP, err : %d", pError);
        return ESP_FAIL;
    } */
    ESP_LOGI("cmp.softAPConfig.APInit", "Starting AP. the SSID: \"%s\", the auth-mode: \"%d\"", wifiConfigAP.ap.ssid, SAC_AUTHMODE);
    wifiStaScanSSID();
    return ESP_OK;
}

void wifiStaScanSSID(void)
{
    esp_err_t pError;

    /** Clear scan record */

    /** Starting wifi scan */
    pError = esp_wifi_scan_start(&wifiScanConfiguration, true);
    switch (pError)
    {
        case ESP_OK:
            ESP_LOGI("cmp.softAPConfig.scan", "Start scan succeed!");
            xSemaphoreTake(mutexScan,portMAX_DELAY);
            return;
        case ESP_ERR_WIFI_NOT_INIT:
            ESP_LOGE("cmp.softAPConfig.scan", "WiFi is not initialized!");
            return;
        case ESP_ERR_WIFI_NOT_STARTED:
            ESP_LOGE("cmp.softAPConfig.scan", "WiFi was not started!");
            return;
        case ESP_ERR_WIFI_TIMEOUT:
            ESP_LOGE("cmp.softAPConfig.scan", "blocking scan is timeout！");
            return;
        case ESP_ERR_WIFI_STATE:
            ESP_LOGE("cmp.softAPConfig.scan", "wifi still connecting when invoke！");
            return;
        default:
            ESP_LOGE("cmp.softAPConfig.scan", "Unknown error, code :\"%d\"", pError);
            return;
    }

}

void wifiEventHandler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE)
    {
        ESP_LOGI("cmp.softAPConfig.scan", "wifi-scan done, now get the report.");
        getScanRecord();
    }
}

void getScanRecord(void)
{
    uint16_t i;
    uint16_t apScanCount = 0,apCount = 0;
    esp_err_t pResult;

    if (esp_wifi_scan_get_ap_num(&apScanCount) != ESP_OK)
    {
        ESP_LOGE("cmp.softAPConfig.scan", "Wifi scan failed!");
        xSemaphoreGive(mutexScan);
        return;
    }
    if (apScanCount == 0)
    {
        ESP_LOGW("cmp.softAPConfig.scan", "Nothing AP found!");
        xSemaphoreGive(mutexScan);
        return;
    }

    wifi_ap_record_t *list = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * apScanCount); //定义一个wifi_ap_record_t的结构体的链表空间
    //获取上次扫描中找到的AP列表。
    pResult = esp_wifi_scan_get_ap_records(&apScanCount, list);
    switch (pResult)
    {
        case ESP_OK:
            apCount = 0;

            wifiInfomation *wifi_network = wifi_infomation;
            while (wifi_network) 
            {
                wifiInfomation *next = wifi_network->next;
                free(wifi_network);
                wifi_network = next;
            }
            wifi_infomation = NULL;

            //过滤SSID 长度 为0 且RSSI < -75 的 SSID
            for (i = 0; i < apScanCount; i++)
            {
                
                if ((strlen((char *)&list[i].ssid) > 0) && list[i].rssi >= -75)
                {
                    wifiInfomation *net = wifi_infomation;
                     while (net)
                    {
                        if (!strncmp(net->SSID, (char *)&list[i].ssid, sizeof(net->SSID)))
                        {
                            break;
                        }
                        net = net->next;
                    }
                    
                    if (!net)
                    {
                        wifiInfomation *p = malloc(sizeof(wifiInfomation));
                        memset(p, 0, sizeof(*p));
                        strncpy(p->SSID, (char *)&list[i].ssid, sizeof(p->SSID));
                        p->IsSecure = list[i].authmode != WIFI_AUTH_OPEN;
                        p->next = wifi_infomation;

                        wifi_infomation = p;
                        apCount++;
                        printf("%02d - SSID : \"%s\" auch_mode: \"%d\" RSSI: %d \r\n", i, list[i].ssid, list[i].authmode, list[i].rssi);
                    } 
                }
                ESP_LOGD("cmp.softAPConfig.scan","%02d - SSID : \"%s\" auch_mode: \"%d\" RSSI: %d \r\n", i, list[i].ssid, list[i].authmode, list[i].rssi);
            }

            ESP_LOGI("cmp.softAPConfig.scan", "Number of access points found %d\r\n", apCount);

            free(list);
            xSemaphoreGive(mutexScan);
            break;
        case ESP_ERR_WIFI_NOT_INIT:
            break;
        case ESP_ERR_WIFI_NOT_STARTED:
            break;
        default:
            ESP_LOGE(TAG, "Unknow error[%d]", pResult);
            break;
    }
}

/////////////////////////////////////////////////////////////httpd server///////////////////////////////////////////////////////////
/* ptth "/" http-GET handler */
esp_err_t root_get_handler(httpd_req_t *pvRequest)
{
    char *pBuffer;
    size_t pBufferLength = 0;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    pBufferLength = httpd_req_get_hdr_value_len(pvRequest, "Host") + 1;

    if (pBufferLength > 1)
    {
        pBuffer = malloc(pBufferLength);
        memset(pBuffer,0,pBufferLength);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(pvRequest, "Host", pBuffer, pBufferLength) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header -> host: \"%s\"", pBuffer);
        }
        free(pBuffer);
        pBufferLength = 0;
    }


    httpd_resp_sendstr_chunk(pvRequest, html_settings_header);
    httpd_resp_sendstr_chunk(pvRequest, html_settings_body);

    if (xSemaphoreTake(mutexScan, 5000 / portTICK_PERIOD_MS))
    {
        char buffer[64];
        wifiInfomation *net = wifi_infomation;
        while (net)
        {
            snprintf(
                buffer, sizeof(buffer),
                html_network_item, net->IsSecure ? "secure" : "unsecure", net->SSID);
            httpd_resp_sendstr_chunk(pvRequest, buffer);

            net = net->next;
        }
        
        xSemaphoreGive(mutexScan);
    }
    httpd_resp_sendstr_chunk(pvRequest,html_settings_footer);

    /** Scan again */
    //wifiStaScanSSID();

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(pvRequest, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t root = 
{
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

/* An http POST handler */
esp_err_t echo_post_handler(httpd_req_t *pvRequest)
{
    char pBuffer[128] = {0};
    int ret, remaining;
    
    remaining = pvRequest->content_len;

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(pvRequest, pBuffer, MIN(remaining, sizeof(pBuffer)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }
        /* Log data received */
        ESP_LOGI("httpd.uri\"/echo\"","Post received data %.*s", ret, pBuffer);

        char pParamSSID[33];
        bzero(pParamSSID,sizeof(pParamSSID));
        if (httpd_query_key_value(pBuffer, "ssid", pParamSSID, sizeof(pParamSSID)) == ESP_OK)
        {
                ESP_LOGI("httpd.uri\"/echo\"", "Found URL query parameter => ssid=%s", pParamSSID);
                memcpy(context->EventData->ssid, pParamSSID, sizeof(context->EventData->ssid));
        }
        char pParampassword[65];
        bzero(pParampassword,sizeof(pParampassword));
        if (httpd_query_key_value(pBuffer, "password", pParampassword, sizeof(pParampassword)) == ESP_OK)
        {
                ESP_LOGI("httpd.uri\"/echo\"", "Found URL query parameter => password=%s", pParampassword);
                memcpy(context->EventData->pswd, pParampassword, sizeof(context->EventData->pswd));
        }

        httpd_resp_set_status(pvRequest, "204 No Content");
        ESP_LOGI("hap.cmp.httpd", "/echo response send 204!");
        httpd_resp_send_chunk(pvRequest, NULL, 0);

        context->EventData->isSetBSSID = false;

        esp_event_post(SAC_EVENT, SAC_EVENT_GOT_SSID_PSWD, context->EventData, sizeof(softapconfig_event_got_ssid_pswt_t),portMAX_DELAY);
    }

    // End response
    httpd_resp_send_chunk(pvRequest, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t echo = {
    .uri       = "/echo",
    .method    = HTTP_POST,
    .handler   = echo_post_handler,
    .user_ctx  = "<script language=javascript> <!-- this.window.opener = null; window.close(); //--> </script>"
};

esp_err_t http_404_error_handler(httpd_req_t *pvRequest, httpd_err_code_t err)
{
    /* For any other URI send 301 and redirecting to http://192.168.4.1/ */
    const char *pstr = "301 Moved Temporarily\r\nLocation: http://192.168.4.1\r\n";
    httpd_resp_set_status(pvRequest, pstr);
    httpd_resp_send(pvRequest, "pstr", 4);
    
    return ESP_FAIL;
}



httpd_handle_t httpdServerStart(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        httpd_register_uri_handler(server, &root);
        httpd_register_uri_handler(server, &echo);
        httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, http_404_error_handler);
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;    
}


void httpdServerStop(void)
{
    // Stoping the httpd server
    if (context->httpdServerTaskHandle != NULL)
    {
        ESP_LOGI("cmp.softAPConfig.httpd", "Stoping http server!");
        httpd_stop(context->httpdServerTaskHandle);
    }
    
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////DNS Server/////////////////////////////////////////////////////////////
void dnsServerTask(void *args)
{
    ip4_addr_t pServerAddress;
    struct sockaddr_in pSocketAddress;
    struct sockaddr pSrcouseAddress;
    socklen_t pSrcouseAddressLength;
    char pRcvBuffer[96];
    char *pHead;
    size_t pRcvBufferLength, pDNSQueryLength;
    uint32_t pDNSResponseLength, pTaskValue;
    int pFd;

    ESP_LOGI("cmp.softAPConfig.dnsd","Starting DNS server.");

    IP4_ADDR(&pServerAddress, 192, 168, 4, 1);
    pFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    memset(&pSocketAddress, '0', sizeof(pSocketAddress));
    pSocketAddress.sin_family = AF_INET;
    pSocketAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    pSocketAddress.sin_port = htons(53);

    bind(pFd, (struct sockaddr *)&pSocketAddress, sizeof(pSocketAddress));

    const struct timeval timeout = {2, 0}; //2 second timeout
    setsockopt(pFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    const struct ifreq pIfreq = {"en1" };
    setsockopt(pFd, SOL_SOCKET, SO_BINDTODEVICE, &pIfreq, sizeof(pIfreq));

    for (;;)
    {
        pSrcouseAddressLength = sizeof(pSrcouseAddress);
        pRcvBufferLength = recvfrom(pFd, pRcvBuffer, sizeof(pRcvBuffer), 0, (struct sockaddr *)&pSrcouseAddress, &pSrcouseAddressLength);

        /* Drop messages that are too large to send a response in the buffer */
        if (pRcvBufferLength > 0 && pRcvBufferLength <= (sizeof(pRcvBuffer) - 16) && pSrcouseAddress.sa_family == AF_INET)
        {
            pDNSQueryLength = strlen(pRcvBuffer + 12) + 1;
            pDNSResponseLength = 2 + 10 + pDNSQueryLength + 16 + 4;

            pHead = pRcvBuffer + 2;
            *pHead++ = 0x80; // Flags
            *pHead++ = 0x00;
            *pHead++ = 0x00; // Q count
            *pHead++ = 0x01;
            *pHead++ = 0x00; // A count
            *pHead++ = 0x01;
            *pHead++ = 0x00; // Auth count
            *pHead++ = 0x00;
            *pHead++ = 0x00; // Add count
            *pHead++ = 0x00;
            pHead += pDNSQueryLength;
            *pHead++ = 0x00; // Q type
            *pHead++ = 0x01;
            *pHead++ = 0x00; // Q class
            *pHead++ = 0x01;
            *pHead++ = 0xC0; // LBL offs
            *pHead++ = 0x0C;
            *pHead++ = 0x00; // Type
            *pHead++ = 0x01;
            *pHead++ = 0x00; // Class
            *pHead++ = 0x01;
            *pHead++ = 0x00; // TTL
            *pHead++ = 0x00;
            *pHead++ = 0x00;
            *pHead++ = 0x78;
            *pHead++ = 0x00; // RD len
            *pHead++ = 0x04;
            *pHead++ = ip4_addr1(&pServerAddress);
            *pHead++ = ip4_addr2(&pServerAddress);
            *pHead++ = ip4_addr3(&pServerAddress);
            *pHead++ = ip4_addr4(&pServerAddress);

            ESP_LOGD("cmp.softAPConfig.dnsd", "Got DNS Query, sending response");
            sendto(pFd, pRcvBuffer, pDNSResponseLength, 0, &pSrcouseAddress, pSrcouseAddressLength);
        }

        pTaskValue = 0;
        if (xTaskNotifyWait(0, 1, &pTaskValue, 0) == pdTRUE)
        {
            if (pTaskValue)
            {
                break;
            }
        }

    }
    ESP_LOGI("cmp.softAPConfig.dnsd", "Stoping DNS server.");
    lwip_close(pFd);
    //context->dnsServerTaskHandle = NULL;
    vTaskDelete(NULL);
}

TaskHandle_t dnsServerStart(void)
{
    BaseType_t pError = pdPASS;
    TaskHandle_t pTaskHandle = NULL;

    pError =  xTaskCreate(dnsServerTask, "hap.cmp.dns-server.task", 2048, NULL, 2, &pTaskHandle);
    if (pError == pdPASS)
    {
        ESP_LOGI(TAG, "Starting DNS server on port: '53'");
        return pTaskHandle;
    }

    ESP_LOGE(TAG, "Error starting DNS server.");
    return NULL;
}

void dnsServerStop(void)
{
    if (!context->dnsServerTaskHandle)
    {
        ESP_LOGW("cmp.softAPConfig.dnsd", "Error Stopping DNS server, DNS server not running.");
        return;
    }
    xTaskNotify(context->dnsServerTaskHandle, 1, eSetValueWithoutOverwrite);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* Public functions */

esp_err_t softAPConfigStart(void)
{
    size_t pParamLength;
    esp_err_t pError = ESP_OK;

    ESP_LOGI(TAG, "Starting compenont 'softap-config'.");

    if (context != NULL)
    {
        ESP_LOGE(TAG, "context error, not null!");
        return ESP_FAIL;
    }
    //malloc context and set to 0
    context = malloc(sizeof(softAPConfigContext));
    bzero(context, sizeof(softAPConfigContext));
    //malloc eventdata and set to 0
    context->EventData = malloc(sizeof(softapconfig_event_got_ssid_pswt_t));
    bzero(context->EventData, sizeof(softapconfig_event_got_ssid_pswt_t));

    /** Check params */
    //Check AP SSID prefix length
    pParamLength = 0;
    pParamLength = strlen(SAC_AP_SSID_PREFIX);
    if (pParamLength ==0 || pParamLength > 25)
    {
        ESP_LOGE(TAG, "The \"AP SSID prefix\" must be configured and less 25 characters！");
        goto softapstart_chk_err;
    }

    //check AP auth mode and password
    if (SAC_AUTHMODE)
    {
        pParamLength = 0;
        pParamLength = strlen(SAC_AUTH_PSWD);
        if (pParamLength < 8 || pParamLength > 64)
        {
            ESP_LOGE(TAG, "The \"AP password\" must be configured and between 8 and 64 characters！");
            goto softapstart_chk_err;
        }
    }

    /** init mutex */
    mutexScan = xSemaphoreCreateBinary();
    xSemaphoreGive(mutexScan);

    /** Init wifi AP mode */
    pError = wifiAPConfiguration();
    if (pError != ESP_OK)
    {
        ESP_LOGE(TAG, "Error Configuring AP-mode.");
        goto softapstart_err;
    }

    /** Starting HTTP server and DNS server task */
    context->httpdServerTaskHandle = httpdServerStart();
    context->dnsServerTaskHandle   = dnsServerStart();
    if (context->httpdServerTaskHandle == NULL || context->dnsServerTaskHandle == NULL)
    {
        goto softapstart_err;
    }
    
    return ESP_OK;

softapstart_chk_err:
    free(context);
    context = NULL;
    return ESP_ERR_INVALID_ARG;

softapstart_err:
    free(context);
    context = NULL;
    return ESP_FAIL;
}

void softAPConfigStop(void)
{
    if (context != NULL)
    {
        ESP_LOGI(TAG, "Stopping compenont 'softap-config'.");
        /** Stoping dns server */
        dnsServerStop();
        /** Stoping httpd server */
        httpdServerStop();

        /** set wifi mode to sta mode */
        ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );

        if (context->EventData != NULL)
        {
            free(context->EventData);
            context->EventData = NULL;
        }
        free(context);
        context = NULL;
        return;
    }

}