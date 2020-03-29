#include <stdio.h>
#include <string.h>

#include "esp_idf_version.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"


#if (ESP_IDF_VERSION_MAJOR >= 4) //Check esp-idf version >= 4

#if (ESP_IDF_VERSION_MINOR > 0)
#include "esp_netif.h"
#else
#include "tcpip_adapter.h"
#endif // ESP_IDF_VERSION_MINOR

#endif // ESP_IDF_VERSION_MAJOR >= 4
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "lwip/dhcp6.h"

#include "softAPConfig.h"

static const char *TAG = "hap.app.softAPConfig.main";

typedef struct _APP_main_context
{
    bool softAPConfigStatus;


} appMainContext;

appMainContext *context = NULL;

/*Private Functions define*/
void event_handler(void* pvArg, esp_event_base_t pvEventBase,  int32_t pvEventId, void* pvEventData);
/* Private functions */
void event_handler(void* pvArg, esp_event_base_t pvEventBase,  int32_t pvEventId, void* pvEventData)
{
    if (pvEventBase == WIFI_EVENT)
    {
        switch (pvEventId)
        {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "WIFI_EVENT -> WIFI_EVENT_STA_START");

                if (context->softAPConfigStatus == false)
                {
                    softAPConfigStart();
                    context->softAPConfigStatus = true;
                }
                break;
            case WIFI_EVENT_STA_CONNECTED:
                ESP_LOGI(TAG, "WIFI_EVENT -> WIFI_EVENT_STA_CONNECTED");

                if (context->softAPConfigStatus)
                {
                    softAPConfigStop();
                    context->softAPConfigStatus = false;
                }
                break;
            case WIFI_EVENT_STA_DISCONNECTED:
                ESP_LOGI(TAG, "WIFI_EVENT -> WIFI_EVENT_STA_DISCONNECTED");

                break;
            case WIFI_EVENT_STA_STOP:
                ESP_LOGI(TAG, "WIFI_EVENT -> WIFI_EVENT_STA_STOP.");

                break;
            default:
                break;
        }

    }
    else if (pvEventBase == SAC_EVENT)
    {
        switch (pvEventId)
        {
            case SAC_EVENT_GOT_SSID_PSWD:
                ESP_LOGI(TAG, "SAC_EVENT -> SAC_EVENT_GOT_SSID_PSWD");
                ESP_LOGI(TAG, "Got ssid and password.");

                softapconfig_event_got_ssid_pswt_t *pEvtData = (softapconfig_event_got_ssid_pswt_t *)pvEventData;
                wifi_config_t pWifiConfigSTA;

                bzero(&pWifiConfigSTA, sizeof(wifi_config_t));

                memcpy(pWifiConfigSTA.sta.ssid, pEvtData->ssid, sizeof(pWifiConfigSTA.sta.ssid));
                memcpy(pWifiConfigSTA.sta.password, pEvtData->pswd, sizeof(pWifiConfigSTA.sta.password));
                pWifiConfigSTA.sta.bssid_set = pEvtData->isSetBSSID;
                if (pWifiConfigSTA.sta.bssid_set == true)
                {
                    memcpy(pWifiConfigSTA.sta.bssid, pEvtData->bssid, sizeof(pWifiConfigSTA.sta.bssid));
                }
                
                ESP_ERROR_CHECK( esp_wifi_disconnect() );
                ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &pWifiConfigSTA) );
                ESP_ERROR_CHECK( esp_wifi_connect() );

                //softAPConfigStop();
                break;
            default:
                break;
        }
    }
    else if (pvEventBase == IP_EVENT)
    {
        switch (pvEventId)
        {
        case IP_EVENT_STA_GOT_IP:
            ESP_LOGI(TAG, "IP_EVENT -> IP_EVENT_STA_GOT_IP");
            /** Greate IPv6 local Address fe80:: */
            ESP_ERROR_CHECK(tcpip_adapter_create_ip6_linklocal(WIFI_IF_STA));
            break;
        case IP_EVENT_GOT_IP6:
            ESP_LOGI(TAG, "IP_EVENT -> IP_EVENT_GOT_IP6");
            ip_event_got_ip6_t* event = (ip_event_got_ip6_t *)pvEventData;
            ip6_addr_t *ipv6 = (ip6_addr_t *)&event->ip6_info.ip;
            ESP_LOGI(TAG, "got ipv6:%s", ip6addr_ntoa(ipv6));
            //ESP_LOGI(TAG, "ipv6 addr %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X:", IP6_ADDR_BLOCK1(pAddr6), IP6_ADDR_BLOCK2(pAddr6), IP6_ADDR_BLOCK3(pAddr6), IP6_ADDR_BLOCK4(pAddr6), IP6_ADDR_BLOCK5(pAddr6), IP6_ADDR_BLOCK5(pAddr6), IP6_ADDR_BLOCK7(pAddr6), IP6_ADDR_BLOCK8(pAddr6));
            break;
        case IP_EVENT_STA_LOST_IP:
            ESP_LOGI(TAG, "IP_EVENT -> IP_EVENT_STA_LOST_IP");
            break;
        default:
            break;
        }
    }
}


/* Public functions */
void app_main()
{

#if (ESP_IDF_VERSION_MAJOR == 4)

#if ESP_IDF_VERSION_MINOR > 0 

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);
#else
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());

#endif // ESP_IDF_VERSION_MINOR


#endif // ESP_IDF_VERSION_MAJOR == 4
    
    if (context == NULL)
    {
        context = malloc(sizeof(appMainContext));
        bzero(context, sizeof(appMainContext));
    }
    
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,ESP_EVENT_ANY_ID, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,ESP_EVENT_ANY_ID, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(SAC_EVENT,ESP_EVENT_ANY_ID, &event_handler, NULL));

    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_start() );

    softAPConfigStart();

}