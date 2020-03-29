
#ifndef __COMPONENTS_SOFTAP_CONFIG_H__
#define __COMPONENTS_SOFTAP_CONFIG_H__


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "esp_event_base.h"

/** SoftAPConfig event declarations */
typedef enum 
{
    SAC_EVENT_SCAN_DONW,
    SAC_EVENT_GOT_SSID_PSWD,
} softapconfig_event_t;

/** @brief softAPConfig event base declaration */
ESP_EVENT_DECLARE_BASE(SAC_EVENT);


typedef struct {
    uint8_t ssid[33];
    uint8_t pswd[65];
    bool isSetBSSID;
    uint8_t bssid[6];
} softapconfig_event_got_ssid_pswt_t;


int softAPConfigStart(void);

void softAPConfigStop(void);



#ifdef __cplusplus
}
#endif

#endif /* __COMPONENTS_SOFTAP_CONFIG_H__ */