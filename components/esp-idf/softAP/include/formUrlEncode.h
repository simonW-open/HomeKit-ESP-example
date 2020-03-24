#ifndef __FORM_URL_ENCODE_H__
#define __FORM_URL_ENCODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#pragma once

typedef struct _Form_Param_struct
{
    char *name;
    char *value;

    struct _Form_Param_struct *next;
} formParam;


formParam *formParamsParse(const char *pvString);
formParam *formParamsFind(formParam *pvParams, const char *pvName);
void formParamsFree(formParam *pvParams);



#ifdef __cplusplus
}
#endif

#endif /* __FORM_URL_ENCODE_H__ */