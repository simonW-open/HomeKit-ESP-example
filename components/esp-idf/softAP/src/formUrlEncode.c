
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "formUrlEncode.h"



char *urlUnescape(const char *pvBuffer, size_t pvBufferlength)
{
    int pLength = 0;
    int i = 0, j;
    char *pResult = NULL;

    int ishex(int c)
    {
        c = toupper(c);
        return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F');
    }

    int hexvalue(int c)
    {
        c = toupper(c);
        if ('0' <= c && c<='9')
        {
            return c - '0';
        }
        else
        {
            return c - 'A' + 10;
        }
        
    }

    while (i < pvBufferlength)
    {
        pLength++;
        if (pvBuffer[i] == '%')
        {
            i += 3;
        }
        else
        {
            i++;
        }
        
    }

    pResult = malloc(pLength + 1);
    i = j = 0;

    while (i < pvBufferlength)
    {
        if (pvBuffer[i] == '+')
        {
            pResult[j++] = ' ';
            i++;
        }
        else if (pvBuffer[i] != '%')
        {
            pResult[j++] = pvBuffer[i++];
        }
        else
        {
            if ((i + 2 < pvBufferlength) && ishex(pvBuffer[i + 1]) && ishex(pvBuffer[i + 2]))
            {
                pResult[j++] = hexvalue(pvBuffer[i + 1]) * 16 + hexvalue(pvBuffer[i + 2]);
                i += 3;
            }
            else
            {
                pResult[j++] = pvBuffer[i++];
            }
            
        }
        
    }
    pResult[j] = 0;
    return pResult;
}


formParam *formParamsParse(const char *pvString)
{
    formParam *pParams = NULL;
    formParam *pParam = NULL;
    int i = 0, pos;

    while (1)
    {
        pos = i;
        while (pvString[i] && pvString[i] != '=' && pvString[i] != '&')
        {
            i++;
        }
        if (i == pos)
        {
            i++;
            continue;
        }
        pParam = malloc(sizeof(formParam));
        pParam->name = urlUnescape(pvString + pos, i - pos);
        pParam->value = NULL;
        pParam->next = pParams;

        pParams = pParam;

        if (pvString[i] == '=')
        {
            i++;
            pos = i;
            while (pvString[i] && pvString[i] != '&')
            {
                i++;
            }
            if (i != pos)
            {
                pParam->value = urlUnescape(pvString + pos, i - pos);
            }
            
        }
        if (!pvString[i])
        {
            break;
        }
        
    }
    
    return pParams;

}

formParam *formParamsFind(formParam *pvParams, const char *pvName)
{
    while (pvParams)
    {
        if (!strcmp(pvParams->name, pvName))
        {
            return pvParams;
        }
        pvParams = pvParams->next;
    }

    return NULL;

}

void formParamsFree(formParam *pvParams)
{
    while (pvParams)
    {
        formParam *next = pvParams->next;
        if (pvParams->name)
        {
            free(pvParams->name);
        }
        if (pvParams->value)
        {
            free(pvParams->value);
        }
        free(pvParams);
        pvParams = next;
    }
    
}