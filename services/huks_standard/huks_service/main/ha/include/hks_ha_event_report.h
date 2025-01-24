#ifndef HKS_HA_EVENT_REPORT_H
#define HKS_HA_EVENT_REPORT_H

#include "hks_plugin_def.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void HksEventReport( const char *funcName, const struct HksProcessInfo *processInfo, 
                        const struct HksParamSet *paramSet, const struct HksParamSet *reportParamSet, int32_t errorCode);

#ifdef __cplusplus
}
#endif
#endif