/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef HKS_UKEY_GLOBAL_ERRINFO_H
#define HKS_UKEY_GLOBAL_ERRINFO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HKS_UKEY_ERROR_DESC_MAX_LEN 256

extern struct HksUkeyGlobalInfo g_ukeyGlobalInfo;
struct HksUkeyGlobalInfo {
    int32_t errVal;
    char errorDesc[HKS_UKEY_ERROR_DESC_MAX_LEN];
};

void HksSetUkeyGlobalInfo(int32_t errVal, const char *errorDesc);

int32_t HksGetUkeyGlobalErrVal(void);

void HksGetUkeyGlobalErrorDesc(char *buf, uint32_t bufLen);

void HksClearUkeyGlobalInfo(void);

// Alias for C API
#define HKS_SET_UKEY_GLOBAL_INFO_C HksSetUkeyGlobalInfo

#define HKS_GET_UKEY_GLOBAL_ERR_VAL_C HksGetUkeyGlobalErrVal

#define HKS_GET_UKEY_GLOBAL_ERR_DESC_C HksGetUkeyGlobalErrorDesc

#define HKS_CLEAR_UKEY_GLOBAL_INFO_C HksClearUkeyGlobalInfo

#ifdef __cplusplus
}
#endif

#endif // HKS_UKEY_GLOBAL_ERRINFO_H