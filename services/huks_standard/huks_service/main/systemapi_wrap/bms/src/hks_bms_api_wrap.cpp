/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_bms_api_wrap.h"

#include <cJSON.h>
#include <cstring>
#include <unistd.h>
#include "securec.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "hap_token_info.h"
#include "bundle_mgr_client.h"
#include "bundle_info.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#define SYSTEM_BASIC "system_basic"
#define SYSTEM_CORE "system_core"

using namespace OHOS;
using namespace Security::AccessToken;

static int32_t ConvertCallerInfoToJson(const std::string &idStr, const std::string &extendStr, HksBlob *outInfo,
    bool isHap)
{
    cJSON *jsonObj = cJSON_CreateObject();
    HKS_IF_NULL_LOGE_RETURN(jsonObj, HKS_ERROR_NULL_POINTER, "create cjson object failed.")

    const char *jsonKeyId;
    const char *jsonKeyExtend;
    if (isHap) {
        jsonKeyId = "appId";
        jsonKeyExtend = "bundleName";
    } else {
        jsonKeyId = "processName";
        jsonKeyExtend = "APL";
    }
    if ((cJSON_AddStringToObject(jsonObj, jsonKeyId, idStr.c_str()) == nullptr) ||
        (cJSON_AddStringToObject(jsonObj, jsonKeyExtend, extendStr.c_str()) == nullptr)) {
        HKS_LOG_E("add string to json object is failed.");
        cJSON_Delete(jsonObj);
        return HKS_ERROR_NULL_POINTER;
    }

    char *jsonStr = cJSON_PrintUnformatted(jsonObj);
    if (jsonStr == nullptr) {
        HKS_LOG_E("cJSON_PrintUnformatted failed.");
        cJSON_Delete(jsonObj);
        return HKS_ERROR_NULL_POINTER;
    }

    outInfo->size = strlen(jsonStr);
    outInfo->data = (uint8_t *)jsonStr;
    cJSON_Delete(jsonObj);
    return HKS_SUCCESS;
}

enum HksCallerType HksGetCallerType(void)
{
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    switch (AccessTokenKit::GetTokenTypeFlag(callingTokenId)) {
        case ATokenTypeEnum::TOKEN_HAP:
            return HKS_HAP_TYPE;
        case ATokenTypeEnum::TOKEN_NATIVE:
        case ATokenTypeEnum::TOKEN_SHELL:
            return HKS_SA_TYPE;
        default:
            return HKS_UNIFIED_TYPE;
    }
}

int32_t HksGetHapInfo(const struct HksProcessInfo *processInfo, struct HksBlob *hapInfo)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(hapInfo, HKS_ERROR_NULL_POINTER, "hapInfo is nullptr.")

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) != ATokenTypeEnum::TOKEN_HAP) {
        HKS_LOG_E("caller is not from hap, not support to get hap info.");
        return HKS_ERROR_NOT_SUPPORTED;
    }

    HapTokenInfo hapTokenInfo;
    int32_t callingResult = AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
    if (callingResult != HKS_SUCCESS) {
        HKS_LOG_E("Get hap info failed from access token kit.");
        return HKS_ERROR_BAD_STATE;
    }

    AppExecFwk::BundleInfo bundleInfo;
    AppExecFwk::BundleMgrClient client;
    bool isGetInfoSuccess = client.GetBundleInfo(hapTokenInfo.bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_HASH_VALUE, bundleInfo, processInfo->userIdInt);
    if (!isGetInfoSuccess) {
        HKS_LOG_E("GetBundleInfo failed.");
        return HKS_ERROR_BAD_STATE;
    }

    // The appid is concatenated from the bundle name and the developer's public key certificate.
    int32_t ret = ConvertCallerInfoToJson(bundleInfo.appId, hapTokenInfo.bundleName, hapInfo, true);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ConvertHapInfoToJson failed.")

    return HKS_SUCCESS;
}

static int32_t HksGetHapPkgName(const struct HksProcessInfo *processInfo, struct HksBlob *hapPkgName)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(hapPkgName, HKS_ERROR_NULL_POINTER, "hapPkgName is nullptr.")

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) != ATokenTypeEnum::TOKEN_HAP) {
        HKS_LOG_E("caller is not from hap, not support to get hap info.");
        return HKS_ERROR_NOT_SUPPORTED;
    }

    HapTokenInfo hapTokenInfo;
    int32_t callingResult = AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
    if (callingResult != HKS_SUCCESS) {
        HKS_LOG_E("Get hap info failed from access token kit.");
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t size = strlen(hapTokenInfo.bundleName.c_str());
    uint8_t *pkgName = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_LOGE_RETURN(pkgName, HKS_ERROR_MALLOC_FAIL, "malloc for pkgName failed.")

    (void)memcpy_s(pkgName, size, hapTokenInfo.bundleName.c_str(), size);

    hapPkgName->size = size;
    hapPkgName->data = pkgName;
    return HKS_SUCCESS;
}

int32_t HksGetSaInfo(const struct HksProcessInfo *processInfo, struct HksBlob *saInfo)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(saInfo, HKS_ERROR_NULL_POINTER, "saInfo is nullptr.")

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) == ATokenTypeEnum::TOKEN_HAP) {
        HKS_LOG_E("Error caller Type, cannot get SaInfo");
        return HKS_ERROR_NOT_SUPPORTED;
    }
    NativeTokenInfo saTokenInfo;
    int32_t ret = AccessTokenKit::GetNativeTokenInfo(callingTokenId, saTokenInfo);
    if (ret != AccessTokenKitRet::RET_SUCCESS) {
        HKS_LOG_E("Get sa info failed from access token kit.");
        return HKS_ERROR_BAD_STATE;
    }

    if (saTokenInfo.apl == ATokenAplEnum::APL_SYSTEM_BASIC) {
        ret = ConvertCallerInfoToJson(saTokenInfo.processName, SYSTEM_BASIC, saInfo, false);
    } else if (saTokenInfo.apl == ATokenAplEnum::APL_SYSTEM_CORE) {
        ret = ConvertCallerInfoToJson(saTokenInfo.processName, SYSTEM_CORE, saInfo, false);
    } else {
        HKS_LOG_E("The normal process, hide the caller information.");
        ret = ConvertCallerInfoToJson("", "", saInfo, false);
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ConvertSaInfoToJson failed.")
    return HKS_SUCCESS;
}

static int32_t HksGetSaProcessName(const struct HksProcessInfo *processInfo, struct HksBlob *saProcessName)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(saProcessName, HKS_ERROR_NULL_POINTER, "saProcessName is nullptr.")

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) == ATokenTypeEnum::TOKEN_HAP) {
        HKS_LOG_E("Error caller Type, cannot get SaInfo");
        return HKS_ERROR_NOT_SUPPORTED;
    }
    NativeTokenInfo saTokenInfo;
    int32_t ret = AccessTokenKit::GetNativeTokenInfo(callingTokenId, saTokenInfo);
    if (ret != AccessTokenKitRet::RET_SUCCESS) {
        HKS_LOG_E("Get sa info failed from access token kit.");
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t size = strlen(saTokenInfo.processName.c_str());
    uint8_t *processName = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_LOGE_RETURN(processName, HKS_ERROR_MALLOC_FAIL, "malloc for processName failed.")

    (void)memcpy_s(processName, size, saTokenInfo.processName.c_str(), size);

    saProcessName->size = size;
    saProcessName->data = processName;
    return HKS_SUCCESS;
}

int32_t GetCallerName(const struct HksProcessInfo *processInfo, struct HksBlob *appInfo)
{
    int32_t ret;
    enum HksCallerType appidType = HksGetCallerType();
    if (appidType == HKS_HAP_TYPE) {
        ret = HksGetHapPkgName(processInfo, appInfo);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksGetHapPkgName failed")
    } else if (appidType == HKS_SA_TYPE) {
        ret = HksGetSaProcessName(processInfo, appInfo);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksGetSaProcessName failed")
    } else {
        HKS_LOG_E("invalid appidType!");
        return HKS_ERROR_BAD_STATE;
    }
    return ret;
}