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
#include "securec.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "hap_token_info.h"
#include "bundle_mgr_proxy.h"

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

static sptr<AppExecFwk::IBundleMgr> GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(systemAbilityManager, nullptr, "fail to get system ability mgr.")

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    HKS_IF_NULL_LOGE_RETURN(remoteObject, nullptr,
            "system ability %" LOG_PUBLIC "d is nullptr", BUNDLE_MGR_SERVICE_SYS_ABILITY_ID)
    return iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
}

static int32_t ConvertHapInfoToJson(const std::string &appIdStr, const std::string &bundleNameStr, HksBlob *hapInfo)
{
    if (appIdStr.empty() || bundleNameStr.empty()) {
        HKS_LOG_E("appid and bundle name is nullptr.");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    cJSON *jsonObj = cJSON_CreateObject();
    HKS_IF_NULL_LOGE_RETURN(jsonObj, HKS_ERROR_NULL_POINTER, "create cjson object failed.")

    const char jsonKeyAppId[] = "appId";
    const char jsonKeyBundleName[] = "bundleName";
    if ((cJSON_AddStringToObject(jsonObj, jsonKeyAppId, appIdStr.c_str()) == nullptr) ||
        (cJSON_AddStringToObject(jsonObj, jsonKeyBundleName, bundleNameStr.c_str()) == nullptr)) {
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

    hapInfo->size = strlen(jsonStr);
    hapInfo->data = (uint8_t *)jsonStr;
    cJSON_Delete(jsonObj);
    return HKS_SUCCESS;
}

static int32_t ConvertSaInfoToJson(const std::string &appIdStr, HksBlob *hapInfo, int32_t apl)
{
    if (apl < 1 || apl > 3) {
        HKS_LOG_E("apl level is invaild.");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    cJSON *jsonObj = cJSON_CreateObject();
    HKS_IF_NULL_LOGE_RETURN(jsonObj, HKS_ERROR_NULL_POINTER, "create cjson object failed.")

    const char jsonKeyAppId[] = "processName";
    const char jsonKeyApl[] = "APL";
    const char * aplStr;

    if (apl == 1) {
        aplStr = "";
    } else if (apl == 2) {
        aplStr = SYSTEM_BASIC;
    } else {
        aplStr = SYSTEM_CORE;
    }

    if ((cJSON_AddStringToObject(jsonObj, jsonKeyAppId, appIdStr.c_str()) == nullptr) ||
        (cJSON_AddStringToObject(jsonObj, jsonKeyApl, aplStr) == nullptr)) {
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

    hapInfo->size = strlen(jsonStr);
    hapInfo->data = (uint8_t *)jsonStr;
    cJSON_Delete(jsonObj);
    return HKS_SUCCESS;
}

void HksGetAppIdType(enum HksAppIdType *appIdType) {
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    switch (AccessTokenKit::GetTokenType(callingTokenId)) {
        case ATokenTypeEnum::TOKEN_HAP:
            *appIdType = HKS_HAP_APPID;
            return;
        case ATokenTypeEnum::TOKEN_NATIVE:
        case ATokenTypeEnum::TOKEN_SHELL:
            *appIdType = HKS_SA_APPID;
            return;
        default:
            *appIdType = HKS_UNIFIED_APPID;
            return;
    } 
}

int32_t HksGetHapName(int32_t tokenId, int32_t userId, char *hapName, int32_t hapNameSize)
{
    HapTokenInfo tokenInfo;
    int result = AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo);
    if (result != HKS_SUCCESS) {
        HKS_LOG_I("GetHapTokenInfo failed, tokenId :%" LOG_PUBLIC "d", tokenId);
        return HKS_ERROR_BAD_STATE;
    }

    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        HKS_LOG_E("bundle mgr proxy is nullptr.");
        return HKS_ERROR_BAD_STATE;
    }

    AppExecFwk::BundleInfo bundleInfo;
    bool isGetInfoSuccess = bundleMgrProxy->GetBundleInfo(tokenInfo.bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_HASH_VALUE, bundleInfo, userId);
    if (!isGetInfoSuccess) {
        HKS_LOG_E("GetBundleInfo failed.");
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t hapNameLen = strlen(tokenInfo.bundleName.c_str());
    if (memcpy_s(hapName, hapNameSize, tokenInfo.bundleName.c_str(), hapNameLen) != EOK) {
        HKS_LOG_E("memcpy for hapName failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    HKS_LOG_E("Get hapName success! : %" LOG_PUBLIC "s", hapName);
    return HKS_SUCCESS;
}

int32_t HksGetHapInfo(const struct HksProcessInfo *processInfo, struct HksBlob *hapInfo)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(hapInfo, HKS_ERROR_NULL_POINTER, "hapInfo is nullptr.")

    // if it is not hap, default no need to get hap info.
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) != ATokenTypeEnum::TOKEN_HAP) {
        HKS_LOG_E("caller is not from hap, not support to get hap info.");
        return HKS_SUCCESS;
    }

    HapTokenInfo hapTokenInfo;
    int32_t callingResult = AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
    if (callingResult != HKS_SUCCESS) {
        HKS_LOG_E("Get hap info failed from access token kit.");
        return HKS_ERROR_BAD_STATE;
    }

    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_NULL_POINTER, "bundle mgr proxy is nullptr.")

    AppExecFwk::BundleInfo bundleInfo;
    const std::string bundleNameStr = hapTokenInfo.bundleName;
    bool isGetInfoSuccess = bundleMgrProxy->GetBundleInfo(bundleNameStr,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_HASH_VALUE, bundleInfo, processInfo->userIdInt);
    if (!isGetInfoSuccess) {
        HKS_LOG_E("GetBundleInfo failed.");
        return HKS_ERROR_BAD_STATE;
    }

    // The appid is concatenated from the bundle name and the developer's public key certificate.
    int32_t ret = ConvertHapInfoToJson(bundleInfo.appId, bundleNameStr, hapInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ConvertHapInfoToJson failed.")

    return HKS_SUCCESS;
}

int32_t HksGetSaInfo(const struct HksProcessInfo *processInfo, struct HksBlob *saInfo)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(saInfo, HKS_ERROR_NULL_POINTER, "saInfo is nullptr.")

    // if it is not hap, default no need to get hap info.
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) == ATokenTypeEnum::TOKEN_HAP) {
        HKS_LOG_E("caller is  from hap, not support to get sa info.");
        return HKS_SUCCESS;
    }
    NativeTokenInfo saTokenInfo;
    int32_t ret = AccessTokenKit::GetNativeTokenInfo(callingTokenId, saTokenInfo);
    if (ret != AccessTokenKitRet::RET_SUCCESS) {
        HKS_LOG_E("Get sa info failed from access token kit.");
        return HKS_ERROR_BAD_STATE;
    }

    if (saTokenInfo.apl >= ATokenAplEnum::APL_SYSTEM_BASIC) {
        ret = ConvertSaInfoToJson(saTokenInfo.processName, saInfo, saTokenInfo.apl);
    } else {
        HKS_LOG_E("The normal process, hide the process information.");
        ret = ConvertSaInfoToJson("", saInfo, saTokenInfo.apl);
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ConvertSaInfoToJson failed.")
    return HKS_SUCCESS;
}