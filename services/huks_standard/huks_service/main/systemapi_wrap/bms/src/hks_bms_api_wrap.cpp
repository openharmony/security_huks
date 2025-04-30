/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "bundle_mgr_interface.h"
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
#define APP_MODE_DEBUG "debug"
#define APP_MODE_RELEASE "release"

using namespace OHOS;
using namespace Security::AccessToken;

static int32_t ConvertCallerInfoToJson(struct HksCallerInfo *callerInfo, struct HksBlob *outInfo)
{
    cJSON *jsonObj = cJSON_CreateObject();
    HKS_IF_NULL_LOGE_RETURN(jsonObj, HKS_ERROR_NULL_POINTER, "create cjson object failed.")

    const char *jsonKeyId = callerInfo->isHap ? "appId" : "processName";
    const char *jsonKeyExtend = callerInfo->isHap ? "bundleName" : "APL";
    if ((cJSON_AddStringToObject(jsonObj, jsonKeyId, callerInfo->id.c_str()) == nullptr) ||
        (cJSON_AddStringToObject(jsonObj, jsonKeyExtend, callerInfo->extend.c_str()) == nullptr)) {
        HKS_LOG_E("add id and extend info to json object is failed.");
        cJSON_Delete(jsonObj);
        return HKS_ERROR_NULL_POINTER;
    }

    const char *jsonKeyIdentifier = "appIdentifier";
    const char *jsonKeyMode = "appMode";
    if (callerInfo->isHap &&
        (cJSON_AddStringToObject(jsonObj, jsonKeyIdentifier, callerInfo->appIdentifier.c_str()) == nullptr ||
        cJSON_AddStringToObject(jsonObj, jsonKeyMode, callerInfo->appMode.c_str()) == nullptr)) {
        HKS_LOG_E("add appIdentifier and appMode to json object is failed.");
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
    HKS_IF_TRUE_LOGE_RETURN(AccessTokenKit::GetTokenType(callingTokenId) != ATokenTypeEnum::TOKEN_HAP,
        HKS_ERROR_NOT_SUPPORTED, "caller is not from hap, not support to get hap info.")

    HapTokenInfo hapTokenInfo;
    int32_t callingResult = AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(callingResult, HKS_ERROR_BAD_STATE, "Get hap info failed from access token kit.")

    AppExecFwk::BundleInfo bundleInfo;
    AppExecFwk::BundleMgrClient client;
    bool isGetInfoSuccess = client.GetBundleInfo(hapTokenInfo.bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_HASH_VALUE, bundleInfo, processInfo->userIdInt);
    HKS_IF_NOT_TRUE_LOGE_RETURN(isGetInfoSuccess, HKS_ERROR_BAD_STATE, "GetBundleInfo failed.")

    struct HksCallerInfo callerInfo = {
        .isHap = true,
        .id = bundleInfo.appId,
        .extend = hapTokenInfo.bundleName,
        .appIdentifier = bundleInfo.signatureInfo.appIdentifier,
        .appMode = bundleInfo.applicationInfo.debug ? APP_MODE_DEBUG : APP_MODE_RELEASE
    };
    // The appid is concatenated from the bundle name and the developer's public key certificate.
    int32_t ret = ConvertCallerInfoToJson(&callerInfo, hapInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ConvertHapInfoToJson failed.")

    return HKS_SUCCESS;
}

static int32_t HksGetBundleInfoV9(const std::string &bundleName, int32_t userId, AppExecFwk::BundleInfo &bundleInfo)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(systemAbilityManager, HKS_ERROR_BAD_STATE, "failed to get system ability mgr")

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    HKS_IF_NULL_LOGE_RETURN(remoteObject, HKS_ERROR_BAD_STATE, "failed to get remoteObject")

    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_BAD_STATE, "failed to get bundleMgrProxy")

    uint32_t flag = static_cast<uint32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);
    int32_t ret = bundleMgrProxy->GetBundleInfoV9(bundleName, flag, bundleInfo, userId);
    HKS_IF_NOT_SUCC_LOGE(ret, "GetBundleInfoV9 fail, ret = %" LOG_PUBLIC "d", ret)

    return ret;
}

static int32_t HksGetHapPkgName(const struct HksProcessInfo *processInfo, struct HksBlob *hapOwnerId)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(hapOwnerId, HKS_ERROR_NULL_POINTER, "hapOwnerId is nullptr.")

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    HKS_IF_TRUE_LOGE_RETURN(AccessTokenKit::GetTokenType(callingTokenId) != ATokenTypeEnum::TOKEN_HAP,
        HKS_ERROR_NOT_SUPPORTED, "caller is not from hap, not support to get hap info.")

    HapTokenInfo hapTokenInfo;
    int32_t callingResult = AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(callingResult, HKS_ERROR_BAD_STATE, "Get hap info failed from access token kit.")

    AppExecFwk::BundleInfo bundleInfo;
    int32_t ret =  HksGetBundleInfoV9(hapTokenInfo.bundleName, processInfo->userIdInt, bundleInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksGetBundleInfoV9 fail")

    const char *appIdentifier = bundleInfo.signatureInfo.appIdentifier.c_str();
    hapOwnerId->size = bundleInfo.signatureInfo.appIdentifier.size();
    hapOwnerId->data = (uint8_t *)HksMalloc(hapOwnerId->size);
    HKS_IF_NULL_LOGE_RETURN(hapOwnerId->data, HKS_ERROR_MALLOC_FAIL, "malloc hapOwnerId data fail")

    (void)memcpy_s(hapOwnerId->data, hapOwnerId->size, appIdentifier, hapOwnerId->size);
    return HKS_SUCCESS;
}

int32_t HksGetSaInfo(const struct HksProcessInfo *processInfo, struct HksBlob *saInfo)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(saInfo, HKS_ERROR_NULL_POINTER, "saInfo is nullptr.")

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    HKS_IF_TRUE_LOGE_RETURN(AccessTokenKit::GetTokenType(callingTokenId) == ATokenTypeEnum::TOKEN_HAP,
        HKS_ERROR_NOT_SUPPORTED, "Error caller Type, cannot get SaInfo")
    NativeTokenInfo saTokenInfo;
    int32_t ret = AccessTokenKit::GetNativeTokenInfo(callingTokenId, saTokenInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != AccessTokenKitRet::RET_SUCCESS, HKS_ERROR_BAD_STATE,
        "Get sa info failed from access token kit.")

    struct HksCallerInfo callerInfo = {
        .isHap = false,
        .id = "",
        .extend = "",
        .appIdentifier = "",
        .appMode = ""
    };
    if (saTokenInfo.apl == ATokenAplEnum::APL_SYSTEM_BASIC) {
        callerInfo.id = saTokenInfo.processName;
        callerInfo.extend = SYSTEM_BASIC;
    } else if (saTokenInfo.apl == ATokenAplEnum::APL_SYSTEM_CORE) {
        callerInfo.id = saTokenInfo.processName;
        callerInfo.extend = SYSTEM_CORE;
    } else {
        HKS_LOG_E("The normal process, hide the caller information.");
    }
    ret = ConvertCallerInfoToJson(&callerInfo, saInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ConvertSaInfoToJson failed.")
    return HKS_SUCCESS;
}

static int32_t HksGetSaProcessName(const struct HksProcessInfo *processInfo, struct HksBlob *saProcessName)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")
    HKS_IF_NULL_LOGE_RETURN(saProcessName, HKS_ERROR_NULL_POINTER, "saProcessName is nullptr.")

    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    HKS_IF_TRUE_LOGE_RETURN(AccessTokenKit::GetTokenType(callingTokenId) == ATokenTypeEnum::TOKEN_HAP,
        HKS_ERROR_NOT_SUPPORTED, "Error caller Type, cannot get SaInfo")
    NativeTokenInfo saTokenInfo;
    int32_t ret = AccessTokenKit::GetNativeTokenInfo(callingTokenId, saTokenInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != AccessTokenKitRet::RET_SUCCESS, HKS_ERROR_BAD_STATE,
        "Get sa info failed from access token kit.")

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