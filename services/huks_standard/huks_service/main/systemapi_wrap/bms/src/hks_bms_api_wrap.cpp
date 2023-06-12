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