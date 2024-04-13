/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hks_response.h"

#include <cinttypes>
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "hks_at_api_wrap.h"
#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef HKS_SUPPORT_ACCESS_TOKEN
#include "accesstoken_kit.h"
#endif
#include "ipc_skeleton.h"

#include "hks_base_check.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_util.h"

#include "hap_token_info.h"
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
#include "hks_bms_api_wrap.h"
#endif

#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif // HAS_OS_ACCOUNT_PART

using namespace OHOS;
static const char *g_trustListHap[] = HUKS_HAP_TRUST_LIST;
static const char *g_trustListSa[] = HUKS_SA_TRUST_LIST;

#ifndef HAS_OS_ACCOUNT_PART
constexpr static int UID_TRANSFORM_DIVISOR = 200000;
static void GetOsAccountIdFromUid(int uid, int &osAccountId)
{
    osAccountId = uid / UID_TRANSFORM_DIVISOR;
}
#endif // HAS_OS_ACCOUNT_PART

void HksSendResponse(const uint8_t *context, int32_t result, const struct HksBlob *response)
{
    if (context == nullptr) {
        HKS_LOG_E("SendResponse NULL Pointer");
        return;
    }

    MessageParcel *reply = const_cast<MessageParcel *>(reinterpret_cast<const MessageParcel *>(context));
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteInt32(result));

    if (response == nullptr) {
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(0));
    } else {
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(response->size));
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteBuffer(response->data, static_cast<size_t>(response->size)));
    }
}

int32_t HksGetProcessInfoForIPC(const uint8_t *context, struct HksProcessInfo *processInfo)
{
    if ((context == nullptr) || (processInfo == nullptr)) {
        HKS_LOG_D("Don't need get process name in hosp.");
        return HKS_SUCCESS;
    }

    auto callingUid = IPCSkeleton::GetCallingUid();
    uint8_t *name = static_cast<uint8_t *>(HksMalloc(sizeof(callingUid)));
    HKS_IF_NULL_LOGE_RETURN(name, HKS_ERROR_MALLOC_FAIL, "GetProcessName malloc failed.")

    (void)memcpy_s(name, sizeof(callingUid), &callingUid, sizeof(callingUid));
    processInfo->processName.size = sizeof(callingUid);
    processInfo->processName.data = name;
    processInfo->uidInt = callingUid;
    int userId = 0;
#ifdef HAS_OS_ACCOUNT_PART
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
#else // HAS_OS_ACCOUNT_PART
    GetOsAccountIdFromUid(callingUid, userId);
#endif // HAS_OS_ACCOUNT_PART

    HKS_LOG_I("Get callingUid = %" LOG_PUBLIC "d, userId = %" LOG_PUBLIC "d, sessionId = %" LOG_PUBLIC "u",
        callingUid, userId, g_sessionId);

    uint32_t size;
    if (userId == 0) {
        size = strlen("0");
    } else {
        size = sizeof(userId);
    }

    uint8_t *name1 = static_cast<uint8_t *>(HksMalloc(size));
    if (name1 == nullptr) {
        HKS_LOG_E("user id malloc failed.");
        HKS_FREE(name);
        processInfo->processName.data = nullptr;
        return HKS_ERROR_MALLOC_FAIL;
    }

    if (userId == 0) {
        (void)memcpy_s(name1, size, "0", size); /* ignore \0 at the end */
    } else {
        (void)memcpy_s(name1, size, &userId, size);
    }

    processInfo->userId.size = size;
    processInfo->userId.data = name1;
    processInfo->userIdInt = userId;

#ifdef HKS_SUPPORT_ACCESS_TOKEN
    processInfo->accessTokenId = static_cast<uint64_t>(IPCSkeleton::GetCallingTokenID());
#endif

    return HKS_SUCCESS;
}

static int32_t CheckHapInfo(int32_t tokenId)
{
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
    HKS_LOG_I("SUPPORT GET_BUNDLE_INFO!");
    char hapName[HAP_NAME_LEN_MAX] = { 0 };
    int32_t ret = HksGetHapNameFromAccessToken(tokenId, hapName, HAP_NAME_LEN_MAX);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksGetHapName fail when check name list.")
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_trustListHap); i++) {
        if (strcmp(hapName, g_trustListHap[i]) == 0) {
            HKS_LOG_I("This hap in permission, hapName: %" LOG_PUBLIC "s", hapName);
            return HKS_SUCCESS;
        }
    }
    HKS_LOG_E("Not in name list, hapName: %" LOG_PUBLIC "s", hapName);
    return HKS_ERROR_NO_PERMISSION;
#else
    //Lite device no need check
    HKS_LOG_I("ACCESS_TOKEN no support!");
    (void)tokenId;
    (void)g_trustListHap;
    return HKS_SUCCESS;
#endif
}

#ifdef HKS_SUPPORT_ACCESS_TOKEN
static int32_t CheckProcessInfo(uint32_t tokenId)
{
    OHOS::Security::AccessToken::NativeTokenInfo tokenInfo;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("GetNativeTokenInfo failed, tokenId: %" LOG_PUBLIC "d", tokenId);
        return HKS_ERROR_BAD_STATE;
    }
    const char *saName = tokenInfo.processName.c_str();
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_trustListSa); i++) {
        if (strcmp(saName, g_trustListSa[i]) == 0) {
            HKS_LOG_I("This sa in whiteList, saName: %" LOG_PUBLIC "s", saName);
            return HKS_SUCCESS;
        }
    }

    HKS_LOG_I("Not in name list, saName: %" LOG_PUBLIC "s", saName);
    return HKS_ERROR_NO_PERMISSION;
}

int32_t CheckNameList(void)
{
    HKS_LOG_I("ACCESS_TOKEN support, start CheckNameList!");
    OHOS::Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    OHOS::Security::AccessToken::ATokenTypeEnum tokenType =
        OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    switch (tokenType) {
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_HAP: {
            return CheckHapInfo(tokenId);
        }
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE:
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL:
            HKS_LOG_I("CheckProcessInfo...");
            return CheckProcessInfo(tokenId);
        default:
            HKS_LOG_E("This type is Unknow Type: %" LOG_PUBLIC "d", tokenType);
            return HKS_ERROR_NOT_EXIST;
    }
    return HKS_ERROR_NOT_EXIST;
}
#else

int32_t CheckNameList(void)
{
    //Lite device no need check
    HKS_LOG_I("ACCESS_TOKEN no support!");
    (void)g_trustListSa;
    return HKS_SUCCESS;
}
#endif

int32_t HksGetFrontUserId(int32_t *outId)
{
#ifdef HAS_OS_ACCOUNT_PART
    std::vector<int> ids;
    int ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        HKS_LOG_E("QueryActiveOsAccountIds Failed!! ret = %" LOG_PUBLIC "d", ret);
        return HKS_FAILURE;
    }
    HKS_LOG_I("QueryActiveOsAccountIds success: FrontUserId= %" LOG_PUBLIC "d", ids[0]);
    *outId = ids[0];
#else // HAS_OS_ACCOUNT_PART
    *outId = -1;
    HKS_LOG_I("QueryActiveOsAccountIds, no os account part, set FrontUserId= -1");
#endif // HAS_OS_ACCOUNT_PART

    return HKS_SUCCESS;
}