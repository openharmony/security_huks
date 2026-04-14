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
#include <securec.h>
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
#ifndef HAS_OS_ACCOUNT_PART
constexpr static int UID_TRANSFORM_DIVISOR = 200000;
#endif // HAS_OS_ACCOUNT_PART
constexpr static int HKS_ANCO_BROKER_UID = 5557;
int HksGetOsAccountIdFromUid(int uid)
{
#ifdef HAS_OS_ACCOUNT_PART
    int accountId = 0;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, accountId);
    return accountId;
#else // HAS_OS_ACCOUNT_PART
    return uid / UID_TRANSFORM_DIVISOR;
#endif // HAS_OS_ACCOUNT_PART
}

void HksSendResponse(const uint8_t *context, int32_t result, const struct HksBlob *response)
{
    if (context == nullptr) {
        HKS_LOG_E("SendResponse NULL Pointer");
        return;
    }

    MessageParcel *reply = const_cast<MessageParcel *>(reinterpret_cast<const MessageParcel *>(context));
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteInt32(result), "reply->WriteInt32(result) failed");

    if (response == nullptr) {
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(0), "reply->WriteUint32(0) failed");
    } else {
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(response->size),
            "reply->WriteUint32(response->size) failed");
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteBuffer(response->data, static_cast<size_t>(response->size)),
            "reply->WriteBuffer failed");
    }
#ifdef L2_STANDARD
    uint32_t msgLen = HksGetThreadErrorMsgLen();
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(msgLen), "reply->WriteUint32(msgLen) failed");

    if (msgLen != 0) {
        const char *msg = HksGetThreadErrorMsg();
        if (!reply->WriteBuffer(msg, static_cast<size_t>(msgLen))) {
            HKS_LOG_E("WriteBuffer for errMsg fail!");
            return;
        }
    }

#endif
}

static int32_t GetUidAndUserId(const struct HksParamSet *paramSet, int &uid, int &userId)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    uid = callingUid;
    userId = HksGetOsAccountIdFromUid(callingUid);
    HKS_IF_NULL_RETURN(paramSet, HKS_SUCCESS)

    struct HksParam *ancoUidParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ANCO_APP_UID, &ancoUidParam);
    if (callingUid == HKS_ANCO_BROKER_UID) {
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get HKS_TAG_ANCO_APP_UID failed, ret: %" LOG_PUBLIC "d", ret)
        HKS_IF_NOT_TRUE_LOGE_RETURN(ancoUidParam->blob.size == sizeof(int), HKS_ERROR_NEW_INVALID_ARGUMENT,
            "uid size should be sizeof(int)")
        // get anco user id
        struct HksParam *ancoUserIdParam = nullptr;
        ret = HksGetParam(paramSet, HKS_TAG_ANCO_USER_ID, &ancoUserIdParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get HKS_TAG_ANCO_USER_ID failed, ret: %" LOG_PUBLIC "d", ret)

        uid = *(int *)(ancoUidParam->blob.data);
        userId = static_cast<int>(ancoUserIdParam->uint32Param);
    } else {
        HKS_IF_TRUE_LOGE_RETURN(ret != HKS_ERROR_PARAM_NOT_EXIST, HKS_ERROR_NEW_INVALID_ARGUMENT,
            "not allowed to add anco tag for non-broker invoker, processName: %" LOG_PUBLIC "d", callingUid)
    }
    return HKS_SUCCESS;
}

int32_t HksGetProcessInfoForIPC(const struct HksParamSet *paramSet,
    const uint8_t *context, struct HksProcessInfo *processInfo)
{
    HKS_IF_NULL_RETURN(context, HKS_SUCCESS);
    HKS_IF_NULL_RETURN(processInfo, HKS_SUCCESS);
    
    int uid = -1;
    int userId = -1;
    int32_t ret = GetUidAndUserId(paramSet, uid, userId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get uid or user id failed")

    uint8_t *uidName = nullptr;
    uint8_t *userName = nullptr;
    uint32_t size = 0;
    ret = HKS_ERROR_MALLOC_FAIL;
    do {
        uidName = static_cast<uint8_t *>(HksMalloc(sizeof(uid)));
        HKS_IF_NULL_LOGE_BREAK(uidName, "malloc uid failed")

        size = userId == 0 ? strlen("0") : sizeof(userId);
        userName = static_cast<uint8_t *>(HksMalloc(size));
        HKS_IF_NULL_LOGE_BREAK(userName, "malloc userId failed")

        (void)memcpy_s(uidName, sizeof(uid), &uid, sizeof(uid));
        processInfo->processName.size = sizeof(uid);
        processInfo->processName.data = uidName;
        processInfo->uidInt = static_cast<uint32_t>(uid);

        if (userId == 0) {
            (void)memcpy_s(userName, size, "0", size); /* ignore \0 at the end */
        } else {
            (void)memcpy_s(userName, size, &userId, size);
        }

        processInfo->userId.size = size;
        processInfo->userId.data = userName;
        processInfo->userIdInt = userId;

#ifdef HKS_SUPPORT_ACCESS_TOKEN
        processInfo->accessTokenId = static_cast<uint64_t>(IPCSkeleton::GetCallingTokenID());
        HKS_IF_TRUE_LOGE(processInfo->accessTokenId == 0, "accessTokenId is zero")
#endif
        processInfo->pid = static_cast<int32_t>(IPCSkeleton::GetCallingPid());
        HKS_IF_TRUE_LOGE(processInfo->pid == 0, "GetCallingPID is zero")
        return HKS_SUCCESS;
    } while (0);

    HKS_FREE(uidName);
    HKS_FREE(userName);
    processInfo->processName.data = nullptr;
    return ret;
}

int32_t HksGetFrontUserId(int32_t *outId)
{
#ifdef HAS_OS_ACCOUNT_PART
    std::vector<int> ids;
    int ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    HKS_IF_TRUE_LOGE_RETURN(ret != ERR_OK || ids.empty(), HKS_FAILURE,
        "QueryActiveOsAccountIds Failed!! ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_D("QueryActiveOsAccountIds success: FrontUserId= %" LOG_PUBLIC "d", ids[0]);
    *outId = ids[0];
#else // HAS_OS_ACCOUNT_PART
    *outId = -1;
    HKS_LOG_I("QueryActiveOsAccountIds, no os account part, set FrontUserId= -1");
#endif // HAS_OS_ACCOUNT_PART

    return HKS_SUCCESS;
}
