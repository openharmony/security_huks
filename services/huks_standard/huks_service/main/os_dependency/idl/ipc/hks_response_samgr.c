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

#include <dlfcn.h>
#include <unistd.h>

#include "hks_response.h"
#include "hks_samgr_server.h"
#include "hks_template.h"

#include <string.h>

static char g_userId[] = "0";

void HksSendResponse(const uint8_t *context, int32_t result, const struct HksBlob *response)
{
    if (context == NULL) {
        HKS_LOG_E("SendResponse NULL Pointer");
        return;
    }
    HksIpcContext *ipcContext = (HksIpcContext *)context;
    IpcIo *reply = ipcContext->reply;

    bool ipcRet = WriteInt32(reply, result);
    if (!ipcRet) {
        HKS_LOG_E("write response result failed!");
        return;
    }

    if (response == NULL) {
        ipcRet = WriteBool(reply, true);
        if (!ipcRet) {
            HKS_LOG_E("write response isNoneResponse failed!");
        }
        return;
    }

    ipcRet = WriteBool(reply, false);
    if (!ipcRet) {
        HKS_LOG_E("write response isNoneResponse failed!");
        return;
    }

    ipcRet = WriteUint32(reply, response->size);
    if (!ipcRet) {
        HKS_LOG_E("write response out data size failed!");
        return;
    }

    if (response->size > 0 && response->data != NULL) {
        ipcRet = WriteBuffer(reply, response->data, response->size);
        if (!ipcRet) {
            HKS_LOG_E("write response out data failed!");
        }
    }
}

int32_t HksGetProcessInfoForIPC(const uint8_t *context, struct HksProcessInfo *processInfo)
{
    if ((context == NULL) || (processInfo == NULL)) {
        HKS_LOG_D("Don't need get process name in hosp.");
        return HKS_SUCCESS;
    }
    HksIpcContext *ipcContext = (HksIpcContext *)context;
    uint32_t callingUid = (uint32_t)(ipcContext->callingUid);
    uint8_t *name = (uint8_t *)HksMalloc(sizeof(callingUid));
    HKS_IF_NULL_LOGE_RETURN(name, HKS_ERROR_MALLOC_FAIL, "GetProcessName malloc failed.")
    (void)memcpy_s(name, sizeof(callingUid), &callingUid, sizeof(callingUid));
    processInfo->processName.data = name;
    processInfo->processName.size = sizeof(callingUid);

    uint8_t *userId = (uint8_t *)HksMalloc(strlen(g_userId));
    HKS_IF_NULL_LOGE_RETURN(userId, HKS_ERROR_MALLOC_FAIL, "GetProcessUserId malloc failed.")
    processInfo->userId.data = userId;
    processInfo->userId.size = strlen(g_userId);
    (void)memcpy_s(processInfo->userId.data, processInfo->userId.size, g_userId, strlen(g_userId));

    processInfo->accessTokenId = 0;
    processInfo->userIdInt = 0;

    return HKS_SUCCESS;
}

int32_t HksGetFrontUserId(int32_t *outId)
{
    *outId = -1;
    HKS_LOG_I("QueryActiveOsFrontUserIds, no os account part, set FrontUserId= -1");
    return HKS_SUCCESS;
}
