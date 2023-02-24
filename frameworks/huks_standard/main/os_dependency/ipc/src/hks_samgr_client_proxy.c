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

#include "hks_samgr_client.h"

#include "hks_message_code.h"
#include "hks_request.h"
#include "hks_template.h"

#include "iproxy_client.h"
#include "registry.h"

#include <unistd.h>

static int32_t SynchronizeOutput(struct HksIpcHandle *reply, struct HksBlob *outBlob)
{
    if (reply == NULL || reply->io == NULL) {
        HKS_LOG_E("get ipc reply failed!");
        return HKS_ERROR_IPC_MSG_FAIL;
    }

    if (reply->state != HKS_IPC_MSG_OK) {
        HKS_LOG_E("ipc reply failed, ret = %d", reply->state);
        return HKS_ERROR_IPC_MSG_FAIL;
    }

    int32_t callBackResult = HKS_ERROR_IPC_MSG_FAIL;
    do {
        bool ipcRet = ReadInt32(reply->io, &callBackResult);
        if (!ipcRet) {
            callBackResult = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }

        bool isNoneResponse = true;
        ipcRet = ReadBool(reply->io, &isNoneResponse);
        if (!ipcRet) {
            callBackResult = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }
        if (isNoneResponse) {
            break;
        }

        if (outBlob != NULL) {
            uint32_t buffSize = 0;
            ipcRet = ReadUint32(reply->io, &buffSize);
            if (!ipcRet) {
                callBackResult = HKS_ERROR_IPC_MSG_FAIL;
                break;
            }
            if (buffSize == 0) {
                HKS_LOG_E("ipc reply with no out data");
                break;
            }

            // the ipc will ensure the validity of data-reading within limited and valid data size
            const uint8_t *tmpUint8Array = ReadBuffer(reply->io, buffSize);
            if (tmpUint8Array == NULL) {
                callBackResult = HKS_ERROR_IPC_MSG_FAIL;
                break;
            }

            if (memcpy_s(outBlob->data, outBlob->size, tmpUint8Array, buffSize) != EOK) {
                callBackResult = HKS_ERROR_BUFFER_TOO_SMALL;
                break;
            }
            outBlob->size = buffSize;
        }
    } while (0);
    
    return callBackResult;
}

static int CurrentCallback(IOwner owner, int code, IpcIo *reply)
{
    (void)code;
    struct HksIpcHandle *curReply = (struct HksIpcHandle *)owner;

    if (memcpy_s(curReply->io->bufferCur, curReply->io->bufferLeft, reply->bufferCur, reply->bufferLeft) != EOK) {
        HKS_LOG_E("data copy for curReply failed, cur size is %d, reply size is %d", curReply->io->bufferLeft,
            reply->bufferLeft);
        curReply->state = HKS_IPC_MSG_ERROR;
        curReply->io->bufferLeft = 0;
        return HKS_ERROR_IPC_MSG_FAIL;
    }
    curReply->state = HKS_IPC_MSG_OK;
    curReply->io->bufferLeft = reply->bufferLeft;
    return HKS_SUCCESS;
}

static int32_t HksIpcCall(IUnknown *iUnknown, enum HksMessage funcId, const struct HksBlob *inBlob,
    struct HksBlob *outBlob)
{
    /* Check input and inBlob */
    int32_t ret = CheckBlob(inBlob);
    if ((ret != HKS_SUCCESS) || (iUnknown == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    IClientProxy *proxy = (IClientProxy *)iUnknown;

    IpcIo request;
    char dataReq[MAX_IO_SIZE];
    IpcIoInit(&request, dataReq, MAX_IO_SIZE, MAX_OBJ_NUM);

    uint32_t outBlobSize = 0;
    if (outBlob != NULL) {
        outBlobSize = outBlob->size;
    }

    do {
        bool ipcRet = WriteUint32(&request, outBlobSize);
        if (!ipcRet) {
            ret = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }

        ipcRet = WriteUint32(&request, inBlob->size);
        if (!ipcRet) {
            ret = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }
        ipcRet = WriteBuffer(&request, inBlob->data, inBlob->size);
        if (!ipcRet) {
            ret = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }

        char dataReply[MAX_IO_SIZE];
        IpcIo reply;
        IpcIoInit(&reply, dataReply, MAX_IO_SIZE, MAX_OBJ_NUM);

        struct HksIpcHandle replyHandle = { .io = &reply, .state = HKS_IPC_MSG_BASE };

        ret = (int32_t)proxy->Invoke((IClientProxy *)proxy, funcId, &request, (IOwner)&replyHandle, CurrentCallback);
        HKS_IF_NOT_SUCC_BREAK(ret, HKS_ERROR_IPC_MSG_FAIL)

        return SynchronizeOutput(&replyHandle, outBlob);
    } while (0);

    return ret;
}

static int32_t HksSendRequestSync(enum HksMessage funcId, const struct HksBlob *inBlob, struct HksBlob *outBlob)
{
    IClientProxy *clientProxy = NULL;
    IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(HKS_SAMGR_SERVICE, HKS_SAMGR_FEATRURE);
    if (iUnknown == NULL) {
        HKS_LOG_E("get HKS_SAMGR_FEATRURE api failed");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = iUnknown->QueryInterface(iUnknown, DEFAULT_VERSION, (void **)&clientProxy);
    if ((clientProxy == NULL) || (ret != 0)) {
        HKS_LOG_E("get clientProxy failed");
        return HKS_ERROR_NULL_POINTER;
    }

    ret = HksIpcCall((IUnknown *)clientProxy, funcId, inBlob, outBlob);
    (void)clientProxy->Release((IUnknown *)clientProxy);

    return ret;
}

int32_t HksSendRequest(enum HksMessage funcId, const struct HksBlob *inBlob, struct HksBlob *outBlob,
    const struct HksParamSet *paramSet)
{
    (void)paramSet;
    return HksSendRequestSync(funcId, inBlob, outBlob);
}
