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
#include "hks_request.h"
#include "hks_template.h"
#include "huks_service_ipc_interface_code.h"

#include "iproxy_client.h"
#include "registry.h"

#include <unistd.h>

static int32_t SynchronizeOutput(const struct HksIpcHandle *reply, struct HksBlob *outBlob)
{
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
                HKS_LOG_I("ipc reply with no out data");
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
    if (curReply == NULL || reply == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (memcpy_s(curReply->io->bufferCur, curReply->io->bufferLeft, reply->bufferCur, reply->bufferLeft) != EOK) {
        HKS_LOG_E("data copy for curReply failed, cur size is %zu, reply size is %zu", curReply->io->bufferLeft,
            reply->bufferLeft);
        curReply->state = HKS_IPC_MSG_ERROR;
        curReply->io->bufferLeft = 0;
        return HKS_ERROR_IPC_MSG_FAIL;
    }
    curReply->state = HKS_IPC_MSG_OK;
    curReply->io->bufferLeft = reply->bufferLeft;
    return HKS_SUCCESS;
}

static int32_t WriteToIpcRequest(IpcIo *request, uint32_t outBlobSize, const struct HksBlob *inBlob)
{
    bool ipcRet = WriteUint32(request, outBlobSize);
    if (!ipcRet) {
        return HKS_ERROR_IPC_MSG_FAIL;
    }
    ipcRet = WriteUint32(request, inBlob->size);
    if (!ipcRet) {
        return HKS_ERROR_IPC_MSG_FAIL;
    }
    ipcRet = WriteBuffer(request, inBlob->data, inBlob->size);
    if (!ipcRet) {
        return HKS_ERROR_IPC_MSG_FAIL;
    }
    return HKS_SUCCESS;
}

static int32_t HksIpcCall(IUnknown *iUnknown, enum HksIpcInterfaceCode type, const struct HksBlob *inBlob,
    struct HksBlob *outBlob)
{
    /* Check input and inBlob */
    int32_t ret = CheckBlob(inBlob);
    if ((ret != HKS_SUCCESS) || (iUnknown == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    IClientProxy *proxy = (IClientProxy *)iUnknown;

    uint32_t outBlobSize = 0;
    if (outBlob != NULL) {
        outBlobSize = outBlob->size;
    }

    char *dataReq = NULL;
    char *dataReply = NULL;
    do {
        dataReq = (char *)HksMalloc(MAX_IO_SIZE);
        if (dataReq == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        IpcIo request;
        IpcIoInit(&request, dataReq, MAX_IO_SIZE, MAX_OBJ_NUM);

        ret = WriteToIpcRequest(&request, outBlobSize, inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "write to ipc request failed!")

        dataReply = (char *)HksMalloc(MAX_IO_SIZE);
        if (dataReply == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        IpcIo reply;
        IpcIoInit(&reply, dataReply, MAX_IO_SIZE, MAX_OBJ_NUM);

        struct HksIpcHandle replyHandle = { .io = &reply, .state = HKS_IPC_MSG_BASE };

        ret = (int32_t)proxy->Invoke((IClientProxy *)proxy, type, &request, (IOwner)&replyHandle, CurrentCallback);
        HKS_IF_NOT_SUCC_BREAK(ret, HKS_ERROR_IPC_MSG_FAIL)

        ret = SynchronizeOutput(&replyHandle, outBlob);
    } while (0);
    HKS_FREE(dataReq);
    HKS_FREE(dataReply);

    return ret;
}

static int32_t HksSendRequestSync(enum HksIpcInterfaceCode type, const struct HksBlob *inBlob, struct HksBlob *outBlob)
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

    ret = HksIpcCall((IUnknown *)clientProxy, type, inBlob, outBlob);
    (void)clientProxy->Release((IUnknown *)clientProxy);

    return ret;
}

int32_t HksSendRequest(enum HksIpcInterfaceCode type, const struct HksBlob *inBlob, struct HksBlob *outBlob,
    const struct HksParamSet *paramSet)
{
    (void)paramSet;
    return HksSendRequestSync(type, inBlob, outBlob);
}
