/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hks_ipc_service.h"
#include "hks_message_handler.h"
#include "hks_samgr_server.h"
#include "hks_template.h"

#include "ipc_skeleton.h"

static const char *FEATURE_GetName(Feature *feature);
static void FEATURE_OnInitialize(Feature *feature, Service *parent, Identity identity);
static void FEATURE_OnStop(Feature *feature, Identity identity);
static BOOL FEATURE_OnMessage(Feature *feature, Request *msg);
static int32 Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply);

static HksMgrFeature g_hksMgrFeature = {
    .GetName = FEATURE_GetName,
    .OnInitialize = FEATURE_OnInitialize,
    .OnStop = FEATURE_OnStop,
    .OnMessage = FEATURE_OnMessage,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
    .identity = { -1, -1, NULL },
};
static const char *FEATURE_GetName(Feature *feature)
{
    (void)feature;
    return HKS_SAMGR_FEATRURE;
}

static void FEATURE_OnInitialize(Feature *feature, Service *parent, Identity identity)
{
    if (feature == NULL) {
        return;
    }
    HksMgrFeature *hksMgrFeature = (HksMgrFeature *)feature;
    hksMgrFeature->identity = identity;
    hksMgrFeature->parent = parent;
}

static void FEATURE_OnStop(Feature *feature, Identity identity)
{
    (void)feature;
    (void)identity;
    g_hksMgrFeature.identity.queueId = NULL;
    g_hksMgrFeature.identity.featureId = -1;
    g_hksMgrFeature.identity.serviceId = -1;
}

static BOOL FEATURE_OnMessage(Feature *feature, Request *msg)
{
    (void)feature;
    HKS_IF_NULL_RETURN(msg, false)

    Response response = { "Yes, you did!", 0 };
    return SAMGR_SendResponse(msg, &response);
}

static int32_t ProcessMsgToHandler(int funcId, HksIpcContext *ipcContext, const struct HksBlob *srcData,
    struct HksBlob *outData)
{
    int32_t ret = HKS_FAILURE;
    do {
        bool isHandled = false;
        uint32_t size = sizeof(g_hksIpcMessageHandler) / sizeof(g_hksIpcMessageHandler[0]);
        for (uint32_t i = 0; i < size; ++i) {
            if (funcId == g_hksIpcMessageHandler[i].msgId) {
                g_hksIpcMessageHandler[i].handler(srcData, (const uint8_t *)ipcContext);
                isHandled = true;
                ret = HKS_SUCCESS;
                break;
            }
        }

        if (!isHandled) {
            size = sizeof(g_hksIpcThreeStageHandler) / sizeof(g_hksIpcThreeStageHandler[0]);
            for (uint32_t i = 0; i < size; ++i) {
                if (funcId == g_hksIpcThreeStageHandler[i].msgId) {
                    g_hksIpcThreeStageHandler[i].handler(srcData, outData, (const uint8_t *)ipcContext);
                    ret = HKS_SUCCESS;
                    break;
                }
            }
        }
    } while (0);
    return ret;
}

static int32 Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    (void)iProxy;
    (void)origin;

    int32_t ret = HKS_FAILURE;

    uint32_t callingUid = GetCallingUid();
    HksIpcContext ipcContext = { reply, callingUid };

    struct HksBlob srcData = { 0 };
    struct HksBlob outData = { 0 };
    do {
        // read outData size
        uint32_t outSize = 0;
        bool ipcRet = ReadUint32(req, &outSize);
        if (!ipcRet) {
            ret = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }
        if (outSize > 0) {
            outData.size = outSize;
            outData.data = (uint8_t *)HksMalloc(outSize);
            if (outData.data == NULL) {
                HKS_LOG_E("outData malloc failed!");
                ret = HKS_ERROR_MALLOC_FAIL;
                break;
            }
        }

        // read srcData size
        uint32_t buffSize = 0;
        ipcRet = ReadUint32(req, &buffSize);
        if (!ipcRet) {
            ret = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }

        srcData.size = buffSize;
        const uint8_t *tmpUint8Array = ReadBuffer(req, srcData.size);
        if (tmpUint8Array == NULL) {
            ret = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }
        srcData.data = (uint8_t *)HksMalloc(srcData.size);
        if (srcData.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        (void)memcpy_s(srcData.data, srcData.size, tmpUint8Array, srcData.size);

        ret = ProcessMsgToHandler(funcId, &ipcContext, &srcData, &outData);
    } while (0);

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("handle ipc msg failed!");
        HksIpcErrorResponse((const uint8_t *)&ipcContext);
    }

    HKS_FREE_BLOB(srcData);
    HKS_FREE_BLOB(outData);

    return ret;
}

static void Init(void)
{
    bool ret = SAMGR_GetInstance()->RegisterFeature(HKS_SAMGR_SERVICE, (Feature *)&g_hksMgrFeature);
    if (!ret) {
        HKS_LOG_E("register feature failed!");
    }
    ret = SAMGR_GetInstance()->RegisterFeatureApi(HKS_SAMGR_SERVICE, HKS_SAMGR_FEATRURE, GET_IUNKNOWN(g_hksMgrFeature));
    if (!ret) {
        HKS_LOG_E("register feature api failed!");
    }
    HKS_LOG_I("HUKS feature init");
}
SYS_FEATURE_INIT(Init);