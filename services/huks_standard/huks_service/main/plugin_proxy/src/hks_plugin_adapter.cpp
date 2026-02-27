/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "hks_plugin_adapter.h"

#include <dlfcn.h>

#include "hks_cfi.h"
#include "hks_client_service_util.h"
#include "hks_error_code.h"
#include "hks_ha_plugin.h"
#include "hks_log.h"
#include "hks_mutex.h"
#include "hks_response.h"
#include "hks_storage_manager.h"
#include "hks_template.h"
#include "hks_type.h"

using HksGetPluginProxyFunc = struct HksPluginProxy *(*)();

static void *g_pluginHandler = nullptr;
static HksMutex *g_pluginMutex = nullptr;
static struct HksPluginProxy *g_pluginProxy = nullptr;

static struct HksBasicInterface g_interfaceInst = {
    .hksManageStoreKeyBlob = HksManageStoreKeyBlob,
    .hksManageStoreDeleteKeyBlob = HksManageStoreDeleteKeyBlob,
    .hksManageStoreIsKeyBlobExist = HksManageStoreIsKeyBlobExist,
    .hksManageStoreGetKeyBlob = HksManageStoreGetKeyBlob,
    .hksManageStoreGetKeyBlobSize = HksManageStoreGetKeyBlobSize,
    .hksManageGetKeyCountByProcessName = HksManageGetKeyCountByProcessName,

    .hksGetProcessInfoForIPC = HksGetProcessInfoForIPC,

    .appendStorageParamsForGen = AppendNewInfoForGenKeyInService,
    .appendStorageParamsForUse = AppendNewInfoForUseKeyInService,
    .appendStorageParamsForQuery = AppendStorageLevelIfNotExist,

    .hksRegisterEventProc = HksRegisterEventProcWrapper,
    .hksRegisterEventProcs = HksRegisterEventProcs,
    .hksEnqueueEvent = HksEnqueueEventWrapper,
};

static void HksDestoryPluginProxy(void)
{
    if (g_pluginProxy != nullptr) {
        g_pluginProxy->hksPluginDestory();
        g_pluginProxy = nullptr;
    }

    if (g_pluginHandler != nullptr) {
        dlclose(g_pluginHandler);
        g_pluginHandler = nullptr;
    }
}

/* It is invoked when service initialize */
ENABLE_CFI(static int32_t HksCreatePluginProxy(void))
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksMutexLock(g_pluginMutex), HKS_ERROR_BAD_STATE, "lock mutex for plugin proxy failed")

    int32_t ret = HKS_ERROR_NULL_POINTER;
    do {
        if (g_pluginProxy != nullptr) {
            ret = HKS_SUCCESS;
            break;
        }

        g_pluginHandler = dlopen("libhuks_ext.z.so", RTLD_NOW);
        HKS_IF_NULL_LOGE_BREAK(g_pluginHandler, "dlopen for plugin proxy failed")

        HksGetPluginProxyFunc func = (HksGetPluginProxyFunc)dlsym(g_pluginHandler, "HksGetPluginProxy");
        HKS_IF_NULL_LOGE_BREAK(func, "dlsym for plugin proxy failed")

        g_pluginProxy = func();
        HKS_IF_NULL_LOGE_BREAK(g_pluginProxy, "HksGetPluginProxy result is null")

        ret = g_pluginProxy->hksPluginInit(&g_interfaceInst);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init plugin failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCreatePluginProxy failed");
        HksDestoryPluginProxy();
    }
    (void)HksMutexUnlock(g_pluginMutex);
    return ret;
}

int32_t RetryLoadPlugin(void)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksCreatePluginProxy(), HKS_ERROR_LOAD_PLUGIN_FAIL,
        "Failed to create the plugin again.")
    return HKS_SUCCESS;
}

int32_t HksInitPluginProxy(void)
{
    if (g_pluginMutex == nullptr) {
        g_pluginMutex = HksMutexCreate();
    }

    if (g_pluginMutex == nullptr) {
        HKS_LOG_E("Hks plugin mutex init failed, null pointer!");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksCreatePluginProxy();
    if (ret != HKS_SUCCESS) {
        HKS_LOG_W("Create plugin proxy failed, ret = %" LOG_PUBLIC "d", ret);
    }
    return HKS_SUCCESS; // Try to load the plugin again while the plugin is in use.
}

int32_t HksPluginOnRemoteRequest(uint32_t code, void *data, void *reply, void *option)
{
    return g_pluginProxy->hksPluginOnRemoteRequest(code, data, reply, option);
}

int32_t HksPluginOnLocalRequest(uint32_t code, const void *data, void *reply)
{
    HKS_IF_NULL_RETURN(g_pluginProxy, HKS_SUCCESS)
    return g_pluginProxy->hksPluginOnLocalRequest(code, data, reply);
}

void HksPluginOnReceiveEvent(const void *data)
{
    HKS_IF_NOT_SUCC_RETURN_VOID(RetryLoadPlugin())
    g_pluginProxy->hksPluginOnReceiveEvent(data);
}

int32_t HksPluginOnLocalRequestWrapKey(uint32_t code, const void *data, void *reply)
{
    HKS_IF_NULL_LOGE_RETURN(g_pluginProxy, HKS_ERROR_API_NOT_SUPPORTED, "wrap key not supported")
    return g_pluginProxy->hksPluginOnLocalRequest(code, data, reply);
}

int32_t HksPluginWrapKey(const struct HksBlob *srcData, const uint8_t *context)
{
    if (g_pluginProxy != nullptr) {
        return HKS_SUCCESS;
    }
    HksSendResponse(context, HKS_ERROR_API_NOT_SUPPORTED, nullptr);
    return HKS_ERROR_API_NOT_SUPPORTED;
}

int32_t HksPluginImportWrappedKey(const struct HksImportKeyStoreArgs *data, struct HksBlob *reply)
{
    HKS_IF_NULL_LOGE_RETURN(g_pluginProxy, HKS_ERROR_API_NOT_SUPPORTED, "import keystore not supported")
    return g_pluginProxy->hksPluginOnLocalRequest(CODE_IMPORT_KEY_STORE, data, reply);
}
