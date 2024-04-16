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

#include "hks_plugin_adapter.h"

#include <dlfcn.h>

#include "hks_cfi.h"
#include "hks_client_service.h"
#include "hks_log.h"
#include "hks_mutex.h"
#include "hks_response.h"
#include "hks_storage_manager.h"
#include "hks_template.h"
#include "hks_type.h"

typedef struct HksPluginProxy *(HksGetPluginProxyFunc)();

static void *g_pluginHandler = nullptr;
static HksMutex *g_pluginMutex = NULL;
static struct HksPluginProxy *g_pluginProxy = nullptr;

struct HksBasicInterface g_interfaceInst = {
    .HksManageStoreKeyBlob = HksManageStoreKeyBlob,
    .HksManageStoreDeleteKeyBlob = HksManageStoreDeleteKeyBlob,
    .HksManageStoreIsKeyBlobExist = HksManageStoreIsKeyBlobExist,
    .HksManageStoreGetKeyBlob = HksManageStoreGetKeyBlob,
    .HksManageStoreGetKeyBlobSize = HksManageStoreGetKeyBlobSize,
    .HksManageGetKeyCountByProcessName = HksManageGetKeyCountByProcessName,

    .HksGetProcessInfoForIPC = HksGetProcessInfoForIPC

    .AppendStorageParamsForGen = AppendNewInfoForGenKeyInService,
    .AppendStorageParamsForUse = AppendNewInfoForUseKeyInService,
    .AppendStorageParamsForQuery = AppendStorageLevelIfNotExist,
};

void HksInitPluginProxyMutex()
{
    g_pluginMutex = HksMutexCreate();
}

int32_t HksCreatePluginProxy()
{
    if (HksMutexLock(g_pluginMutex) != HKS_SUCCESS) {
        HKS_LOG_E("lock mutex for plugin proxy failed");
        return HKS_ERROR_BAD_STATE;
    }
    int32_t ret = HKS_NULL_POINTER;
    struct HksPluginProxy *pluginProxy = nullptr;
    do {
        if (g_pluginProxy != nullptr) {
            ret = HKS_SUCCESS;
            break;
        }

        g_pluginHandler = dlopen("libhuks_ext.z.so", RTLD_NOW);
        HKS_IF_NULL_LOGE_BREAK(g_pluginHandler, "dlopen for plugin proxy failed")

        HksGetPluginProxyFunc func = dlsym(g_pluginHandler, "HksGetPluginProxy");
        HKS_IF_NULL_LOGE_BREAK(func, "dlsym for plugin proxy failed")

        pluginProxy = func();
        HKS_IF_NULL_LOGE_BREAK(g_pluginHandler, "HksGetPluginProxy result is null")

        ret = pluginProxy->HksPluginInit(&g_interfaceInst);
        HKS_IF_NULL_LOGE_BREAK(g_pluginHandler, "init plugin failed, ret = %" LOG_PUBLIC "d", ret)

        g_pluginHandler = pluginProxy;
    } while (0);

    (void)HksMutexUnlock(g_pluginMutex);
    if (ret != HKS_SUCCESS) {
        HksDestoryPluginProxy();
    }
    return ret;
}

void HksDestoryPluginProxy()
{
    if (g_pluginMutex == NULL || HksMutexLock(g_pluginMutex) != HKS_SUCCESS) {
        HKS_LOG_E("lock mutex for plugin proxy failed");
        return;
    }

    if (g_pluginProxy != nullptr) {
        g_pluginProxy->HksPluginDestory();
        g_pluginProxy = nullptr;
    }

    if (g_pluginHandler != nullptr) {
        dlclose(g_pluginHandler);
        g_pluginHandler = nullptr;
    }

    (void)HksMutexUnlock(g_pluginMutex);
    HksMutexClose(g_pluginMutex);
    g_pluginMutex = NULL;
}

struct HksPluginProxy *HksGetPluginProxy()
{
    if (g_pluginProxy == nullptr) {
        HKS_LOG_I("g_pluginProxy is null");
    }
    return g_pluginProxy;
}
