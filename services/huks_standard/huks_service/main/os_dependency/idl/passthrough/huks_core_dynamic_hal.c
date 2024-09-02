/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "huks_core_hal.h"

#include <dlfcn.h>

#include "hks_cfi.h"
#include "hks_log.h"
#include "hks_mutex.h"
#include "hks_template.h"

typedef struct HuksHdi *(*HalCreateHandle)(void);
typedef void (*HalDestroyHandle)(struct HuksHdi *);

void *g_halDeviceHandle = NULL;
static HksMutex *g_halDevicePtrMutex = NULL;

ENABLE_CFI(int32_t HksCreateHuksHdiDevice(struct HuksHdi **halDevice))
{
    HKS_IF_NULL_LOGE_RETURN(halDevice, HKS_ERROR_NULL_POINTER, "invalid input halDevice")

    if (*halDevice != NULL) {
        return HKS_SUCCESS;
    }

    if (HksMutexLock(g_halDevicePtrMutex) != 0) {
        HKS_LOG_E("g_halDevicePtrMutex HksMutexLock failed");
        return HKS_FAILURE;
    }

    if (*halDevice != NULL) {
        (void)HksMutexUnlock(g_halDevicePtrMutex);
        return HKS_SUCCESS;
    }

#ifdef HKS_L1_SMALL
    g_halDeviceHandle = dlopen("libhuks_engine_core_standard.so", RTLD_NOW);
#else
    g_halDeviceHandle = dlopen("libhuks_engine_core_standard.z.so", RTLD_NOW);
#endif
    if (g_halDeviceHandle == NULL) {
        (void)HksMutexUnlock(g_halDevicePtrMutex);
        HKS_LOG_E("dlopen failed, %" LOG_PUBLIC "s!", dlerror());
        return HKS_FAILURE;
    }

    do {
        HalCreateHandle devicePtr = (HalCreateHandle)dlsym(g_halDeviceHandle, "HuksCreateHdiDevicePtr");
        HKS_IF_NULL_LOGE_BREAK(devicePtr, "dlsym failed, %" LOG_PUBLIC "s!", dlerror())

        *halDevice = (*devicePtr)();
        HKS_IF_NULL_LOGE_BREAK(*halDevice, "g_hksHalDevicePtr is NULL!")

        (void)HksMutexUnlock(g_halDevicePtrMutex);
        return HKS_SUCCESS;
    } while (0);

    dlclose(g_halDeviceHandle);
    g_halDeviceHandle = NULL;
    (void)HksMutexUnlock(g_halDevicePtrMutex);
    return HKS_ERROR_NULL_POINTER;
}

ENABLE_CFI(int32_t HksDestroyHuksHdiDevice(struct HuksHdi **halDevice))
{
    if ((halDevice == NULL) || (*halDevice == NULL)) {
        return HKS_SUCCESS;
    }

    if (HksMutexLock(g_halDevicePtrMutex) != 0) {
        HKS_LOG_E("g_halDevicePtrMutex HksMutexLock failed");
        return HKS_FAILURE;
    }

    if ((halDevice == NULL) || (*halDevice == NULL)) {
        (void)HksMutexUnlock(g_halDevicePtrMutex);
        return HKS_SUCCESS;
    }

    if (g_halDeviceHandle == NULL) {
        (void)HksMutexUnlock(g_halDevicePtrMutex);
        HKS_LOG_E("g_halDeviceHandle is NULL!");
        return HKS_ERROR_NULL_POINTER;
    }

    HalDestroyHandle halDestroyHandle = (HalDestroyHandle)dlsym(g_halDeviceHandle, "HuksDestoryHdiDevicePtr");
    (*halDestroyHandle)(*halDevice);
    *halDevice = NULL;

    dlclose(g_halDeviceHandle);
    g_halDeviceHandle = NULL;
    (void)HksMutexUnlock(g_halDevicePtrMutex);

    return HKS_SUCCESS;
}

int32_t HksCreateHalDevicePtrMutex(void)
{
    if (g_halDevicePtrMutex == NULL) {
        g_halDevicePtrMutex = HksMutexCreate();
        HKS_IF_NULL_LOGE_RETURN(g_halDevicePtrMutex, HKS_FAILURE, "create g_halDevicePtrMutex fail")
    }
    return HKS_SUCCESS;
}

void HksDestroyHalDevicePtrMutex(void)
{
    if (g_halDevicePtrMutex != NULL) {
        HksMutexClose(g_halDevicePtrMutex);
        g_halDevicePtrMutex = NULL;
    }
}