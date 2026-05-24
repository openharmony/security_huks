/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_se_api_wrap.h"

#include <dlfcn.h>
#include <cstring>
#include <string>
#include <mutex>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_error_code.h"
#include "hks_template.h"

typedef int32_t (*CheckSeCapabilityFunc)(int32_t uid, bool &hasCapability);

static void *g_seHandle = nullptr;
static CheckSeCapabilityFunc g_checkSeCapability = nullptr;
static std::atomic_int32_t g_seRefCount = 0;
static std::mutex g_seMutex{};

static int32_t g_seCallCount = 0;
constexpr static int32_t MAX_SE_CALL_COUNT = 4;
static std::mutex g_seCallMutex{};

int32_t HksSePermissionCheck(const struct HksProcessInfo *processInfo)
{
    HKS_IF_TRUE_LOGE_RETURN(processInfo == nullptr, HKS_ERROR_NULL_POINTER, "processInfo is nullptr.")

    CheckSeCapabilityFunc checkSeCapability = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_seMutex);
        if (g_seRefCount == 0) {
            g_seHandle = dlopen("libtrusted_auth_ext.so", RTLD_LAZY);
            if (g_seHandle == nullptr) {
                HKS_LOG_E("Failed to load se library: %" LOG_PUBLIC "s", dlerror());
                return HKS_ERROR_BAD_STATE;
            }
            g_checkSeCapability = reinterpret_cast<CheckSeCapabilityFunc>(
                dlsym(g_seHandle, "CheckAccessSeCapability"));
            if (g_checkSeCapability == nullptr) {
                HKS_LOG_E("Failed to get se check permission function: %" LOG_PUBLIC "s", dlerror());
                dlclose(g_seHandle);
                g_seHandle = nullptr;
                return HKS_ERROR_BAD_STATE;
            }
        }
        g_seRefCount++;
        checkSeCapability = g_checkSeCapability;
    }

    bool hasCapability = false;
    int32_t result = checkSeCapability(processInfo->uidInt, hasCapability);

    {
        std::lock_guard<std::mutex> lock(g_seMutex);
        g_seRefCount--;
        if (g_seRefCount == 0) {
            dlclose(g_seHandle);
            g_seHandle = nullptr;
            g_checkSeCapability = nullptr;
        }
    }

    HKS_IF_TRUE_LOGE_RETURN((result != 0 || !hasCapability), HKS_ERROR_NO_PERMISSION,
        "Se permission check failed, ret = 0x%" LOG_PUBLIC "x", result)

    return HKS_SUCCESS;
}

int32_t HksSeIncrementSeCount(void)
{
    std::lock_guard<std::mutex> lock(g_seCallMutex);
    HKS_IF_TRUE_LOGE_RETURN(g_seCallCount >= MAX_SE_CALL_COUNT, HKS_ERROR_SE_COUNT_EXCEED_LIMIT,
        "SE call count exceeds limit.")

    g_seCallCount++;
    HKS_LOG_I("Increment se Call Count is %" LOG_PUBLIC "d", g_seCallCount);
    return HKS_SUCCESS;
}

int32_t HksSeDecrementSeCount(void)
{
    std::lock_guard<std::mutex> lock(g_seCallMutex);
    g_seCallCount--;
    HKS_LOG_I("Decrement se Call Count is %" LOG_PUBLIC "u", g_seCallCount);
    return HKS_SUCCESS;
}
