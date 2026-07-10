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

#include <string>
#include <mutex>

#include "hks_log.h"
#include "hks_error_code.h"
#include "hks_template.h"

#ifdef L2_STANDARD
#ifdef HKS_SUPPORT_ACCESS_TOKEN
#include "hks_permission_check.h"
#endif
#endif

static int32_t g_seCallCount = 0;
constexpr static int32_t MAX_SE_CALL_COUNT = 4;
static std::mutex g_seCallMutex{};

int32_t HksSePermissionCheck(void)
{
#ifdef L2_STANDARD
#ifdef HKS_SUPPORT_ACCESS_TOKEN
    int32_t ret = SensitivePermissionCheck("ohos.permission.ACCESS_SE_KEY");
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Se permission check failed.")
    return HKS_SUCCESS;
#else
    HKS_LOG_E("HKS_SUPPORT_ACCESS_TOKEN is not enabled, Se permission check not supported.");
    return HKS_ERROR_NOT_SUPPORTED;
#endif
#else
    HKS_LOG_E("L2_STANDARD is not enabled, Se permission check not supported.");
    return HKS_ERROR_NOT_SUPPORTED;
#endif
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
