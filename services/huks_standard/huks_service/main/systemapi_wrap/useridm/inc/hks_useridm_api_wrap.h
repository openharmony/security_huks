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

#ifndef HKS_USERIDM_API_WRAP_H
#define HKS_USERIDM_API_WRAP_H

#include "hks_type.h"
#include "hks_type_inner.h"
#include "hks_log.h"

#ifdef __cplusplus
#include <atomic>
#include <condition_variable>
#include <mutex>

namespace OHOS::Security::Hks {
class HksIpcCounter {
public:
    inline HksIpcCounter() = default;

    inline ~HksIpcCounter()
    {
        std::unique_lock<std::mutex> lck(mutex_);
        if (!threadsCountDecreased_) {
            --threadsCount_;
        }
        cv_.notify_one();
        HKS_LOG_I("after notify_one threadsCount_ %" LOG_PUBLIC "u waitCount_ %" LOG_PUBLIC "u",
            threadsCount_.load(), waitCount_.load());
    }

    [[nodiscard]] inline int32_t Wait()
    {
        std::unique_lock<std::mutex> lck(mutex_);
        ++threadsCount_;
        while (threadsCount_ > HUKS_IPC_THREAD_WITH_CALLBACK_ASYNC_TO_SYNC_PARALLEL_NUM_LIMIT) {
            if (waitCount_ >= HUKS_IPC_THREAD_WITH_CALLBACK_ASYNC_TO_SYNC_WAIT_NUM_LIMIT -
                HUKS_IPC_THREAD_WITH_CALLBACK_ASYNC_TO_SYNC_PARALLEL_NUM_LIMIT) {
                return LogErrorDecreaseThreadCount();
            }
            LogWarningWait(lck);
        }
        return HKS_SUCCESS;
    }

private:
    inline int32_t LogErrorDecreaseThreadCount()
    {
        HKS_LOG_E("wait queue full! %" LOG_PUBLIC
            "u can not wait! wait here will cause dead lock! return immediatelly!", waitCount_.load());
        threadsCountDecreased_ = true;
        --threadsCount_;
        return HKS_ERROR_SESSION_REACHED_LIMIT;
    }

    inline static void LogWarningWait(std::unique_lock<std::mutex> &lck)
    {
        ++waitCount_;
        HKS_LOG_W("begin wait waitCount_ %" LOG_PUBLIC "u", waitCount_.load());
        cv_.wait(lck);
        HKS_LOG_W("end wait waitCount_ %" LOG_PUBLIC "u", waitCount_.load());
        --waitCount_;
    }

    std::atomic_bool threadsCountDecreased_{};
    static inline std::atomic_uint32_t threadsCount_{};
    static inline std::atomic_uint32_t waitCount_{};
    static inline std::mutex mutex_{};
    static inline std::condition_variable cv_{};
};
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

// callback
int32_t HksUserIdmGetSecInfo(int32_t userId, struct SecInfoWrap **outSecInfo);

// callback
int32_t HksUserIdmGetAuthInfoNum(int32_t userId, enum HksUserAuthType hksAuthType, uint32_t *numOfAuthInfo);

int32_t HksConvertUserIamTypeToHksType(enum HksUserIamType type, uint32_t userIamValue, uint32_t *hksValue);

#ifdef __cplusplus
}
#endif

#endif // HKS_USERIDM_API_WRAP_H