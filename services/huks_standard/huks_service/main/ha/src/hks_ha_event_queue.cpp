/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hks_ha_event_queue.h"
#include "hks_log.h"
#include "hks_template.h"

bool HksEventQueue::Enqueue(uint32_t eventId, struct HksParamSet *paramSet)
{
    std::unique_lock<std::mutex> lock(queueMutex_);
    HKS_IF_NULL_LOGE_RETURN(paramSet, false,
        "HksParamSet is nullptr, cannot enqueue eventId: %" LOG_PUBLIC "u", eventId)

    // 1. Check if already stopped
    HKS_IF_TRUE_LOGI_RETURN(stopped_, false, "Enqueue stopped")

    // 2. Check if the queue is full
    HKS_IF_TRUE_LOGI_RETURN(queueItem_.size() >= queueCapacity_, false,
        "Queue is full, cannot enqueue eventId: %" LOG_PUBLIC "u", eventId)
    
    // 3. Enqueue
    queueItem_.emplace(HksEventQueueItem{eventId, paramSet});
    notEmpty.notify_one();
    return true;
}

bool HksEventQueue::Dequeue(HksEventQueueItem& item)
{
    std::unique_lock<std::mutex> lock(queueMutex_);

    // Wait until the queue is not empty or stopped
    notEmpty.wait(lock, [this]() {
        return (!queueItem_.empty()) || stopped_;
    });

    HKS_IF_TRUE_LOGI_RETURN(stopped_ && queueItem_.empty(), false, "Dequeue stopped")

    item = std::move(queueItem_.front());
    queueItem_.pop();

    return true;
}

void HksEventQueue::Stop()
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    stopped_ = true;
    notEmpty.notify_all();
}

uint32_t HksEventQueue::Size() const
{
    return queueItem_.size();
}

bool HksEventQueue::IsEmpty() const
{
    return queueItem_.empty();
}