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

bool HksEventQueue::Enqueue(uint32_t eventId, struct HksParamSet *paramSet)
{
    std::unique_lock<std::mutex> lock(queueMutex);

    HKS_LOG_I("Enqueue is start.................................");

    if (paramSet == nullptr) {
        HKS_LOG_E("HksParamSet is nullptr, cannot enqueue eventId: %u", eventId);
        return false;
    }

    notFull.wait(lock, [this]() { return queueItem.size() < queueCapacity; });

    queueItem.emplace(HksEventQueueItem{eventId, paramSet});
    notEmpty.notify_one();

    return true;
}

bool HksEventQueue::Dequeue(HksEventQueueItem& item)
{
    std::unique_lock<std::mutex> lock(queueMutex);

    HKS_LOG_I("Dequeue is start.................................");

    notEmpty.wait(lock, [this]() { return !queueItem.empty(); });

    if (queueItem.empty()) {
        return false;
    }

    item = std::move(queueItem.front());
    queueItem.pop();
    notFull.notify_one();

    return true;
}

uint32_t HksEventQueue::Size() const
{
    std::lock_guard<std::mutex> lock(queueMutex);
    return queueItem.size();
}

bool HksEventQueue::IsEmpty() const
{
    std::lock_guard<std::mutex> lock(queueMutex);
    return queueItem.empty();
}