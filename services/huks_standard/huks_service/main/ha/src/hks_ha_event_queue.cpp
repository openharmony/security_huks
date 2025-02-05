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
    std::unique_lock<std::mutex> lock(queueMutex_);
    HKS_LOG_I("Enqueue is start");
    if (paramSet == nullptr) {
        HKS_LOG_I("HksParamSet is nullptr, cannot enqueue eventId: %" LOG_PUBLIC "u", eventId);
        return false;
    }

    // 1. 检查是否已停止
    if (stopped_) {
        HKS_LOG_I("Enqueue stopped");
        return false;
    }

    // 2. 检查队列是否已满
    if (queueItem_.size() >= queueCapacity_) {
        HKS_LOG_I("Queue is full, cannot enqueue eventId: %" LOG_PUBLIC "u", eventId);
        return false;
    }
    
    // 3. 入队
    queueItem_.emplace(HksEventQueueItem{eventId, paramSet});
    HKS_LOG_I("Enqueued eventId %" LOG_PUBLIC "u", eventId);
    notEmpty.notify_one(); // 唤醒可能等待线程
    return true;
}

bool HksEventQueue::Dequeue(HksEventQueueItem& item)
{
    std::unique_lock<std::mutex> lock(queueMutex_);
    HKS_LOG_I("Dequeue is start");

    // 等待直到队列非空或停止
    notEmpty.wait(lock, [this]() { 
        return (!queueItem_.empty()) || stopped_; 
    });

    if (stopped_ && queueItem_.empty()) {
        HKS_LOG_I("Dequeue stopped");
        return false;
    }

    item = std::move(queueItem_.front());
    queueItem_.pop();
    HKS_LOG_I("Dequeued eventId %" LOG_PUBLIC "u", item.eventId);

    return true;
}

void HksEventQueue::Stop() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    stopped_ = true;
    // 唤醒所有等待的线程
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