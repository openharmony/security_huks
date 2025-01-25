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

#ifndef HKS_HA_EVENT_QUEUE_H
#define HKS_HA_EVENT_QUEUE_H

#ifdef __cplusplus

#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <cstdint>


constexpr uint32_t MAX_CAPACITY = 2048;

typedef struct {
    uint32_t eventId;
    struct HksParamSet *paramSet;
} HksEventQueueItem;

class HksEventQueue {
public:
    explicit HksEventQueue(uint32_t capacity = MAX_CAPACITY)
        : queueCapacity(capacity) {}

    bool Enqueue(uint32_t eventId, struct HksParamSet *paramSet);

    bool Dequeue(HksEventQueueItem& item);

    uint32_t Size() const;

    bool IsEmpty() const;

private:
    std::queue<HksEventQueueItem> queueItem;
    uint32_t queueCapacity;
    mutable std::mutex queueMutex;
    std::condition_variable notEmpty;
    std::condition_variable notFull;
};
#endif

#endif