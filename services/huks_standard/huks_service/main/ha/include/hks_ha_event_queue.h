#ifndef HKS_HA_EVENT_queueItem_H
#define HKS_HA_EVENT_queueItem_H

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