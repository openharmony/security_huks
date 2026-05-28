/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef HKS_FUZZ_STATS_H
#define HKS_FUZZ_STATS_H

#include <cstdint>
#include <cstdio>

namespace OHOS {
namespace Security {
namespace Hks {

[[maybe_unused]] static inline void FuzzStatsRecord(int32_t result)
{
    static size_t execCount = 0;
    static size_t errorCounts[1001] = {0}; // index i -> error code = -i

    if (result <= 0 && result >= -1000) {
        errorCounts[-result]++;
    }

    execCount++;

    if ((execCount % 100000) == 0) {
        printf("\n=== Cumulative Error Stats (total runs: %zu) ===\n", execCount);
        for (int i = 0; i <= 1000; ++i) {
            if (errorCounts[i] != 0) {
                printf("Error %d: %zu times\n", -i, errorCounts[i]);
            }
        }
        printf("===========================================================\n\n");
        fflush(stdout);
    }
}

}
}
}

#endif