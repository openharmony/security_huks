/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "hks_mem.h"

#if defined(HKS_USE_OHOS_MEM)
#include "ohos_mem_pool.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"

void *HksMalloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }
    void *ret = NULL;
#if defined(HKS_USE_OHOS_MEM)
    ret = OhosMalloc(MEM_TYPE_HICHAIN, size);
#else
    ret = malloc(size);
#endif
    if (ret == NULL) {
        return NULL;
    }
    (void)memset_s(ret, size, 0, size);
    return ret;
}

int32_t HksMemCmp(const void *ptr1, const void *ptr2, uint32_t size)
{
    return memcmp(ptr1, ptr2, size);
}

void HksFreeImpl(void *addr)
{
    if (addr == NULL) {
        return;
    }
#if defined(HKS_USE_OHOS_MEM)
    OhosFree(addr);
#else
    free(addr);
#endif
}
