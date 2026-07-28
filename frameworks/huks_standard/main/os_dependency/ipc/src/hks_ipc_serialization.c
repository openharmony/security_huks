/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type_enum.h"
#include "securec.h"

int32_t CopyBlobToBuffer(const struct HksBlob *blob, struct HksBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) ||
        ((destBlob->size - *destOffset) < (sizeof(blob->size) + ALIGN_SIZE(blob->size)))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &(blob->size),
        sizeof(blob->size)), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!")
    *destOffset += sizeof(blob->size);

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, blob->data,
        blob->size), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!")
    *destOffset += ALIGN_SIZE(blob->size);

    return HKS_SUCCESS;
}

int32_t GetBlobFromBuffer(struct HksBlob *blob, const struct HksBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || ((srcBlob->size - *srcOffset) < sizeof(uint32_t))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t size = *((uint32_t *)(srcBlob->data + *srcOffset));
    HKS_IF_TRUE_RETURN(IsAdditionOverflow(size, DEFAULT_ALIGN_MASK_SIZE), HKS_ERROR_INVALID_ARGUMENT)
    HKS_IF_TRUE_RETURN(ALIGN_SIZE(size) > srcBlob->size - *srcOffset - sizeof(uint32_t), HKS_ERROR_BUFFER_TOO_SMALL)

    blob->size = size;
    *srcOffset += sizeof(blob->size);
    blob->data = (uint8_t *)(srcBlob->data + *srcOffset);
    *srcOffset += ALIGN_SIZE(blob->size);
    return HKS_SUCCESS;
}

int32_t HksAllocInBlobWithThreeBlobs(struct HksBlob *inBlob, const struct HksBlob *blob1,
    const struct HksBlob *blob2, const struct HksBlob *blob3)
{
    if (inBlob == NULL || blob1 == NULL || blob2 == NULL || blob3 == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint32_t size = (uint32_t)(sizeof(blob1->size) + ALIGN_SIZE(blob1->size));
    size += (uint32_t)(sizeof(blob2->size) + ALIGN_SIZE(blob2->size));
    size += (uint32_t)(sizeof(blob3->size) + ALIGN_SIZE(blob3->size));

    inBlob->data = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_LOGE_RETURN(inBlob->data, HKS_ERROR_MALLOC_FAIL, "malloc inBlob fail");

    inBlob->size = size;
    return HKS_SUCCESS;
}

int32_t HksBlob3Unpack(const struct HksBlob *srcData, struct HksBlob *blob1,
    struct HksBlob *blob2, struct HksBlob *blob3)
{
    uint32_t offset = 0;
    int32_t ret = 0;

    do {
        ret = GetBlobFromBuffer(blob1, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get blob1 failed!");

        ret = GetBlobFromBuffer(blob2, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get blob2 failed!");

        ret = GetBlobFromBuffer(blob3, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get blob3 failed!");
    } while (0);
    return ret;
}

int32_t HksBlob3Pack(const struct HksBlob *blob1, const struct HksBlob *blob2,
    const struct HksBlob *blob3, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret;
    do {
        ret = CopyBlobToBuffer(blob1, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy blob1 failed");

        ret = CopyBlobToBuffer(blob2, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy blob2 failed");

        ret = CopyBlobToBuffer(blob3, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy blob3 failed");
    } while (0);
    return ret;
}