/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_IPC_SERIALIZATION_IN_BOTH_H
#define HKS_IPC_SERIALIZATION_IN_BOTH_H

#include <stdbool.h>
#include <stdint.h>

#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CopyBlobToBuffer(const struct HksBlob *blob, const struct HksBlob *destBlob, uint32_t *destOffset);

int32_t HksBlob3Unpack(const struct HksBlob *srcData, struct HksBlob *blob1,
    struct HksBlob *blob2, struct HksBlob *blob3);

int32_t HksAllocInBlobWithThreeBlobs(struct HksBlob *inBlob, const struct HksBlob *blob1,
    const struct HksBlob *blob2, const struct HksBlob *blob3);

int32_t GetBlobFromBuffer(struct HksBlob *blob, const struct HksBlob *srcBlob, uint32_t *srcOffset);

int32_t HksBlob3Pack(const struct HksBlob *blob1, const struct HksBlob *blob2,
    const struct HksBlob *blob3, struct HksBlob *destData);

#ifdef __cplusplus
}
#endif

#endif