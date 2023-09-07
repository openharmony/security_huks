/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HKS_AES_128 \
{ \
    .tag = HKS_TAG_KEY_SIZE, \
    .uint32Param = HKS_AES_KEY_SIZE_128 \
}, { \
    .tag = HKS_TAG_PADDING, \
    .uint32Param = HKS_PADDING_NONE \
}, { \
    .tag = HKS_TAG_BLOCK_MODE, \
    .uint32Param = HKS_MODE_CBC \
}

#define HKS_NONE_DIGEST_IV \
{ \
    .tag = HKS_TAG_DIGEST, \
    .uint32Param = HKS_DIGEST_NONE \
}, { \
    .tag = HKS_TAG_IV, \
    .blob = { \
        .size = IV_SIZE, \
        .data = (uint8_t *)IV \
    } \
}