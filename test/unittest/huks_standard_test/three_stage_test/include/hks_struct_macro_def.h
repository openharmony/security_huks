/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define HKS_AGREE_FINISH_ECDH_256_COMMON \
{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH}, \
{.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE}, \
{.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256}

#define HKS_DERIVE_FINISH_AES_256_COMMON \
{.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT}, \
{.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true}, \
{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES}, \
{.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256}, \
{.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT}, \
{.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},

#define HKS_DERIVE_FINISH_AES_256_COMMON_01 \
{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES}, \
{.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256}, \
{.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT}, \
{.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},

#define HKS_DERIVE_FINISH_AES_256_COMMON_02 \
{.tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true}, \
{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES}, \
{.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256}, \
{.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT}, \
{.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
