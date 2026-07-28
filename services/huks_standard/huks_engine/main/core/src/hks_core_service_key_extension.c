/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_core_service_key_extension.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "securec.h"

#ifndef _CUT_AUTHENTICATE_

int32_t HksCoreWrapKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *wrappedKey)
{
    (void)keyAlias;
    (void)key;
    (void)paramSet;
    (void)wrappedKey;
    return HKS_ERROR_API_NOT_SUPPORTED;
}

int32_t HksCoreUnwrapKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappedKey,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    (void)keyAlias;
    (void)wrappedKey;
    (void)paramSet;
    (void)keyOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
}

#endif /* _CUT_AUTHENTICATE_ */
