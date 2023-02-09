/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_MANDATORY_PARAMS_H
#define HKS_MANDATORY_PARAMS_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_type_inner.h"

struct HksMandatoryParams {
    uint32_t keyVersion;
    uint32_t paramsLen;
    const uint32_t *params;
};

// only add mandatory params including huks parameters and key file encrypt materials
static const uint32_t HKS_MANDATORY_PARAM_VERSION_ONE[] = {
    HKS_TAG_KEY_VERSION,
    HKS_TAG_OS_VERSION,
    HKS_TAG_OS_PATCHLEVEL,
    HKS_TAG_PROCESS_NAME,
};

// same as version one
static const uint32_t HKS_MANDATORY_PARAM_VERSION_TWO[] = {
    HKS_TAG_KEY_VERSION,
    HKS_TAG_OS_VERSION,
    HKS_TAG_OS_PATCHLEVEL,
    HKS_TAG_PROCESS_NAME,
};

static const struct HksMandatoryParams HKS_MANDATORY_PARAMS[] = {
    {
        .keyVersion = 1,
        .paramsLen = HKS_ARRAY_SIZE(HKS_MANDATORY_PARAM_VERSION_ONE),
        .params = HKS_MANDATORY_PARAM_VERSION_ONE
    }, {
        .keyVersion = 2,
        .paramsLen = HKS_ARRAY_SIZE(HKS_MANDATORY_PARAM_VERSION_TWO),
        .params = HKS_MANDATORY_PARAM_VERSION_TWO
    }
};

#endif /* HKS_MANDATORY_PARAMS_H */
