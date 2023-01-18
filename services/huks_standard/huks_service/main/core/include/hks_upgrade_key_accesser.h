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

#ifndef HKS_UPGRADE_KEY_ACCESSER_H
#define HKS_UPGRADE_KEY_ACCESSER_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_param.h"
#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

enum HksOptionalUpgradeKeyCode {
    HKS_OPTIONAL_UPGRADE_KEY_CODE_BASE = 0,
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    HKS_OPTIONAL_UPGRADE_KEY_CHANGE_KEY_OWNER,
#endif

    HKS_OPTIONAL_UPGRADE_KEY_CODE_MAX,
};

struct HksOptionalUpgradeLabels {
    uint32_t codeNum;
    uint32_t *optionalCodes;
};

int32_t HksDoUpgradeKeyAccess(const struct HksBlob *oldKey, const struct HksParamSet *srcParamSet,
    const struct HksOptionalUpgradeLabels *optionalLabels, struct HksBlob *newKey);

#ifdef __cplusplus
}
#endif

#endif /* HKS_UPGRADE_KEY_ACCESSER_H */
