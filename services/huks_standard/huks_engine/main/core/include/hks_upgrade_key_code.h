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

#ifndef HKS_UPGRADE_KEY_CODE_H
#define HKS_UPGRADE_KEY_CODE_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

enum HksUpgradeKeyCode {
    HKS_UPGRADE_CODE_BASE,

    // to do : only change version without any other change
    HKS_UPGRADE_CHANGE_KEH_VERSION,

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    HKS_UPGRADE_UPGRADE_KEY_OWNER,
#endif

    /* new code must be added before HKS_UPGRADE_CODE_MAX */
    HKS_UPGRADE_CODE_MAX,
};

#endif /* HKS_UPGRADE_KEY_CODE_H */
