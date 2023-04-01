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

#include "hks_check_trust_list.h"

#include "hks_log.h"

static const uint32_t g_trustList[] = HUKS_UID_TRUST_LIST;

int32_t HksCheckIsInTrustList(uint32_t uid)
{
    uint32_t listSize = HKS_ARRAY_SIZE(g_trustList);
    int32_t ret = HKS_ERROR_NO_PERMISSION;
    uint32_t i = 0;
    for (; i < listSize; ++i) {
        if (uid == g_trustList[i]) {
            ret = HKS_SUCCESS;
            break;
        }
    }
    return ret;
}
