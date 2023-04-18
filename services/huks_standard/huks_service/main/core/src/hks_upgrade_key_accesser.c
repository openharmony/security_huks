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

#include "hks_upgrade_key_accesser.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef HKS_ENABLE_UPGRADE_KEY

#include "huks_access.h"
#include "hks_client_service_util.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type_inner.h"

#include "securec.h"

// add some mandatory params in service, the others mandatory params added in core
static int32_t AddMandatoryParamsInService(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    if (srcParamSet == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HksAddParams(targetParamSet, srcParamSet->params, srcParamSet->paramsCnt);
}

int32_t HksDoUpgradeKeyAccess(const struct HksBlob *oldKey, const struct HksParamSet *srcParamSet,
    struct HksBlob *newKey)
{
    int32_t ret = HKS_SUCCESS;
    struct HksParamSet *paramSet = NULL;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init paramSet failed!")

        ret = AddMandatoryParamsInService(srcParamSet, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddUpgradeParams failed!")

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramSet failed!")
        ret = HuksAccessUpgradeKey(oldKey, paramSet, newKey);
    } while (0);
    HksFreeParamSet(&paramSet);
    return ret;
}
#endif /* HKS_ENABLE_UPGRADE_KEY */
