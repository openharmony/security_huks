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

#include "hks_upgrade_key_accesser.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "huks_access.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type_inner.h"

#include "securec.h"

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
static int32_t HksAddParamsForSmallToService(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    if (srcParamSet == NULL) {
        HKS_LOG_E("none params for small to service failed!");
        return HKS_FAILURE;
    }
    struct HksParam *newProcessInfo = NULL;
    int32_t ret = HksGetParam(srcParamSet, HKS_TAG_PROCESS_NAME, &newProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "no new process info in param set!")
    ret = HksAddParams(targetParamSet, newProcessInfo, 1);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add params failed!")

    struct HksParam isNeedUpgradeKeyOwner = { .tag = HKS_TAG_NEED_CHANGE_KEY_OWNER, .boolParam = true };
    ret = HksAddParams(targetParamSet, &isNeedUpgradeKeyOwner, 1);
    
    return ret;
}

#endif

static int32_t CheckIsOptionalCodeLabeled(const struct HksOptionalUpgradeLabels *optionalLabels,
    enum HksOptionalUpgradeKeyCode code)
{
    if (optionalLabels == NULL) {
        return HKS_FAILURE;
    }
    for (uint32_t i = 0; i < optionalLabels->codeNum; ++i) {
        if (optionalLabels->optionalCodes[i] == code) {
            return HKS_SUCCESS;
        }
    }
    return HKS_FAILURE;
}

static int32_t AddDeterministicUpgradeParams(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    return HKS_SUCCESS;
}

static int32_t AddOptionalUpgradeParams(const struct HksParamSet *srcParamSet,
    const struct HksOptionalUpgradeLabels *optionalLabels, struct HksParamSet *targetParamSet)
{
    int32_t ret = HKS_SUCCESS;
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    if (CheckIsOptionalCodeLabeled(optionalLabels, HKS_OPTIONAL_UPGRADE_KEY_CHANGE_KEY_OWNER) == HKS_SUCCESS) {
        ret = HksAddParamsForSmallToService(srcParamSet, targetParamSet);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksAddParamsForSmallToService failed!")
    }
#endif
    return ret;
}

int32_t HksDoUpgradeKeyAccess(const struct HksBlob *oldKey, const struct HksParamSet *srcParamSet,
    const struct HksOptionalUpgradeLabels *optionalLabels, struct HksBlob *newKey)
{
    int32_t ret = HKS_SUCCESS;
    struct HksParamSet *paramSet = NULL;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init paramSet failed!")
        
        // add optional upgrade params
        ret = AddOptionalUpgradeParams(srcParamSet, optionalLabels, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddOptionalUpgradeParams failed!")

        // add deterministic upgrade params
        ret = AddDeterministicUpgradeParams(srcParamSet, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddDeterministicUpgradeParams failed!")

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramSet failed!")
        ret = HuksAccessUpgradeKey(oldKey, paramSet, newKey);
    } while (0);

    HksFreeParamSet(&paramSet);
    return ret;
}