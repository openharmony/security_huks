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

typedef int32_t (*HksAddUpgradeParam)(const struct HksParamSet *keyBlobParamSet, const struct HksParamSet *srcParamSet,
    struct HksParamSet *targetParamSet);

struct HksAddUpgradeParamFuncMap {
    uint32_t paramTag;
    HksAddUpgradeParam func;
};

static int32_t HksAddProcessNameToParamSet(const struct HksParamSet *keyBlobParamSet,
    const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    (void)keyBlobParamSet;
    if (srcParamSet == NULL) {
        HKS_LOG_E("none params for small to service failed!");
        return HKS_FAILURE;
    }
    struct HksParam *srcProcessInfo = NULL;
    int32_t ret = HksGetParam(srcParamSet, HKS_TAG_PROCESS_NAME, &srcProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get param process name failed!")

    return HksAddParams(targetParamSet, srcProcessInfo, 1);
}

static const struct HksAddUpgradeParamFuncMap HKS_ADD_MANDATORY_FUNC_LIST[] = {
    {
        .paramTag = HKS_TAG_PROCESS_NAME,
        .func = HksAddProcessNameToParamSet
    },
};

// add some mandatory params in service, the others mandatory params added in core
static int32_t AddMandatoryeParamsInService(const struct HksParamSet *keyBlobParamSet,
    const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    int32_t ret = HKS_SUCCESS;

    uint32_t funcArraySize = HKS_ARRAY_SIZE(HKS_ADD_MANDATORY_FUNC_LIST);
    uint32_t i = 0;
    for (; i < funcArraySize; ++i) {
        ret = HKS_ADD_MANDATORY_FUNC_LIST[i].func(keyBlobParamSet, srcParamSet, targetParamSet);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add upgrade param %" LOG_PUBLIC "u failed!", i)
    }

    return ret;
}

int32_t HksDoUpgradeKeyAccess(const struct HksBlob *oldKey, const struct HksParamSet *srcParamSet,
    struct HksBlob *newKey)
{
    int32_t ret = HKS_SUCCESS;
    struct HksParamSet *paramSet = NULL;
    struct HksParamSet *keyBlobParamSet = NULL;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init paramSet failed!")
        const struct HksParamSet *oldKeyParamSet = (const struct HksParamSet *)oldKey->data;

        keyBlobParamSet = (struct HksParamSet *)HksMalloc(oldKeyParamSet->paramSetSize);
        if (keyBlobParamSet == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        (void)memcpy_s(keyBlobParamSet, oldKeyParamSet->paramSetSize, oldKeyParamSet, oldKeyParamSet->paramSetSize);

        ret = HksFreshParamSet(keyBlobParamSet, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "fresh paramset from old key failed!")

        ret = AddMandatoryeParamsInService(keyBlobParamSet, srcParamSet, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddUpgradeParams failed!")

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramSet failed!")
        ret = HuksAccessUpgradeKey(oldKey, paramSet, newKey);
    } while (0);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&keyBlobParamSet);
    return ret;
}
#endif /* HKS_ENABLE_UPGRADE_KEY */
