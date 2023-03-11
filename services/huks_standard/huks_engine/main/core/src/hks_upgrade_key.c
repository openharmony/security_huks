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

#include "hks_upgrade_key.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_keyblob.h"
#include "hks_log.h"
#include "hks_mandatory_params.h"
#include "hks_mem.h"
#include "hks_secure_access.h"
#include "hks_template.h"
#include "hks_type.h"

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
#include "hks_check_trust_list.h"
#endif

#include "securec.h"

#ifdef HKS_ENABLE_UPGRADE_KEY
static const struct HksMandatoryParams* GetMandatoryParams(uint32_t keyVersion)
{
    if (HKS_ARRAY_SIZE(HKS_MANDATORY_PARAMS) < keyVersion ||
        keyVersion == 0 || HKS_MANDATORY_PARAMS[keyVersion - 1].keyVersion != keyVersion) {
        HKS_LOG_E("get mandatory params for version %" LOG_PUBLIC "u failed!", keyVersion);
        return NULL;
    }
    return &HKS_MANDATORY_PARAMS[keyVersion - 1];
}

static bool IsTagInMandatoryArray(uint32_t tag, uint32_t keyVersion)
{
    const struct HksMandatoryParams *mandatoryParams = GetMandatoryParams(keyVersion);
    if (mandatoryParams == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < mandatoryParams->paramsLen; ++i) {
        if (tag == mandatoryParams->params[i]) {
            return true;
        }
    }
    return false;
}

static int32_t AddParamsWithoutMandatory(uint32_t keyVersion, const struct HksParamSet *srcParamSet,
    const struct HksParamSet *paramSet, struct HksParamSet *targetParamSet)
{
    (void)paramSet;
    int32_t ret = HKS_SUCCESS;

    for (uint32_t i = 0; i < srcParamSet->paramsCnt; ++i) {
        if (!IsTagInMandatoryArray(srcParamSet->params[i].tag, keyVersion)) {
            ret = HksAddParams(targetParamSet, &(srcParamSet->params[i]), 1);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("append param %" LOG_PUBLIC "u failed", srcParamSet->params[i].tag);
                break;
            }
        }
    }
    return ret;
}

static int32_t AddMandatoryParams(const struct HksParamSet *srcParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet *targetParamSet)
{
    int32_t ret = HKS_SUCCESS;
    uint32_t i = 0;
    const struct HksMandatoryParams* mandatoryParams = GetMandatoryParams(HKS_KEY_VERSION);
    for (; i < mandatoryParams->paramsLen; ++i) {
        struct HksParam *param = NULL;
        ret = HksGetParam(paramSet, mandatoryParams->params[i], &param);
        if (ret != HKS_SUCCESS) {
            ret = HksGetParam(srcParamSet, mandatoryParams->params[i], &param);
        }
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get param %" LOG_PUBLIC "u from srcParamSet and paramSet failed!",
            mandatoryParams->params[i])
        ret = HksAddParams(targetParamSet, param, 1);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add param %" LOG_PUBLIC "u into targetParamSet failed!",
            mandatoryParams->params[i])
    }
    return ret;
}

static int32_t AddMandatoryParamsInCore(const struct HksParamSet *srcParamSet, struct HksParamSet **targetParamSet)
{
    struct HksParamSet *outParamSet = NULL;
    int32_t ret;
    do {
        ret = HksInitParamSet(&outParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init paramset failed!")

        ret = HksAddParams(outParamSet, srcParamSet->params, srcParamSet->paramsCnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add params from srcParamSet to targetParamSet failed!")

        struct HksParam HksParamKeyVerison = { .tag = HKS_TAG_KEY_VERSION, .uint32Param = HKS_KEY_VERSION };
        ret = HksAddParams(outParamSet, &HksParamKeyVerison, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param HksParamKeyVerison failed!")

        struct HksParam HksParamOsLevel = { .tag = HKS_TAG_OS_VERSION, .uint32Param = HKS_KEY_BLOB_DUMMY_OS_VERSION };
        ret = HksAddParams(outParamSet, &HksParamOsLevel, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param HksParamOsLevel failed!")

        struct HksParam HksOsPatchLevel = { .tag = HKS_TAG_OS_PATCHLEVEL,
            .uint32Param = HKS_KEY_BLOB_DUMMY_OS_PATCHLEVEL };
        ret = HksAddParams(outParamSet, &HksOsPatchLevel, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param HksOsPatchLevel failed!")
        *targetParamSet = outParamSet;
        return ret;
    } while (0);
    HksFreeParamSet(&outParamSet);
    return ret;
}

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
// only enable to skip process info verify when the file-owner-change is needed and the target uid is in the white list
static int32_t HksIsToSkipProcessVerify(const struct HksParamSet *paramSet)
{
    struct HksParam *processName;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_PROCESS_NAME, &processName);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get process name from paramset failed!")
    uint32_t uid = 0;
    if (processName->blob.size == sizeof(uid)) {
        (void)memcpy_s(&uid, sizeof(uid), processName->blob.data, processName->blob.size);
    } else {
        return HKS_ERROR_NO_PERMISSION;
    }

    return HksCheckIsInTrustList(uid);
}
#endif

static int32_t AuthChangeProcessName(const struct HksParamSet *oldKeyBlobParamSet, const struct HksParamSet *paramSet)
{
    struct HksParam *oldProcessName;
    int32_t ret = HksGetParam(oldKeyBlobParamSet, HKS_TAG_PROCESS_NAME, &oldProcessName);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get process name from old key paramset failed!")

    struct HksParam *newProcessName;
    ret = HksGetParam(paramSet, HKS_TAG_PROCESS_NAME, &newProcessName);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_SUCCESS, "not to change process name, skip the process name auth")

    if (oldProcessName->blob.size != newProcessName->blob.size ||
        HksMemCmp(oldProcessName->blob.data, newProcessName->blob.data, oldProcessName->blob.size) != HKS_SUCCESS) {
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
        uint32_t uid = 0;
        ret = memcpy_s(&uid, sizeof(uid), newProcessName->blob.data, newProcessName->blob.size);
        if (ret != EOK) {
            return HKS_ERROR_NO_PERMISSION;
        }
        ret = HksCheckIsInTrustList(uid);
#else
        return HKS_FAILURE;
#endif
    }
    return ret;
}

static int32_t AuthUpgradeKey(const struct HksParamSet *oldKeyBlobParamSet, const struct HksParamSet *paramSet)
{
    int32_t ret;
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    ret = HksIsToSkipProcessVerify(paramSet);
    if (ret != HKS_SUCCESS) {
#endif
        ret = HksProcessIdentityVerify(oldKeyBlobParamSet, paramSet);
        if (ret != HKS_SUCCESS) {
            return ret;
        }
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    }
#endif

    return AuthChangeProcessName(oldKeyBlobParamSet, paramSet);
}

int32_t HksUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, struct HksBlob *newKey)
{
    HKS_LOG_I("enter HksUpgradeKey");
    int32_t ret;
    struct HksParamSet *oldKeyBlobParamSet = NULL;
    struct HksParamSet *newKeyBlobParamSet = NULL;
    struct HksKeyNode *keyNode = NULL;
    struct HksParamSet *newMandatoryeParamSet = NULL;
    do {
        keyNode = HksGenerateKeyNode(oldKey);
        if (keyNode == NULL) {
            ret = HKS_ERROR_BAD_STATE;
            HKS_LOG_E("generate key node failed!");
            break;
        }

        ret = HksInitParamSet(&newKeyBlobParamSet);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = HksGetParamSet(keyNode->paramSet, keyNode->paramSet->paramSetSize, &oldKeyBlobParamSet);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = AuthUpgradeKey(oldKeyBlobParamSet, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "auth upgrade key param failed!")

        struct HksParam *keyVersion = NULL;
        ret = HksGetParam(oldKeyBlobParamSet, HKS_TAG_KEY_VERSION, &keyVersion);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key version failed!")

        ret = AddMandatoryParamsInCore(paramSet, &newMandatoryeParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddMandatoryParamsInCore failed!")

        // the key param must be the last one added
        ret = AddMandatoryParams(oldKeyBlobParamSet, newMandatoryeParamSet, newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddMandatoryParams failed!")

        ret = AddParamsWithoutMandatory(keyVersion->uint32Param, oldKeyBlobParamSet, newMandatoryeParamSet,
            newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddParamsWithoutMandatory failed!")

        ret = HksBuildParamSet(&newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build newKeyBlobParamSet failed!")

        ret = HksBuildKeyBlobWithOutAddKeyParam(newKeyBlobParamSet, newKey);
    } while (0);

    HksFreeParamSet(&newKeyBlobParamSet);
    HksFreeParamSet(&oldKeyBlobParamSet);
    HksFreeParamSet(&newMandatoryeParamSet);
    HksFreeKeyNode(&keyNode);

    return ret;
}

#else /* HKS_ENABLE_UPGRADE_KEY */
int32_t HksUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, struct HksBlob *newKey)
{
    (void)oldKey;
    (void)paramSet;
    (void)newKey;
    return HKS_SUCCESS;
}
#endif