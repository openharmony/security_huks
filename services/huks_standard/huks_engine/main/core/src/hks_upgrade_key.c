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
#include "hks_tags_type_manager.h"
#include "hks_mem.h"
#include "hks_secure_access.h"
#include "hks_template.h"
#include "hks_type.h"

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
#include "hks_check_trust_list.h"
#endif

#include "securec.h"

#ifdef HKS_ENABLE_UPGRADE_KEY
static bool IsTagInAlgTagsList(uint32_t tag)
{
    uint32_t *tagList = NULL;
    uint32_t listSize = 0;
    HksGetAlgTagsList(&tagList, &listSize);
    for (uint32_t i = 0; i < listSize; ++i) {
        if (tag == tagList[i]) {
            return true;
        }
    }
    return false;
}

static int32_t AddAlgParamsTags(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    int32_t ret = HKS_SUCCESS;

    for (uint32_t i = 0; i < srcParamSet->paramsCnt; ++i) {
        if (IsTagInAlgTagsList(srcParamSet->params[i].tag)) {
            ret = HksAddParams(targetParamSet, &(srcParamSet->params[i]), 1);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("append param %" LOG_PUBLIC "u failed", srcParamSet->params[i].tag);
                break;
            }
        }
    }
    return ret;
}

static int32_t AddMandatoryParams(const struct HksParamSet *paramSet, struct HksParamSet *targetParamSet)
{
    uint32_t *tagList = NULL;
    uint32_t listSize = 0;
    HksGetKeyFileTagsList(&tagList, &listSize);
    int32_t ret = HKS_SUCCESS;
    for (uint32_t i = 0; i < listSize; ++i) {
        struct HksParam *param = NULL;
        ret = HksGetParam(paramSet, tagList[i], &param);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get param %" LOG_PUBLIC "u from paramSet failed!", tagList[i])
        ret = HksAddParams(targetParamSet, param, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param %" LOG_PUBLIC "u into targetParamSet failed!", tagList[i])
    }
    return ret;
}

typedef int32_t (*HksAddUpgradeParam)(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet);

struct HksAddUpgradeParamFuncMap {
    uint32_t paramTag;
    HksAddUpgradeParam func;
};

static int32_t HksAddKeyVersionToParamSet(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    (void)srcParamSet;
    struct HksParam HksParamKeyVerison = { .tag = HKS_TAG_KEY_VERSION, .uint32Param = HKS_KEY_VERSION };
    return HksAddParams(targetParamSet, &HksParamKeyVerison, 1);
}

static int32_t HksAddOsVersionToParamSet(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    (void)srcParamSet;
    struct HksParam HksParamOsVersion = { .tag = HKS_TAG_OS_VERSION, .uint32Param = HKS_KEY_BLOB_DUMMY_OS_VERSION };
    return HksAddParams(targetParamSet, &HksParamOsVersion, 1);
}

static int32_t HksAddOsPatchToParamSet(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    (void)srcParamSet;
    struct HksParam HksOsPatchLevel = { .tag = HKS_TAG_OS_PATCHLEVEL,
            .uint32Param = HKS_KEY_BLOB_DUMMY_OS_PATCHLEVEL };
    return HksAddParams(targetParamSet, &HksOsPatchLevel, 1);
}

static int32_t HksAddkeyToParamSet(const struct HksParamSet *srcParamSet, struct HksParamSet *targetParamSet)
{
    struct HksParam *keyParam = NULL;
    int32_t ret = HksGetParam(srcParamSet, HKS_TAG_KEY, &keyParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get param key failed!")
    return HksAddParams(targetParamSet, keyParam, 1);
}

static const struct HksAddUpgradeParamFuncMap HKS_ADD_MANDATORY_FUNC_LIST[] = {
    {
        .paramTag = HKS_TAG_KEY_VERSION,
        .func = HksAddKeyVersionToParamSet
    }, {
        .paramTag = HKS_TAG_OS_VERSION,
        .func = HksAddOsVersionToParamSet
    }, {
        .paramTag = HKS_TAG_OS_PATCHLEVEL,
        .func = HksAddOsPatchToParamSet
    }, {
        .paramTag = HKS_TAG_KEY,
        .func = HksAddkeyToParamSet
    },
};

static int32_t AddMandatoryParamsInCore(const struct HksParamSet *oldKeyBlobParamSet,
    const struct HksParamSet *srcParamSet, struct HksParamSet **targetParamSet)
{
    struct HksParamSet *outParamSet = NULL;
    int32_t ret;
    do {
        ret = HksInitParamSet(&outParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init paramset failed!")

        ret = HksAddParams(outParamSet, srcParamSet->params, srcParamSet->paramsCnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add params from srcParamSet to targetParamSet failed!")

        uint32_t funcArraySize = HKS_ARRAY_SIZE(HKS_ADD_MANDATORY_FUNC_LIST);
        for (uint32_t i = 0; i < funcArraySize; ++i) {
            ret = HKS_ADD_MANDATORY_FUNC_LIST[i].func(oldKeyBlobParamSet, outParamSet);
            if (ret != HKS_SUCCESS) {
                HksFreeParamSet(&outParamSet);
                HKS_LOG_E("add upgrade param %" LOG_PUBLIC "u failed!", i);
                return ret;
            }
        }

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

static void CleanParamSetKey(const struct HksParamSet *paramSet)
{
    struct HksParam *keyParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY, &keyParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get key param failed!");
        return;
    }
    (void)memset_s(keyParam->blob.data, keyParam->blob.size, 0, keyParam->blob.size);
}

static int32_t CheckIsNeedToUpgradeKey(const struct HksParamSet *oldKeyBlobParamSet, const struct HksParamSet *paramSet)
{
    int32_t ret = AuthUpgradeKey(oldKeyBlobParamSet, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "auth upgrade key param failed!")

    struct HksParam *keyVersion = NULL;
    ret = HksGetParam(oldKeyBlobParamSet, HKS_TAG_KEY_VERSION, &keyVersion);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get key version failed!")

    if (keyVersion->uint32Param >= HKS_KEY_VERSION) {
        HKS_LOG_E("key version is already up to date!");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static int32_t ConstructNewKeyParamSet(const struct HksParamSet *oldKeyBlobParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **outKeyBlobParamSet)
{
    int32_t ret;
    struct HksParamSet *newMandatoryParamSet = NULL;
    struct HksParamSet *newKeyBlobParamSet = NULL;
    do {
        ret = AddMandatoryParamsInCore(oldKeyBlobParamSet, paramSet, &newMandatoryParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddMandatoryParamsInCore failed!")

        ret = HksInitParamSet(&newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksInitParamSet failed!")

        ret = AddAlgParamsTags(oldKeyBlobParamSet, newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddAlgParamsTags failed!")

        // the key param must be the last one added
        ret = AddMandatoryParams(newMandatoryParamSet, newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddMandatoryParams failed!")

        ret = HksBuildParamSet(&newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build newKeyBlobParamSet failed!")

        ret = HksCheckParamSetTag(newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckParamSetTag failed!")

        *outKeyBlobParamSet = newKeyBlobParamSet;
        HksFreeParamSet(&newMandatoryParamSet);
        return HKS_SUCCESS;
    } while (0);
    HksFreeParamSet(&newMandatoryParamSet);

    CleanParamSetKey(newKeyBlobParamSet);
    HksFreeParamSet(&newKeyBlobParamSet);
    return ret;
}

int32_t HksUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, struct HksBlob *newKey)
{
    HKS_LOG_I("enter HksUpgradeKey");
    int32_t ret;
    struct HksParamSet *oldKeyBlobParamSet = NULL;
    struct HksParamSet *newKeyBlobParamSet = NULL;
    struct HksKeyNode *keyNode = NULL;
    do {
        keyNode = HksGenerateKeyNode(oldKey);
        if (keyNode == NULL) {
            ret = HKS_ERROR_BAD_STATE;
            HKS_LOG_E("generate key node failed!");
            break;
        }

        ret = HksGetParamSet(keyNode->paramSet, keyNode->paramSet->paramSetSize, &oldKeyBlobParamSet);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = CheckIsNeedToUpgradeKey(oldKeyBlobParamSet, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckIsNeedToUpgradeKey failed!")

        ret = ConstructNewKeyParamSet(oldKeyBlobParamSet, paramSet, &newKeyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ConstructNewKeyParamSet failed!")

        ret = HksBuildKeyBlobWithOutAddKeyParam(newKeyBlobParamSet, newKey);
    } while (0);
    CleanParamSetKey(newKeyBlobParamSet);
    HksFreeParamSet(&newKeyBlobParamSet);

    CleanParamSetKey(oldKeyBlobParamSet);
    HksFreeParamSet(&oldKeyBlobParamSet);

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