/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_check_white_list.h"
#include "hks_keyblob.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"

typedef int32_t (*HksUpgradeKeyAbility)(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, 
    struct HksBlob *newKey);

struct HksAbility {
    bool isValid;
    uint32_t id;
    HksUpgradeKeyAbility func;
};

static struct HksAbility g_upgradeAbilityList[HKS_UPGRADE_CODE_MAX] = { { 0 } };

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
static bool IsToChangedTag(const uint32_t *tagList, uint32_t tagCount, uint32_t paramTag)
{
    uint32_t i = 0;
    for (; i < tagCount; ++i) {
        if (paramTag == tagList[i]) {
            return true;
        }
    }
    return false;
}

static int32_t HksChangeOldKeyParams(const struct HksParamSet *paramSet,
    const struct HksParam *newProcessInfo, struct HksParamSet **outParamSet)
{
    uint32_t deleteTags[] = { HKS_TAG_PROCESS_NAME };
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append init operation param set failed")
        uint32_t i = 0;
        bool isFault = false;
        for (; i < paramSet->paramsCnt; ++i) {
            if (!IsToChangedTag(deleteTags, HKS_ARRAY_SIZE(deleteTags), paramSet->params[i].tag)) {
                ret = HksAddParams(newParamSet, &(paramSet->params[i]), 1);
                if (ret != HKS_SUCCESS) {
                    HKS_LOG_E("append param %" LOG_PUBLIC "u failed", paramSet->params[i].tag);
                    isFault = true;
                    break;
                }
            } else if (paramSet->params[i].tag == HKS_TAG_PROCESS_NAME){
                ret = HksAddParams(newParamSet, newProcessInfo, 1);
                
                if (ret != HKS_SUCCESS) {
                    HKS_LOG_E("append process name failed");
                    isFault = true;
                    break;
                }
            } else if (paramSet->params[i].tag == HKS_TAG_KEY_VERSION) {
                struct HksParam tmpParam;
                tmpParam.tag = HKS_TAG_KEY_VERSION;
                tmpParam.uint32Param = HKS_KEY_VERSION;
                ret = HksAddParams(newParamSet, &tmpParam, 1);
                
                if (ret != HKS_SUCCESS) {
                    HKS_LOG_E("append process name failed");
                    isFault = true;
                    break;
                }
            }
        }
        if (isFault) {
            break;
        }

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed")

        *outParamSet = newParamSet;
        return ret;
    } while (0);

    HksFreeParamSet(&newParamSet);
    return ret;
}

static int32_t HksAuthWhiteList(const struct HksParam *processInfo)
{
    uint32_t uid = 0;
    if (processInfo->blob.size == sizeof("0") && HksMemCmp(processInfo->blob.data, "0",
        processInfo->blob.size) == EOK) { // for uid == 0
        uid = 0;
    } else if (processInfo->blob.size == sizeof(uid)) {
        (void)memcpy_s(&uid, sizeof(uid), processInfo->blob.data, processInfo->blob.size);
    } else {
        return HKS_ERROR_NO_PERMISSION;
    }
    return HksCheckIsInWhiteList(uid);
}

static int32_t HksCheckKeyVersion(const struct HksParamSet *paramSet, uint32_t expectVersion)
{
    struct HksParam *keyVersion = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_VERSION, &keyVersion);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get key version failed!");
    if (keyVersion->uint32Param == expectVersion) {
        return HKS_SUCCESS;
    }

    // expected old version key not exist
    return HKS_ERROR_NOT_EXIST;
}

static int32_t HksUpgradeKeyOwner(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, 
    struct HksBlob *newKey)
{
    struct HksParam *newProcessInfo = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_PROCESS_NAME, &newProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "no new process info in param set!")

    ret = HksAuthWhiteList(newProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "not in white list")

    struct HksParamSet *newParamSet = NULL;
    struct HksKeyNode *keyNode = NULL;
    do {
        keyNode = HksGenerateKeyNode(oldKey);
        if (keyNode == NULL) {
            ret = HKS_ERROR_BAD_STATE;
            HKS_LOG_E("generate key node failed!");
            break;
        }

        ret = HksCheckKeyVersion(keyNode->paramSet, HKS_KEY_BLOB_DUMMY_KEY_VERSION);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "not a old key")

        ret = HksChangeOldKeyParams(keyNode->paramSet, newProcessInfo, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "change old key param failed!")
        
        ret = HksBuildKeyBlobWithOutAdd(newParamSet, newKey);
    } while (0);
    
    HksFreeParamSet(&newParamSet);
    HksFreeKeyNode(&keyNode);

    return ret;
}

#endif

static int32_t RegisterUpgradeKeyAbility(uint32_t id, HksUpgradeKeyAbility func)
{
    g_upgradeAbilityList[id].func = func;
    g_upgradeAbilityList[id].id = id;
    g_upgradeAbilityList[id].isValid = true;
    return HKS_SUCCESS;
}

int32_t HksDoUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, uint32_t upgradeTag,
    struct HksBlob *newKey)
{
    if (upgradeTag <= HKS_UPGRADE_CODE_BASE || upgradeTag >= HKS_UPGRADE_CODE_MAX ||
        !g_upgradeAbilityList[upgradeTag].isValid) {
        return HKS_ERROR_BAD_STATE;
    }
    int32_t ret = g_upgradeAbilityList[upgradeTag].func(oldKey, paramSet, newKey);
    return ret;
}

int32_t HksInitUpgradeKeyAbility(void)
{
    HKS_LOG_I("HksInitUpgradeKeyAbility");
    int32_t ret = HKS_SUCCESS;

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    ret = RegisterUpgradeKeyAbility(HKS_UPGRADE_UPGRADE_KEY_OWNER, HksUpgradeKeyOwner);
#endif

    return ret;
}