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

#include "hks_upgrade_key_manager.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_keyblob.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_upgrade_key.h"

#include "securec.h"

typedef int32_t (*UpgradeFuncPtr)(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet);

struct HksUpgradeFuncAbility {
    bool isValid;
    uint32_t upgradeVersion;
    UpgradeFuncPtr func;
};

// base version for upgrade
enum HksUpgradeVersionId {
    HKS_UPGRADE_VERSION_BASE = 0,
    HKS_UPGRADE_VERSION_ONE,

    HKS_UPGRADE_VERSION_MAX,
};

static struct HksUpgradeFuncAbility g_upgradeFuncList[HKS_UPGRADE_VERSION_MAX + 1] = { { 0 } };

static int32_t RegisterUpgradeFuncAbility(enum HksUpgradeVersionId versionId, UpgradeFuncPtr func)
{
    if (versionId <= HKS_UPGRADE_VERSION_BASE || versionId > HKS_UPGRADE_VERSION_MAX) {
        return HKS_ERROR_BAD_STATE;
    }
    g_upgradeFuncList[versionId].upgradeVersion = versionId;
    g_upgradeFuncList[versionId].func = func;
    g_upgradeFuncList[versionId].isValid = true;
    return HKS_SUCCESS;
}

static int32_t UpgradeFuncOneToTwo(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet)
{
    int32_t ret = HKS_SUCCESS;
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    do {
        ret = HksDoUpgradeKey(oldKeyParamSet, paramSet, HKS_UPGRADE_UPGRADE_KEY_OWNER, newKeyParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "access change key owner failed!")
    } while (0);
#endif

    return ret;
}

static int32_t UpgradeKeyToNewestVersion(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet)
{
    int32_t ret;
    ret = HksDoUpgradeKey(oldKeyParamSet, paramSet, HKS_UPGRADE_UPGRADE_KEY_VERSION, newKeyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "access change key owner failed!")
    return ret;
}

int32_t HksUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, struct HksBlob *newKey)
{
    HKS_LOG_I("enter HksUpgradeKey");
    int32_t ret;
    struct HksParamSet *oldParamSet = NULL;
    struct HksParamSet *newParamSet = NULL;
    struct HksKeyNode *keyNode = NULL;
    do {
        keyNode = HksGenerateKeyNode(oldKey);
        if (keyNode == NULL) {
            ret = HKS_ERROR_BAD_STATE;
            HKS_LOG_E("generate key node failed!");
            break;
        }
        struct HksParam *keyVersion = NULL;
        ret = HksGetParam(keyNode->paramSet, HKS_TAG_KEY_VERSION, &keyVersion);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get key version failed!");

        ret = HksGetParamSet(keyNode->paramSet, keyNode->paramSet->paramSetSize, &newParamSet);

        if (ret != HKS_SUCCESS) {
            break;
        }
        for (uint32_t i = keyVersion->uint32Param; i <= HKS_UPGRADE_VERSION_MAX; ++i) {
            HKS_LOG_I("upgrade key from %" LOG_PUBLIC "u", i);
            if (g_upgradeFuncList[i].isValid) {
                HksFreeParamSet(&oldParamSet);
                ret = HksGetParamSet(newParamSet, newParamSet->paramSetSize, &oldParamSet);
                if (ret != HKS_SUCCESS) {
                    break;
                }
                HksFreeParamSet(&newParamSet);
                ret = g_upgradeFuncList[i].func(oldParamSet, paramSet, &newParamSet);
                if (ret != HKS_SUCCESS) {
                    break;
                }
            }
        }
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HksBuildKeyBlobWithOutAdd(newParamSet, newKey);
    } while (0);
    
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&oldParamSet);
    HksFreeKeyNode(&keyNode);

    return ret;
}

int32_t HksUpgradeKeyFuncInit(void)
{
    HKS_LOG_I("HksUpgradeKeyFuncInit");
    int32_t ret = HksInitUpgradeKeyAbility();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksInitUpgradeKeyAbility failed!")
    ret = RegisterUpgradeFuncAbility(HKS_UPGRADE_VERSION_ONE, UpgradeFuncOneToTwo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "register HKS_UPGRADE_VERSION_ONE failed!")

    // change key version in the end
    RegisterUpgradeFuncAbility(HKS_UPGRADE_VERSION_MAX, UpgradeKeyToNewestVersion);
    return ret;
}
