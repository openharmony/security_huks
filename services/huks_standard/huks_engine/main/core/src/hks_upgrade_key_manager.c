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

#include "hks_check_white_list.h"
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

static struct HksUpgradeFuncAbility g_upgradeFuncList[HKS_KEY_VERSION + 1] = { { 0 } };

static int32_t RegisterUpgradeFuncAbility(enum HksUpgradeVersionId versionId, UpgradeFuncPtr func)
{
    if (versionId <= HKS_UPGRADE_VERSION_BASE || versionId >= HKS_UPGRADE_VERSION_MAX) {
        return HKS_ERROR_BAD_STATE;
    }
    g_upgradeFuncList[versionId].isValid = true;
    g_upgradeFuncList[versionId].upgradeVersion = versionId;
    g_upgradeFuncList[versionId].func = func;

    return HKS_SUCCESS;
}

#ifdef HKS_ENABLE_SMALL_TO_SERVICE

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
#endif

static int32_t UpgradeFuncOneToTwo(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet)
{
    int32_t ret = HKS_SUCCESS;
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    // to do : 增加判断是否需要changeKeyOwner
    struct HksParam *newProcessInfo = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_PROCESS_NAME, &newProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "no new process info in param set!")

    ret = HksAuthWhiteList(newProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "not in white list")

    ret = HksDoUpgradeKey(oldKeyParamSet, paramSet, HKS_UPGRADE_UPGRADE_KEY_OWNER, newKeyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "access change key owner failed!")
#endif
    return HKS_SUCCESS;
}

static int32_t UpgradeKeyToNewestVersion(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet)
{
    int32_t ret;
    ret = HksDoUpgradeKey(oldKeyParamSet, paramSet, HKS_UPGRADE_CHANGE_KEH_VERSION, newKeyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "access change key owner failed!")
    return ret;
}

static int32_t CopyHksParamSet(const struct HksParamSet *oldParamSet, struct HksParamSet **newParamSet)
{
    *newParamSet = (struct HksParamSet *)HksMalloc(oldParamSet->paramSetSize);
    HKS_IF_NULL_LOGE_RETURN(*newParamSet, HKS_ERROR_MALLOC_FAIL, "malloc newParamSet failed!")

    (void)memcpy_s(*newParamSet, oldParamSet->paramSetSize, oldParamSet, oldParamSet->paramSetSize);
    return HksFreshParamSet(*newParamSet, false);
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

        ret = CopyHksParamSet(keyNode->paramSet, &newParamSet);
        if (ret != HKS_SUCCESS) {
            break;
        }
        bool isError = false;
        for (uint32_t i = keyVersion->uint32Param; i <= HKS_UPGRADE_VERSION_MAX; ++i) {
            HKS_LOG_I("upgrade key from %" LOG_PUBLIC "u", i);
            if (g_upgradeFuncList[i].isValid) {
                HksFreeParamSet(&oldParamSet);
                ret = CopyHksParamSet(newParamSet, &oldParamSet);
                if (ret != HKS_SUCCESS) {
                    isError = true;
                    break;
                }
                HksFreeParamSet(&newParamSet);
                ret = g_upgradeFuncList[i].func(oldParamSet, paramSet, &newParamSet);
                if (ret != HKS_SUCCESS) {
                    isError = true;
                    break;
                }
            }
        }
        if (isError) {
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
