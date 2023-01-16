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

#include "huks_access.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_upgrade_key_code.h"

#include "securec.h"

typedef int32_t (*UpgradeFuncPtr)(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey);

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

static int32_t UpgradeFuncOneToTwo(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey)
{
    int32_t ret = HKS_SUCCESS;
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    ret = HuksAccessUpgradeKey(oldKey, paramSet, HKS_UPGRADE_UPGRADE_KEY_OWNER, newKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "access change key owner failed!")
#endif
    return HKS_SUCCESS;
}

int32_t HksIsNewestVersion(uint32_t keyVersion)
{
    if (keyVersion == HKS_KEY_VERSION) {
        return HKS_SUCCESS;
    }
    return HKS_FAILURE;
}

// to do : 即使没有升级函数，也要将密钥版本号升级
// static int32_t UpgradeKeyToNewestVersion(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
//     struct HksBlob *newKey)
// {
//     int32_t ret;
//     ret = HuksAccessUpgradeKey(oldKey, paramSet, HKS_UPGRADE_CHANGE_KEH_VERSION, newKey);
//     HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "access change key owner failed!")
//     return ret;
// }

static int32_t CopyHksBlob(const struct HksBlob *oldBlob, struct HksBlob *newBlob)
{
    if (oldBlob == NULL || oldBlob->data == NULL) {
        return HKS_FAILURE;
    }
    newBlob->data = (uint8_t *)HksMalloc(oldBlob->size);
    HKS_IF_NULL_LOGE_RETURN(newBlob->data, HKS_ERROR_MALLOC_FAIL, "malloc newBlob failed!")
    (void)memcpy_s(newBlob->data, oldBlob->size, oldBlob->data, oldBlob->size);
    newBlob->size = oldBlob->size;
    return HKS_SUCCESS;
}

// to do : 即使没有升级函数，也要将密钥版本号升级
int32_t HksUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, uint32_t keyVersion,
    struct HksBlob *newKey) {
    HKS_LOG_I("enter HksUpgradeKey");
    struct HksBlob inputKey = { 0 };
    struct HksBlob outputKey = { 0 };
    int32_t ret;
    do {
        ret = CopyHksBlob(oldKey, &inputKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy oldKey to inputKey failed!");
        bool isError = false;
        for (uint32_t i = keyVersion; i < HKS_UPGRADE_VERSION_MAX; ++i) {
            HKS_LOG_I("upgrade key from %" LOG_PUBLIC "u", i);
            if (g_upgradeFuncList[i].isValid) {
                HKS_FREE_BLOB(outputKey);
                ret = g_upgradeFuncList[i].func(&inputKey, paramSet, &outputKey);
                if (ret != HKS_SUCCESS) {
                    isError = true;
                    break;
                }
                HKS_FREE_BLOB(inputKey);
                ret = CopyHksBlob(&outputKey, &inputKey);
                if (ret != HKS_SUCCESS) {
                    isError = true;
                    break;
                }
            }
        }
        if (isError) {
            break;
        }
        ret = CopyHksBlob(&outputKey, newKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy oldKey to newKey failed!");
    } while (0);
    HKS_FREE_BLOB(inputKey);
    HKS_FREE_BLOB(outputKey);

    return ret;
}

int32_t HksUpgradeKeyFuncInit(void)
{
    HKS_LOG_I("HksUpgradeKeyFuncInit");
    int32_t ret = RegisterUpgradeFuncAbility(HKS_UPGRADE_VERSION_ONE, UpgradeFuncOneToTwo);
    return ret;
}
