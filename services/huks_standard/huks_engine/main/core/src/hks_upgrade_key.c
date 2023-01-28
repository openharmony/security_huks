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
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"

typedef int32_t (*HksUpgradeKeyAbility)(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet);

struct HksAbility {
    bool isValid;
    uint32_t id;
    HksUpgradeKeyAbility func;
};

static struct HksAbility g_upgradeAbilityList[HKS_UPGRADE_CODE_MAX] = { { 0 } };

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

static int32_t HksChangeOldKeyParams(const struct HksParamSet *paramSet,
    const struct HksParam *newProcessInfo, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed")
        uint32_t i = 0;
        for (; i < paramSet->paramsCnt; ++i) {
            if (paramSet->params[i].tag == HKS_TAG_PROCESS_NAME) {
                ret = HksAddParams(newParamSet, newProcessInfo, 1);
                
                if (ret != HKS_SUCCESS) {
                    HKS_LOG_E("append key version failed");
                    break;
                }
            } else {
                ret = HksAddParams(newParamSet, &(paramSet->params[i]), 1);
                if (ret != HKS_SUCCESS) {
                    HKS_LOG_E("append param %" LOG_PUBLIC "u failed", paramSet->params[i].tag);
                    break;
                }
            }
        }
        if (ret != HKS_SUCCESS) {
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

static int32_t HksUpgradeKeyOwner(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet)
{
    struct HksParam *isNeedUpgradeKeyOwner = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_NEED_CHANGE_KEY_OWNER, &isNeedUpgradeKeyOwner);
    if (ret != HKS_SUCCESS || !isNeedUpgradeKeyOwner->boolParam) {
        HKS_LOG_I("no need to upgrade key owner");
        return HksGetParamSet(oldKeyParamSet, oldKeyParamSet->paramSetSize, newKeyParamSet);
    }

    struct HksParam *newProcessInfo = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_PROCESS_NAME, &newProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "no new process info in param set!")

    ret = HksAuthWhiteList(newProcessInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "not in white list!")

    return HksChangeOldKeyParams(oldKeyParamSet, newProcessInfo, newKeyParamSet);
}
#endif

static int32_t HksUpgradeKeyVersion(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    struct HksParamSet **newKeyParamSet)
{
    (void)paramSet;
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    do {
        ret = HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed")
        for (uint32_t i = 0; i < oldKeyParamSet->paramsCnt; ++i) {
            if (oldKeyParamSet->params[i].tag == HKS_TAG_KEY_VERSION) {
                struct HksParam versionParam;
                versionParam.tag = HKS_TAG_KEY_VERSION;
                versionParam.uint32Param = HKS_KEY_VERSION;
                ret = HksAddParams(newParamSet, &versionParam, 1);
                
                if (ret != HKS_SUCCESS) {
                    HKS_LOG_E("append key version failed");
                    break;
                }
            } else {
                ret = HksAddParams(newParamSet, &(oldKeyParamSet->params[i]), 1);
                if (ret != HKS_SUCCESS) {
                    HKS_LOG_E("append param %" LOG_PUBLIC "u failed", oldKeyParamSet->params[i].tag);
                    break;
                }
            }
        }
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed")

        *newKeyParamSet = newParamSet;
        return ret;
    } while (0);

    HksFreeParamSet(&newParamSet);
    return ret;
}

static int32_t RegisterUpgradeKeyAbility(uint32_t id, HksUpgradeKeyAbility func)
{
    g_upgradeAbilityList[id].func = func;
    g_upgradeAbilityList[id].id = id;
    g_upgradeAbilityList[id].isValid = true;
    return HKS_SUCCESS;
}

int32_t HksDoUpgradeKey(const struct HksParamSet *oldKeyParamSet, const struct HksParamSet *paramSet,
    uint32_t upgradeTag, struct HksParamSet **newKeyParamSet)
{
    if (upgradeTag <= HKS_UPGRADE_CODE_BASE || upgradeTag >= HKS_UPGRADE_CODE_MAX ||
        !g_upgradeAbilityList[upgradeTag].isValid) {
        return HKS_ERROR_BAD_STATE;
    }
    int32_t ret = g_upgradeAbilityList[upgradeTag].func(oldKeyParamSet, paramSet, newKeyParamSet);
    return ret;
}

int32_t HksInitUpgradeKeyAbility(void)
{
    HKS_LOG_I("HksInitUpgradeKeyAbility");
    int32_t ret = HKS_SUCCESS;

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    ret = RegisterUpgradeKeyAbility(HKS_UPGRADE_UPGRADE_KEY_OWNER, HksUpgradeKeyOwner);
#endif
    ret = RegisterUpgradeKeyAbility(HKS_UPGRADE_UPGRADE_KEY_VERSION, HksUpgradeKeyVersion);

    return ret;
}
