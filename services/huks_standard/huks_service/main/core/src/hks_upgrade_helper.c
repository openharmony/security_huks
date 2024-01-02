/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hks_upgrade_helper.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_check_trust_list.h"
#include "hks_client_service_util.h"
#include "hks_get_process_info.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_storage.h"
#include "hks_template.h"
#include "hks_type_inner.h"

#include "hks_upgrade_key_accesser.h"

#include "securec.h"

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
#define HKS_OLD_KEY_VERSION_FOR_SDK_HUKS 1

static int32_t HksIsProcessInfoInTrustList(const struct HksProcessInfo *processInfo)
{
    uint32_t uid = 0;
    if (processInfo->processName.size == sizeof(uid)) {
        (void)memcpy_s(&uid, sizeof(uid), processInfo->processName.data, processInfo->processName.size);
    } else {
        return HKS_ERROR_NO_PERMISSION;
    }

    return HksCheckIsInTrustList(uid);
}

#ifdef HKS_ENABLE_MARK_CLEARED_FOR_SMALL_TO_SERVICE
// it is ok for no mutex lock, because the hugest problem it can lead to is checking key directory for nothing once
static volatile bool g_isOldKeyCleared = false;

void HksMarkOldKeyClearedIfEmpty(void)
{
    uint32_t keyCount = 0;
    int32_t ret = HksIsOldKeyPathCleared(&keyCount);
    if (ret == HKS_SUCCESS && keyCount == 0) {
        // record mark
        g_isOldKeyCleared = true;
    }
}

static bool HksIsOldKeyCleared(void)
{
    return g_isOldKeyCleared ? true : false;
}
#endif /** HKS_ENABLE_MARK_CLEARED_FOR_SMALL_TO_SERVICE */

static int32_t HksIsKeyExpectedVersion(const struct HksBlob *key, uint32_t expectedVersion)
{
    struct HksParam *keyVersion = NULL;
    int32_t ret = HksGetParam((const struct HksParamSet *)key->data, HKS_TAG_KEY_VERSION, &keyVersion);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get param key version failed!")
    return (keyVersion->uint32Param == expectedVersion) ? HKS_SUCCESS : HKS_FAILURE;
}

int32_t HksCheckNeedUpgradeForSmallToService(const struct HksProcessInfo *processInfo)
{
#ifdef HKS_ENABLE_MARK_CLEARED_FOR_SMALL_TO_SERVICE
    if (HksIsOldKeyCleared()) {
        return HKS_FAILURE;
    }
#endif
    return HksIsProcessInfoInTrustList(processInfo);
}

static int32_t HksConstructRootProcessInfo(struct HksProcessInfo *processInfo)
{
    char *processName = NULL;
    char *userId = NULL;
    int32_t ret = HksGetProcessName(&processName);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get old process name failed");
    ret = HksGetUserId(&userId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get old user if failed");

    processInfo->processName.data = (uint8_t *)processName;
    processInfo->processName.size = strlen(processName);
    processInfo->userId.data = (uint8_t *)userId;
    processInfo->userId.size = strlen(userId);
    processInfo->userIdInt = 0;
    processInfo->accessTokenId = 0;
    return HKS_SUCCESS;
}

int32_t HksDeleteOldKeyForSmallToService(const struct HksBlob *keyAlias)
{
    struct HksProcessInfo rootProcessInfo;
    int32_t ret = HksConstructRootProcessInfo(&rootProcessInfo);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    uint32_t keySize = 0;
    ret = HksManageStoreGetKeyBlobSize(&rootProcessInfo, NULL, keyAlias, &keySize, HKS_STORAGE_TYPE_KEY);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyblob size from storage failed, ret = %" LOG_PUBLIC "d.", ret)

    if (keySize > MAX_KEY_SIZE) {
        HKS_LOG_E("invalid storage size, size = %" LOG_PUBLIC "u", keySize);
        return HKS_ERROR_INVALID_KEY_FILE;
    }
    struct HksBlob oldKey = { .size = keySize, .data = NULL };
    do {
        oldKey.data = (uint8_t *)HksMalloc(keySize);
        if (oldKey.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        ret = HksManageStoreGetKeyBlob(&rootProcessInfo, NULL, keyAlias, &oldKey, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_BREAK(ret)
        ret = HksIsKeyExpectedVersion(&oldKey, HKS_OLD_KEY_VERSION_FOR_SDK_HUKS);
        if (ret != HKS_SUCCESS) {
            ret = HKS_ERROR_NOT_EXIST;
            break;
        }

        ret = HksManageStoreDeleteKeyBlob(&rootProcessInfo, NULL, keyAlias, HKS_STORAGE_TYPE_KEY);
        if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
            HKS_LOG_E("service delete main key failed, ret = %" LOG_PUBLIC "d", ret);
        }

#ifdef HKS_ENABLE_MARK_CLEARED_FOR_SMALL_TO_SERVICE
        HksMarkOldKeyClearedIfEmpty();
#endif
    } while (0);
    HKS_FREE_BLOB(oldKey);

    return ret;
}

static int32_t HksChangeKeyOwner(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, enum HksStorageType mode)
{
    HKS_LOG_I("enter HksChangeKeyOwner");
    struct HksProcessInfo rootProcessInfo;
    int32_t ret = HksConstructRootProcessInfo(&rootProcessInfo);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    struct HksBlob oldKey = { .size = 0, .data = NULL };
    struct HksBlob newKey = { .size = 0, .data = NULL };

    struct HksParamSet *upgradeParamSet = NULL;

    do {
        // get old key
        ret = GetKeyFileData(&rootProcessInfo, NULL, keyAlias, &oldKey, mode);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "not have old key")

        ret = ConstructUpgradeKeyParamSet(processInfo, paramSet, &upgradeParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "construct param set failed!")
        ret = HksIsKeyExpectedVersion(&oldKey, HKS_OLD_KEY_VERSION_FOR_SDK_HUKS);
        if (ret != HKS_SUCCESS) {
            ret = HKS_ERROR_NOT_EXIST;
            break;
        }

        newKey.data = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
        if (newKey.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        newKey.size = MAX_KEY_SIZE;
        ret = HksDoUpgradeKeyAccess(&oldKey, upgradeParamSet, &newKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "access change key owner failed!")

        ret = HksManageStoreKeyBlob(processInfo, NULL, keyAlias, &newKey, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "store new key failed!")

        // delete old key only after new key stored successfully
        (void)HksDeleteOldKeyForSmallToService(keyAlias);

#ifdef HKS_ENABLE_MARK_CLEARED_FOR_SMALL_TO_SERVICE
        HksMarkOldKeyClearedIfEmpty();
#endif
    } while (0);
    HksFreeParamSet(&upgradeParamSet);
    HKS_FREE_BLOB(oldKey);
    HKS_FREE_BLOB(newKey);

    return ret;
}

int32_t HksChangeKeyOwnerForSmallToService(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, enum HksStorageType mode)
{
    HKS_LOG_I("enter get new key");
    return HksChangeKeyOwner(processInfo, paramSet, keyAlias, mode);
}

static int32_t HksGetkeyInfoListByProcessName(const struct HksProcessInfo *processInfo,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    int32_t ret;

    // the number for infos really added in keyInfoList
    uint32_t realCnt = 0;
    do {
        ret = HksManageGetKeyAliasByProcessName(processInfo, NULL, keyInfoList, listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get old key alias list from storage failed, ret = %" LOG_PUBLIC "d", ret)
        for (uint32_t i = 0; i < *listCount; ++i) {
            struct HksBlob keyFromFile = { 0, NULL };
            ret = GetKeyFileData(processInfo, NULL, &(keyInfoList[i].alias), &keyFromFile, HKS_STORAGE_TYPE_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get old key data failed, ret = %" LOG_PUBLIC "d", ret)
            if (HksIsKeyExpectedVersion(&keyFromFile, HKS_OLD_KEY_VERSION_FOR_SDK_HUKS) != HKS_SUCCESS) {
                HKS_FREE_BLOB(keyFromFile);
                continue;
            }
            ret = GetKeyParamSet(&keyFromFile, keyInfoList[realCnt].paramSet);
            HKS_FREE_BLOB(keyFromFile);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get old key paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ++realCnt;
        }
        *listCount = realCnt;
        return HKS_SUCCESS;
    } while (0);

    *listCount = realCnt;

    return ret;
}

int32_t HksGetOldKeyInfoListForSmallToService(const struct HksProcessInfo *processInfo, struct HksKeyInfo *keyInfoList,
    uint32_t listMaxCnt, uint32_t *listCount)
{
    int32_t ret;

    // remain buffer count for old key info
    uint32_t listCountOld = listMaxCnt - *listCount;
    do {
        struct HksProcessInfo rootProcessInfo;
        ret = HksConstructRootProcessInfo(&rootProcessInfo);
        HKS_IF_NOT_SUCC_BREAK(ret, "construct root process info failed!")
        ret = HksGetkeyInfoListByProcessName(&rootProcessInfo, NULL, keyInfoList + *listCount, &listCountOld);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key info list in old path failed!")

        *listCount = *listCount + listCountOld;
    } while (0);
    return ret;
}
#endif
