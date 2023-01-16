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

#include "hks_upgrade_operation.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_check_white_list.h"
#include "hks_client_service_util.h"
#include "hks_get_process_info.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_storage.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_upgrade_key_manager.h"

#include "securec.h"

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
static int32_t HksIsProcessInfoInWhiteList(const struct HksProcessInfo *processInfo)
{
    uint32_t uid = 0;
    if (processInfo->processName.size == sizeof("0") && HksMemCmp(processInfo->processName.data, "0",
        processInfo->processName.size) == EOK) { // for uid == 0
        uid = 0;
    } else if (processInfo->processName.size == sizeof(uid)) {
        (void)memcpy_s(&uid, sizeof(uid), processInfo->processName.data, processInfo->processName.size);
    } else {
        return HKS_ERROR_NO_PERMISSION;;
    }

    return HksCheckIsInWhiteList(uid);
}

static volatile bool isOldKeyCleared = false;

static void HksMarkOldKeyClearedIfEmpty(void)
{
    uint32_t keyCount = 0;
    int32_t ret = HksIsOldKeyPathCleared(&keyCount);
    if (ret == HKS_SUCCESS && keyCount == 0) {
        // record mark
        isOldKeyCleared = true;
    }
}

static int32_t HksIsKeyExpectedVersion(const struct HksBlob *key, uint32_t oldVersion)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret;
    do {
        ret = HksGetParamSet((const struct HksParamSet *)key->data, key->size, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get paramSet from file failed!")
        struct HksParam *keyVersion = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_KEY_VERSION, &keyVersion);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get param key version failed!")
        ret = (keyVersion->uint32Param == oldVersion) ? HKS_SUCCESS : HKS_FAILURE;
    } while (0);
    HksFreeParamSet(&paramSet);
    return ret;
}

#ifdef _HKS_ENABLE_CHECK_OLD_PATH_
static int32_t HksIsOldKeyCleared(void) {
    // it is ok for without mutex, because the hugest problem is check key directory for nothing
    return isOldKeyCleared ? HKS_SUCCESS : HKS_FAILURE;
}
#endif

int32_t HksIsNeedUpgradeForSmallToService(const struct HksProcessInfo *processInfo)
{
#ifdef _HKS_ENABLE_CHECK_OLD_PATH_
    if (HksIsOldKeyCleared()) {
        return HKS_FAILURE;
    }
#endif
    return HksIsProcessInfoInWhiteList(processInfo);
}

static int32_t HksConstructRootProcessInfo(struct HksProcessInfo *processInfo)
{
    char *processName = NULL;
    char *userId = NULL;
    int32_t ret = HksGetProcessName(&processName);
    HKS_IF_NULL_LOGE_RETURN(processName, HKS_ERROR_BAD_STATE, "get old process name failed");
    ret = HksGetUserId(&userId);
    HKS_IF_NULL_LOGE_RETURN(userId, HKS_ERROR_BAD_STATE, "get old user if failed");

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
    ret = HksStoreGetKeyBlobSize(&rootProcessInfo, keyAlias, HKS_STORAGE_TYPE_KEY, &keySize);
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
        ret = HksStoreGetKeyBlob(&rootProcessInfo, keyAlias, HKS_STORAGE_TYPE_KEY, &oldKey);
        HKS_IF_NOT_SUCC_BREAK(ret)
        const uint32_t oldKeyVersion = 1;
        ret = HksIsKeyExpectedVersion(&oldKey, oldKeyVersion);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksStoreDeleteKeyBlob(&rootProcessInfo, keyAlias, HKS_STORAGE_TYPE_KEY);
        if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
            HKS_LOG_E("service delete main key failed, ret = %" LOG_PUBLIC "d", ret);
        }

        HksMarkOldKeyClearedIfEmpty();
    } while (0);
    HKS_FREE_BLOB(oldKey);

    return ret;
}

static int32_t ConstructChangeOwnerParamSet(const struct HksProcessInfo *rootProcessInfo,
    const struct HksProcessInfo *processInfo, struct HksParamSet **outParamSet)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed!")

        struct HksParam newProcessParam;
        newProcessParam.tag = HKS_TAG_PROCESS_NAME;
        newProcessParam.blob = processInfo->processName;

        ret = HksAddParams(paramSet, &newProcessParam, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param newProcessParam failed!")

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build param set failed!")

        *outParamSet = paramSet;
        return HKS_SUCCESS;
    } while (0);
    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t HksChangeKeyOwner(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    int32_t mode)
{
    HKS_LOG_I("enter HksChangeKeyOwner");
    struct HksProcessInfo rootProcessInfo;
    int32_t ret = HksConstructRootProcessInfo(&rootProcessInfo);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    struct HksBlob oldKey = { .size = 0, .data = NULL };
    struct HksBlob newKey = { .size = 0, .data = NULL };

    struct HksParamSet *paramSet = NULL;

    do {
        // get old key
        ret = GetKeyFileData(&rootProcessInfo, keyAlias, &oldKey, mode);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "not have old key")

        ret = ConstructChangeOwnerParamSet(&rootProcessInfo, processInfo, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "construct param set failed!")

        ret = HksUpgradeKey(&oldKey, paramSet, 1, &newKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "access change key owner failed!")

        ret = HksStoreKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY, &newKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "store new key failed!")

        // delete old key only after new key stored successfully
        HksMarkOldKeyClearedIfEmpty();
        (void)HksDeleteOldKeyForSmallToService(keyAlias);
    } while (0);
    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(oldKey);
    HKS_FREE_BLOB(newKey);

    return ret;
}

int32_t HksChangeKeyOwnerForSmallToService(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    int32_t mode)
{
    HKS_LOG_I("enter get new key");
    return HksChangeKeyOwner(processInfo, keyAlias, mode);
}

static int32_t HksGetkeyInfoListByProcessName(const struct HksProcessInfo *processInfo,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    int32_t ret;
    uint32_t realCnt = 0;
    do {
        ret = HksGetKeyAliasByProcessName(processInfo, keyInfoList, listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get old key alias list from storage failed, ret = %" LOG_PUBLIC "d", ret)
        for (uint32_t i = 0; i < *listCount; ++i) {
            struct HksBlob keyFromFile = { 0, NULL };
            ret = GetKeyFileData(processInfo, &(keyInfoList[i].alias), &keyFromFile, HKS_STORAGE_TYPE_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get old key data failed, ret = %" LOG_PUBLIC "d", ret)
            const uint32_t oldKeyVersion = 1;
            if (HksIsKeyExpectedVersion(&keyFromFile, oldKeyVersion) != HKS_SUCCESS) {
                break;
            }
            ret = GetKeyParamSet(&keyFromFile, keyInfoList[i].paramSet);
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
    uint32_t listCountOld = listMaxCnt - *listCount;
    do {
        struct HksProcessInfo rootProcessInfo;
        ret = HksConstructRootProcessInfo(&rootProcessInfo);
        HKS_IF_NOT_SUCC_BREAK(ret, "construct root process info failed!")
        ret = HksGetkeyInfoListByProcessName(&rootProcessInfo, keyInfoList + *listCount, &listCountOld);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key info list in old path failed!")

        *listCount = *listCount + listCountOld;
    } while (0);
    return ret;
}
#endif
