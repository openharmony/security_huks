/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_client_service.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_client_check.h"
#include "hks_hitrace.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_report.h"
#include "hks_session_manager.h"
#include "hks_storage.h"
#include "huks_access.h"
#include "securec.h"

#ifdef _STORAGE_LITE_
#include "hks_storage_adapter.h"
#endif

#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
#include "hks_upgrade_storage_data.h"
#endif

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL

#include "hks_useridm_api_wrap.h"

#endif

#define USER_ID_ROOT_DEFAULT          "0"

#define MAX_KEY_COUNT 256
#define MAX_STORAGE_SIZE (2 * 1024 * 1024)

#ifndef _CUT_AUTHENTICATE_
#ifdef _STORAGE_LITE_
static int32_t GetKeyData(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    struct HksBlob *key, int32_t mode)
{
    int32_t ret = HksStoreGetKeyBlob(processInfo, keyAlias, mode, key);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get key blob from storage failed, ret = %d", ret);
    }
    return ret;
}

static int32_t CheckKeyCondition(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias)
{
    /* check is enough buffer to store */
    uint32_t size = 0;
    int32_t ret = HksStoreGetToatalSize(&size);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get total size from storage failed, ret = %d", ret);
        return ret;
    }

    if (size >= MAX_STORAGE_SIZE) {
        /* is key exist */
        ret = HksStoreIsKeyBlobExist(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("buffer exceeds limit");
            return HKS_ERROR_STORAGE_FAILURE;
        }
    }

    return HKS_SUCCESS;
}

static int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet)
{
    struct HksParamSet *tmpParamSet = NULL;
    int32_t ret = TranslateKeyInfoBlobToParamSet(NULL, key, &tmpParamSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    if (paramSet->paramSetSize < tmpParamSet->paramSetSize) {
        HksFreeParamSet(&tmpParamSet);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    if (memcpy_s(paramSet, paramSet->paramSetSize, tmpParamSet, tmpParamSet->paramSetSize) != EOK) {
        HKS_LOG_E("memcpy paramSet failed");
        ret = HKS_ERROR_BAD_STATE;
    }

    HksFreeParamSet(&tmpParamSet);
    return ret;
}

int32_t HksServiceGetKeyInfoList(const struct HksProcessInfo *processInfo, struct HksKeyInfo *keyInfoList,
    uint32_t *listCount)
{
    int32_t ret = HksCheckGetKeyInfoListParams(&(processInfo->processName), keyInfoList, listCount);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksStoreGetKeyInfoList(keyInfoList, listCount);

    HksReport(__func__, processInfo, NULL, ret);
    return ret;
}
#else

static int32_t GetKeyData(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    struct HksBlob *key, int32_t mode)
{
    uint32_t size;
    int32_t ret = HksStoreGetKeyBlobSize(processInfo, keyAlias, mode, &size);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get keyblob size from storage failed, ret = %d.", ret);
        return ret;
    }
    if (size > MAX_STORAGE_SIZE) {
        HKS_LOG_E("invalid storage size, size = %u", size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    key->data = (uint8_t *)HksMalloc(size);
    if (key->data == NULL) {
        HKS_LOG_E("get key data: malloc failed");
        return HKS_ERROR_MALLOC_FAIL;
    }

    key->size = size;
    ret = HksStoreGetKeyBlob(processInfo, keyAlias, mode, key);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get keyblob from storage failed, ret = %d", ret);
        HKS_FREE_BLOB(*key);
    }

    return ret;
}

static int32_t CheckKeyCondition(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias)
{
    /* delete old key and certchain before obtaining the number of keys */
    int32_t ret = HksStoreDeleteKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY);
    if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
        HKS_LOG_E("delete keyblob from storage failed, ret = %d", ret);
        return ret;
    }

    ret = HksStoreDeleteKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_CERTCHAIN);
    if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
        HKS_LOG_E("delete certchain from storage failed, ret = %d", ret);
        return ret;
    }

    uint32_t fileCount;
    ret = HksGetKeyCountByProcessName(processInfo, &fileCount);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    if (fileCount >= MAX_KEY_COUNT) {
        HKS_LOG_E("fileCount is no less than max count");
        ret = HKS_ERROR_STORAGE_FAILURE;
    }

    return ret;
}

static int32_t CheckBeforeDeleteParam(const struct HksParamSet *paramSet, uint32_t tag)
{
    int32_t ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check paramSet failed, ret = %d", ret);
        return ret;
    }

    if (paramSet->paramsCnt == 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (paramSet->params[i].tag == tag) {
            return HKS_SUCCESS;
        }
    }

    return HKS_ERROR_PARAM_NOT_EXIST;
}

static int32_t DeleteTagFromParamSet(uint32_t tag, const struct HksParamSet *paramSet,
    struct HksParamSet **outParamSet)
{
    int32_t ret = CheckBeforeDeleteParam(paramSet, tag);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check failed before delete param, ret = %d", ret);
        return ret;
    }

    ret = HksFreshParamSet((struct HksParamSet *)paramSet, false);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("fresh paramset failed");
        return ret;
    }

    struct HksParamSet *newParamSet = NULL;
    ret = HksInitParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init param set failed");
        return ret;
    }

    for (uint32_t i = 0; i < paramSet->paramsCnt; ++i) {
        if (paramSet->params[i].tag != tag) {
            ret = HksAddParams(newParamSet, &paramSet->params[i], 1);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("add in params failed");
                HKS_FREE_PTR(newParamSet);
                return ret;
            }
        }
    }

    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("build paramset failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }

    *outParamSet = newParamSet;
    return HKS_SUCCESS;
}

static int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet)
{
    if (key->size < sizeof(struct HksParamSet)) {
        HKS_LOG_E("get key paramset: invalid key size: %u", key->size);
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    const struct HksParamSet *tmpParamSet = (const struct HksParamSet *)key->data;
    struct HksParamSet *outParamSet = NULL;
    int32_t ret = DeleteTagFromParamSet(HKS_TAG_KEY, tmpParamSet, &outParamSet);
    if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        if (paramSet->paramSetSize < key->size) {
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
        if (memcpy_s(paramSet, paramSet->paramSetSize, key->data, key->size) != EOK) {
            HKS_LOG_E("memcpy key failed");
            return HKS_ERROR_BAD_STATE;
        }
        return HKS_SUCCESS;
    }

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("delete tag from paramSet failed, ret = %d.", ret);
        return ret;
    }

    if (paramSet->paramSetSize < outParamSet->paramSetSize) {
        HksFreeParamSet(&outParamSet);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    if (memcpy_s(paramSet, paramSet->paramSetSize, outParamSet, outParamSet->paramSetSize) != EOK) {
        HKS_LOG_E("memcpy outParamSet failed");
        ret = HKS_ERROR_BAD_STATE;
    }

    HksFreeParamSet(&outParamSet);
    return ret;
}

int32_t HksServiceGetKeyInfoList(const struct HksProcessInfo *processInfo, struct HksKeyInfo *keyInfoList,
    uint32_t *listCount)
{
    int32_t ret;

    do {
        ret = HksCheckGetKeyInfoListParams(&processInfo->processName, keyInfoList, listCount);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get key data failed, ret = %d", ret);
            break;
        }

        ret = HksGetKeyAliasByProcessName(processInfo, keyInfoList, listCount);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get key alias list from storage failed, ret = %d", ret);
            break;
        }

        for (uint32_t i = 0; i < *listCount; ++i) {
            struct HksBlob keyFromFile = { 0, NULL };
            ret = GetKeyData(processInfo, &(keyInfoList[i].alias), &keyFromFile, HKS_STORAGE_TYPE_KEY);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("get key data failed, ret = %d", ret);
                break;
            }

            ret = GetKeyParamSet(&keyFromFile, keyInfoList[i].paramSet);
            HKS_FREE_BLOB(keyFromFile);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("get key paramSet failed, ret = %d", ret);
                break;
            }
        }
    } while (0);

    HksReport(__func__, processInfo, NULL, ret);
    return ret;
}
#endif
#endif /* _CUT_AUTHENTICATE_ */

static int32_t AppendToNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check paramSet failed");
            break;
        }

        ret = HksFreshParamSet((struct HksParamSet *)paramSet, false);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append fresh paramset failed");
            break;
        }

        ret = HksInitParamSet(&newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append init operation param set failed");
            break;
        }

        ret = HksAddParams(newParamSet, paramSet->params, paramSet->paramsCnt);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append params failed");
            break;
        }

        *outParamSet = newParamSet;
        return ret;
    } while (0);

    HksFreeParamSet(&newParamSet);
    return ret;
}

static bool CheckProcessNameTagExist(const struct HksParamSet *paramSet)
{
    for (uint32_t i = 0; i < paramSet->paramsCnt; ++i) {
        if (paramSet->params[i].tag == HKS_TAG_PROCESS_NAME) {
            return true;
        }
    }

    return false;
}

static int32_t AppendProcessNameTag(const struct HksParamSet *paramSet, const struct HksBlob *processName,
    struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        if (paramSet != NULL) {
            ret = AppendToNewParamSet(paramSet, &newParamSet);
        } else {
            ret = HksInitParamSet(&newParamSet);
        }

        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append client service tag failed");
            break;
        }

        // process name only can be inserted by service
        if (CheckProcessNameTagExist(newParamSet)) {
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        struct HksParam tmpParam;
        tmpParam.tag = HKS_TAG_PROCESS_NAME;
        tmpParam.blob = *processName;

        ret = HksAddParams(newParamSet, &tmpParam, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add param failed");
            break;
        }

        ret = HksBuildParamSet(&newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("build paramset failed");
            break;
        }

        *outParamSet = newParamSet;
        return ret;
    } while (0);

    HksFreeParamSet(&newParamSet);
    return ret;
}

#ifndef _CUT_AUTHENTICATE_
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static int32_t AppendSecUid(struct HksParamSet *newParamSet, struct SecInfoWrap *secInfo)
{
    struct HksParam secureUid;
    secureUid.tag = HKS_TAG_USER_AUTH_SECURE_UID;
    secureUid.blob.size = sizeof(uint64_t);
    secureUid.blob.data = (uint8_t *)&secInfo->secureUid;
    return HksAddParams(newParamSet, &secureUid, 1);
}

static int32_t ConstructEnrolledInfoBlob(struct SecInfoWrap *secInfo, struct HksBlob *enrolledInfo,
    struct HksParam *outParam)
{
    (void)memset_s(enrolledInfo->data, enrolledInfo->size, 0, enrolledInfo->size);

    uint32_t index = 0;
    if (memcpy_s(enrolledInfo->data, enrolledInfo->size, &secInfo->enrolledInfoLen,
        sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("copy enrolledInfoLen failed!");
        return HKS_ERROR_BAD_STATE;
    }
    index += sizeof(secInfo->enrolledInfoLen);
    for (uint32_t i = 0; i < secInfo->enrolledInfoLen; ++i) {
        uint32_t authTypeInt = (uint32_t)secInfo->enrolledInfo[i].authType;
        if (memcpy_s(enrolledInfo->data + index, enrolledInfo->size - index, &authTypeInt,
            sizeof(uint32_t)) != EOK) {
            HKS_LOG_E("copy authType failed!");
            return HKS_ERROR_BAD_STATE;
        }
        index += sizeof(authTypeInt);
        if (memcpy_s(enrolledInfo->data + index, enrolledInfo->size - index,
            &((secInfo->enrolledInfo[i]).enrolledId), sizeof(uint64_t)) != EOK) {
            HKS_LOG_E("copy enrolledId failed!");
            return HKS_ERROR_BAD_STATE;
        }
        index += sizeof(secInfo->enrolledInfo[i].enrolledId);
    }

    outParam->tag = HKS_TAG_USER_AUTH_ENROLL_ID_INFO;
    outParam->blob = *enrolledInfo;
    return HKS_SUCCESS;
}

static uint32_t ComputeEnrolledInfoLen(uint32_t enrolledInfoLen)
{
    return sizeof(uint32_t) + (sizeof(uint32_t) + sizeof(uint64_t)) * enrolledInfoLen;
}

static int32_t AddEnrolledInfoInParamSet(struct SecInfoWrap *secInfo, struct HksBlob *enrolledInfo,
    struct HksParamSet *paramSet)
{
    int32_t ret;
    do {
        struct HksParam tmpParam;
        enrolledInfo->size = ComputeEnrolledInfoLen(secInfo->enrolledInfoLen);
        enrolledInfo->data = (uint8_t *)HksMalloc(enrolledInfo->size);
        if (enrolledInfo->data == NULL) {
            HKS_LOG_E("malloc enrolledInfo blob failed");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = ConstructEnrolledInfoBlob(secInfo, enrolledInfo, &tmpParam);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("ConstructEnrolledInfoBlob failed!");
            break;
        }
        ret = HksAddParams(paramSet, &tmpParam, 1);
        return ret;
    } while (0);
    HKS_FREE_PTR(enrolledInfo->data);
    return ret;
}

static int32_t AppendUserAuthInfo(const struct HksParamSet *paramSet, int32_t userId, uint32_t authAccessType,
    struct HksParamSet **outParamSet)
{
    struct SecInfoWrap *secInfo = NULL;
    struct HksParamSet *newParamSet = NULL;
    int32_t ret;

    struct HksBlob enrolledInfo = { 0, NULL };
    do {
        ret = HksUserIdmGetSecInfo(userId, &secInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get useriam sec info failed ret=%d", ret);
            ret = HKS_ERROR_GET_USERIAM_SECINFO_FAILED;
            break;
        }
        
        if (paramSet != NULL) {
            ret = AppendToNewParamSet(paramSet, &newParamSet);
        } else {
            ret = HksInitParamSet(&newParamSet);
        }
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("init param set failed");
            break;
        }

        ret = AppendSecUid(newParamSet, secInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append sec uid failed");
            break;
        }

        ret = AddEnrolledInfoInParamSet(secInfo, &enrolledInfo, newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("AddEnrolledInfoInParamSet failed!");
            break;
        }

        ret = HksBuildParamSet(&newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("build append info failed");
            break;
        }

        *outParamSet = newParamSet;
    } while (0);
    HKS_FREE_PTR(enrolledInfo.data);
    HKS_FREE_PTR(secInfo);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        *outParamSet = NULL;
    }
    return ret;
}

static int32_t CheckIfEnrollAuthInfo(int32_t userId, enum HksUserAuthType authType)
{
    uint32_t numOfAuthInfo = 0;
    if (HksUserIdmGetAuthInfoNum(userId, authType, &numOfAuthInfo) != HKS_SUCCESS) {
        HKS_LOG_E("HksUserIdmGetAuthInfoNum failed.");
        return HKS_FAILURE;
    }
    if (numOfAuthInfo == 0) {
        HKS_LOG_E("have not enroll the auth info.");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static int32_t CheckIfUserIamSupportCurType(int32_t userId, uint32_t userAuthType)
{
    const enum HksUserAuthType userAuthTypes[] = {
        HKS_USER_AUTH_TYPE_FINGERPRINT,
        HKS_USER_AUTH_TYPE_FACE,
        HKS_USER_AUTH_TYPE_PIN
    };
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(userAuthTypes); ++i) {
        if ((userAuthType & userAuthTypes[i]) == 0) {
            continue;
        }

        if (CheckIfEnrollAuthInfo(userId, userAuthTypes[i]) != HKS_SUCCESS) {
            HKS_LOG_E("no enrolled info of the user auth type: %d.", userAuthTypes[i]);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    return HKS_SUCCESS;
}

static int32_t AppendNewInfoForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    uint32_t userAuthType = 0;
    uint32_t authAccessType = 0;
    int32_t ret = HksCheckAndGetUserAuthInfo(paramSet, &userAuthType, &authAccessType);
    if (ret == HKS_ERROR_NOT_SUPPORTED) {
        struct HksParamSet *newParamSet = NULL;
        ret = AppendProcessNameTag(paramSet, &processInfo->processName, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append tag processName failed, ret = %d", ret);
            return ret;
        }
        *outParamSet = newParamSet;
        return HKS_SUCCESS;
    }

    if (ret == HKS_SUCCESS) {
        HKS_LOG_I("support secure access");
        if (CheckIfUserIamSupportCurType(processInfo->userIdInt, userAuthType) != HKS_SUCCESS) {
            HKS_LOG_E("UserIAM do not support current user auth or not enrolled cur auth info");
            return HKS_ERROR_NOT_SUPPORTED;
        }

        struct HksParamSet *userAuthParamSet = NULL;
        ret = AppendUserAuthInfo(paramSet, processInfo->userIdInt, authAccessType, &userAuthParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append secure access info failed!");
            return ret;
        }

        struct HksParamSet *newInfoParamSet = NULL;
        ret = AppendProcessNameTag(userAuthParamSet, &processInfo->processName, &newInfoParamSet);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(&userAuthParamSet);
            HKS_LOG_E("append tag processName failed, ret = %d", ret);
            return ret;
        }
        HksFreeParamSet(&userAuthParamSet);
        *outParamSet = newInfoParamSet;
        return HKS_SUCCESS;
    }
    return ret;
}
#else
static int32_t AppendNewInfoForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    return AppendProcessNameTag(paramSet, &processInfo->processName, outParamSet);
}
#endif

static int32_t GetKeyAndNewParamSet(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key, struct HksParamSet **outParamSet)
{
    int32_t ret = AppendProcessNameTag(paramSet, &processInfo->processName, outParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append tag processName failed, ret = %d", ret);
        return ret;
    }

    ret = GetKeyData(processInfo, keyAlias, key, HKS_STORAGE_TYPE_KEY);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get key data failed, ret = %d.", ret);
        HksFreeParamSet(outParamSet);
    }

    return ret;
}

#ifdef HKS_SUPPORT_ED25519_TO_X25519
static int32_t GetAgreeStoreKey(uint32_t keyAliasTag, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    struct HksParam *keyAliasParam = NULL;
    int32_t ret = HksGetParam(paramSet, keyAliasTag, &keyAliasParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get agree key alias tag failed");
        return ret;
    }

    if (keyAliasParam->blob.size > HKS_MAX_KEY_ALIAS_LEN) {
        HKS_LOG_E("invalid main key size: %u", keyAliasParam->blob.size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return GetKeyData(processInfo, &(keyAliasParam->blob), key, HKS_STORAGE_TYPE_KEY);
}

static int32_t TranslateToInnerCurve25519Format(const uint32_t alg, const struct HksBlob *key,
    struct HksBlob *publicKey)
{
    if (key->size != HKS_KEY_BYTES(HKS_CURVE25519_KEY_SIZE_256)) {
        HKS_LOG_E("Invalid curve25519 public key size! key size = 0x%X", key->size);
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    uint32_t totalSize = sizeof(struct HksPubKeyInfo) + key->size;
    uint8_t *buffer = (uint8_t *)HksMalloc(totalSize);
    if (buffer == NULL) {
        HKS_LOG_E("malloc failed! %u", totalSize);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(buffer, totalSize, 0, totalSize);

    struct HksPubKeyInfo *curve25519Key = (struct HksPubKeyInfo *)buffer;
    curve25519Key->keyAlg = (enum HksKeyAlg)alg;
    curve25519Key->keySize = HKS_CURVE25519_KEY_SIZE_256;
    curve25519Key->nOrXSize = key->size; /* curve25519 public key */

    uint32_t offset = sizeof(struct HksPubKeyInfo);
    if (memcpy_s(buffer + offset, totalSize - offset, key->data, key->size) != EOK) {
        HKS_LOG_E("copy pub key failed!");
        HKS_FREE_PTR(buffer);
        return HKS_ERROR_BAD_STATE;
    }
    publicKey->data = buffer;
    publicKey->size = totalSize;
    return HKS_SUCCESS;
}

static int32_t GetAgreePublicKey(const uint32_t alg, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    struct HksParam *isKeyAliasParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS, &isKeyAliasParam);
    if ((ret == HKS_SUCCESS) && (!(isKeyAliasParam->boolParam))) {
        struct HksParam *keyParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_AGREE_PUBLIC_KEY, &keyParam);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get agree public key tag fail");
            return ret;
        }
        return TranslateToInnerCurve25519Format(alg, &(keyParam->blob), key);
    }

    return GetAgreeStoreKey(HKS_TAG_AGREE_PUBLIC_KEY, processInfo, paramSet, key);
}

static int32_t GetAgreePrivateKey(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    return GetAgreeStoreKey(HKS_TAG_AGREE_PRIVATE_KEY_ALIAS, processInfo, paramSet, key);
}

static int32_t ConbineIntoKeyPair(const struct HksBlob *privateKey,
    const struct HksBlob *publicKey, struct HksBlob *keyPair)
{
    uint32_t size = sizeof(struct Hks25519KeyPair) + privateKey->size + publicKey->size; /* size has been checked */
    uint8_t *buffer = (uint8_t *)HksMalloc(size);
    if (buffer == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(buffer, size, 0, size);

    struct Hks25519KeyPair keyPairStruct = { publicKey->size, privateKey->size };
    uint32_t offset = 0;
    int32_t ret = HKS_ERROR_BAD_STATE;
    do {
        if (memcpy_s(buffer + offset, size, &keyPairStruct, sizeof(keyPairStruct)) != EOK) {
            break;
        }
        offset += sizeof(keyPairStruct);

        if (memcpy_s(buffer  + offset, size - offset, publicKey->data, publicKey->size) != EOK) {
            break;
        }
        offset += publicKey->size;

        if (memcpy_s(buffer  + offset, size - offset, privateKey->data, privateKey->size) != EOK) {
            break;
        }

        keyPair->data = buffer;
        keyPair->size = size;
        return HKS_SUCCESS;
    } while (0);

    HKS_FREE_PTR(buffer);
    return ret;
}

static int32_t GetAgreeKeyPair(const uint32_t alg, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    int32_t ret;
    struct HksBlob privateKey = { 0, NULL };
    struct HksBlob publicKey = { 0, NULL };
    do {
        ret = GetAgreePublicKey(alg, processInfo, paramSet, &publicKey);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = GetAgreePrivateKey(processInfo, paramSet, &privateKey);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = ConbineIntoKeyPair(&privateKey, &publicKey, key);
    } while (0);

    HKS_FREE_BLOB(privateKey);
    HKS_FREE_BLOB(publicKey);
    return ret;
}
#endif

static int32_t GetAgreeBaseKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksBlob *key)
{
    (void)key;
    struct HksParam *keyAlgParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &keyAlgParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get alg tag fail");
        return HKS_ERROR_CHECK_GET_ALG_FAIL;
    }

    if (keyAlgParam->uint32Param != HKS_ALG_AES) {
        HKS_LOG_I("not an aes key, no need check main key and derive factor");
        return HKS_SUCCESS;
    }

#ifdef HKS_SUPPORT_ED25519_TO_X25519
    struct HksParam *agreeAlgParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_AGREE_ALG, &agreeAlgParam);
    if (ret != HKS_SUCCESS) {
        return HKS_ERROR_CHECK_GET_ALG_FAIL;
    }

    if ((agreeAlgParam->uint32Param != HKS_ALG_X25519) && (agreeAlgParam->uint32Param != HKS_ALG_ED25519)) {
        return HKS_ERROR_INVALID_ALGORITHM;
    }

    return GetAgreeKeyPair(agreeAlgParam->uint32Param, processInfo, paramSet, key);
#else
    (void)processInfo;
    return HKS_ERROR_INVALID_ARGUMENT; /* if aes generated by agree but x25519/ed25519 is ot support, return error */
#endif
}

static int32_t GetDeriveMainKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksBlob *key)
{
    struct HksParam *keyGenTypeParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_GENERATE_TYPE, &keyGenTypeParam);
    if (ret != HKS_SUCCESS) {
        return HKS_SUCCESS; /* not set tag KEY_GENERATE_TYPE, gen key by default type */
    }

    if (keyGenTypeParam->uint32Param == HKS_KEY_GENERATE_TYPE_AGREE) {
        return GetAgreeBaseKey(processInfo, paramSet, key);
    } else if (keyGenTypeParam->uint32Param == HKS_KEY_GENERATE_TYPE_DEFAULT) {
        return HKS_SUCCESS;
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

static int32_t GetKeyIn(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksBlob *key)
{
    int32_t ret = GetDeriveMainKey(processInfo, paramSet, key);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* if not generate by derive, init keyIn by default value(ca to ta not accept null pointer) */
    if (key->data == NULL) {
        key->size = 1; /* malloc least buffer as keyIn buffer */
        key->data = (uint8_t *)HksMalloc(key->size);
        if (key->data == NULL) {
            HKS_LOG_E("malloc failed");
            return HKS_ERROR_MALLOC_FAIL;
        }
        key->data[0] = 0;
    }
    return HKS_SUCCESS;
}

static int32_t StoreOrCopyKeyBlob(const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo,
    struct HksBlob *output, struct HksBlob *outData, bool isStorage)
{
    if (!isStorage) {
        if ((outData->size != 0) && (memcpy_s(outData->data, outData->size, output->data, output->size) != EOK)) {
            HKS_LOG_E("copy keyblob data fail");
            return HKS_ERROR_BAD_STATE;
        }
        outData->size = output->size;
        return HKS_SUCCESS;
    }

    struct HksParam *keyAliasParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_ALIAS, &keyAliasParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get key alias fail, ret = %d", ret);
        return ret;
    }

    if (keyAliasParam->blob.size > HKS_MAX_KEY_ALIAS_LEN) {
        HKS_LOG_E("key alias size is too long, size is %u", keyAliasParam->blob.size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    ret = CheckKeyCondition(processInfo, &keyAliasParam->blob);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("CheckKeyCondition fail, ret = %d", ret);
        return ret;
    }

    ret = HksStoreKeyBlob(processInfo, &keyAliasParam->blob, HKS_STORAGE_TYPE_KEY, output);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksStoreKeyBlob fail, ret = %d", ret);
    }

    return ret;
}

int32_t HksServiceGenerateKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksBlob *keyOut)
{
    struct HksParamSet *newParamSet = NULL;
    uint8_t *keyOutBuffer = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
    if (keyOutBuffer == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    struct HksBlob output = { MAX_KEY_SIZE, keyOutBuffer };
    struct HksBlob keyIn = { 0, NULL };
    int32_t ret;
    do {
        /* if user don't pass the key out buffer, we will use a tmp key out buffer */
        if ((keyOut != NULL) && (keyOut->data != NULL) && (keyOut->size != 0)) {
            output = *keyOut;
        }

        ret = HksCheckGenAndImportKeyParams(&processInfo->processName, keyAlias, paramSetIn, &output);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check generate key params failed, ret = %d", ret);
            break;
        }

        ret = CheckKeyCondition(processInfo, keyAlias);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check key condition failed, ret = %d", ret);
            break;
        }

        ret = AppendNewInfoForGenKeyInService(processInfo, paramSetIn, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append processName tag failed, ret = %d", ret);
            break;
        }

        ret = GetKeyIn(processInfo, newParamSet, &keyIn);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get keyIn failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessGenerateKey(keyAlias, newParamSet, &keyIn, &output);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("access level generate key failed, ret = %d", ret);
            break;
        }

        ret = HksStoreKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY, &output);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("store keyblob to storage failed, ret = %d", ret);
        }
    } while (0);

    HKS_FREE_PTR(keyOutBuffer);
    HKS_FREE_PTR(keyIn.data);
    HksFreeParamSet(&newParamSet);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSetIn, ret);

    return ret;
}

int32_t HksServiceSign(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *srcData, struct HksBlob *signature)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };

    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, srcData, signature);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check sign params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("sign: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessSign(&keyFromFile, newParamSet, srcData, signature);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);

    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceVerify(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *srcData, const struct HksBlob *signature)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, srcData, signature);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check verify params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("verify: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessVerify(&keyFromFile, newParamSet, srcData, signature);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);

    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceEncrypt(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, plainText, cipherText);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check encrypt failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("encrypt: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessEncrypt(&keyFromFile, newParamSet, plainText, cipherText);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceDecrypt(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, cipherText, plainText);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check decrypt failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("decrypt: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessDecrypt(&keyFromFile, newParamSet, cipherText, plainText);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceDeleteKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias)
{
    int32_t ret = HksCheckProcessNameAndKeyAlias(&processInfo->processName, keyAlias);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /*
     * Detele key first, record log if failed; then delete cert chain, return error if failed;
     * Return error code of deleteKey in the end.
     */
    ret = HksStoreDeleteKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY);
    if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
        HKS_LOG_E("service delete main key failed, ret = %d", ret);
    }

    int32_t deleteCertRet = HksStoreDeleteKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_CERTCHAIN);
    if ((deleteCertRet != HKS_SUCCESS) && (deleteCertRet != HKS_ERROR_NOT_EXIST)) {
        HKS_LOG_E("service delete cert chain failed, ret = %d", ret);
        ret = deleteCertRet;
    }

    HksReport(__func__, processInfo, NULL, ret);

    return ret;
}

int32_t HksServiceKeyExist(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias)
{
    int32_t ret = HksCheckProcessNameAndKeyAlias(&processInfo->processName, keyAlias);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksStoreIsKeyBlobExist(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY);

    HksReport(__func__, processInfo, NULL, ret);
    return ret;
}

int32_t HksServiceGetKeyParamSet(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    struct HksParamSet *paramSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };

    do {
        ret = HksCheckGetKeyParamSetParams(&processInfo->processName, keyAlias, paramSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check get key paramSet params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, NULL, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get key paramSet: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessGetKeyProperties(newParamSet, &keyFromFile);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("access level check key validity failed, ret = %d", ret);
            break;
        }

        ret = GetKeyParamSet(&keyFromFile, paramSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get Key paramSet failed, ret = %d", ret);
        }
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceImportKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksCheckGenAndImportKeyParams(&processInfo->processName, keyAlias, paramSet, key);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check import key params failed, ret = %d", ret);
            break;
        }

        ret = CheckKeyCondition(processInfo, keyAlias);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("import: check key condition failed, ret = %d", ret);
            break;
        }

        ret = AppendNewInfoForGenKeyInService(processInfo, paramSet, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append processName tag failed, ret = %d", ret);
            break;
        }

        uint8_t *keyOutBuffer = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
        if (keyOutBuffer == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        struct HksBlob keyOut = { MAX_KEY_SIZE, keyOutBuffer };
        ret = HuksAccessImportKey(keyAlias, key, newParamSet, &keyOut);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("access level import public key failed, ret = %d", ret);
            HKS_FREE_PTR(keyOutBuffer);
            break;
        }

        ret = HksStoreKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY, &keyOut);
        HKS_FREE_PTR(keyOutBuffer);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HksReport(__func__, processInfo, paramSet, ret);
    return ret;
}

static int32_t GetKeyAndNewParamSetInForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *key,
    struct HksParamSet **outParamSet)
{
    int32_t ret = AppendNewInfoForGenKeyInService(processInfo, paramSet, outParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append new info failed, ret = %d", ret);
        return ret;
    }

    ret = GetKeyData(processInfo, keyAlias, key, HKS_STORAGE_TYPE_KEY);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get key data failed, ret = %d.", ret);
        HksFreeParamSet(outParamSet);
    }

    return ret;
}

int32_t HksServiceImportWrappedKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob wrappingKeyFromFile = { 0, NULL };
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckImportWrappedKeyParams(&processInfo->processName, keyAlias,
            wrappingKeyAlias, paramSet, wrappedKeyData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check import params failed, ret = %d", ret);
            break;
        }

        ret = HksServiceKeyExist(processInfo, wrappingKeyAlias);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("wrapping key is not exist, ret = %d", ret);
            break;
        }

        ret = CheckKeyCondition(processInfo, keyAlias);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check condition failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSetInForGenKeyInService(processInfo, wrappingKeyAlias, paramSet, &wrappingKeyFromFile,
            &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get wrapping key and new paramSet failed, ret = %d", ret);
            break;
        }

        uint8_t *keyOutBuffer = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
        if (keyOutBuffer == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        struct HksBlob keyOut = { MAX_KEY_SIZE, keyOutBuffer };
        ret = HuksAccessImportWrappedKey(wrappingKeyAlias, &wrappingKeyFromFile, wrappedKeyData, newParamSet, &keyOut);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("access level import wrapped key failed, ret = %d", ret);
            HKS_FREE_PTR(keyOutBuffer);
            break;
        }

        ret = HksStoreKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_KEY, &keyOut);
        HKS_FREE_PTR(keyOutBuffer);
    } while (0);

    HKS_FREE_BLOB(wrappingKeyFromFile);
    HksFreeParamSet(&newParamSet);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceExportPublicKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    struct HksBlob *key)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };

    do {
        ret = HksCheckExportPublicKeyParams(&processInfo->processName, keyAlias, key);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check export public key params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, NULL, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("export public: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessExportPublicKey(&keyFromFile, newParamSet, key);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);

    HksReport(__func__, processInfo, NULL, ret);
    return ret;
}

int32_t HksServiceAgreeKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *privateKey, const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckAllParams(&processInfo->processName, privateKey, paramSet, peerPublicKey, agreedKey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check agree key params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, privateKey, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("agree: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessAgreeKey(newParamSet, &keyFromFile, peerPublicKey, agreedKey);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceDeriveKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *mainKey, struct HksBlob *derivedKey)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckDeriveKeyParams(&processInfo->processName, paramSet, mainKey, derivedKey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check derive key params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, mainKey, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("derive: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessDeriveKey(newParamSet, &keyFromFile, derivedKey);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceMac(const struct HksProcessInfo *processInfo, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksBlob *srcData, struct HksBlob *mac)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckAllParams(&processInfo->processName, key, paramSet, srcData, mac);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check mac params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, key, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("mac: get key and new paramSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessMac(&keyFromFile, newParamSet, srcData, mac);
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceInitialize(void)
{
    int32_t ret;
    do {
#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
        ret = HksUpgradeStorageData();
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("hks update storage data failed, ret = %d", ret);
            break;
        }
#endif
        ret = HuksAccessModuleInit();
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("hks core service initialize failed! ret = %d", ret);
            break;
        }

#ifdef _STORAGE_LITE_
        ret = HksLoadFileToBuffer();
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("load file to buffer failed, ret = %d", ret);
            break;
        }
#endif
    } while (0);

    HksReport(__func__, NULL, NULL, ret);

    return ret;
}

int32_t HksServiceRefreshKeyInfo(const struct HksBlob *processName)
{
    int32_t ret = HksStoreDestroy(processName);
    HKS_LOG_I("destroy storage files ret = 0x%X", ret); /* only recode log */

#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
    ret = HksDestroyOldVersionFiles();
    HKS_LOG_I("destroy old version files ret = 0x%X", ret); /* only recode log */
#endif
    do {
#ifndef _HARDWARE_ROOT_KEY_
        ret = HuksAccessRefresh();
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Hks core service refresh info failed! ret = 0x%X", ret);
            break;
        }
#endif

#ifdef _STORAGE_LITE_
        ret = HksFileBufferRefresh();
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("load file to buffer failed, ret = %d", ret);
            break;
        }
#endif
    } while (0);

#ifdef L2_STANDARD
    int userId = 0;
    struct HksBlob userIdBlob = { sizeof(int), (uint8_t *)&userId };
    struct HksProcessInfo processInfo = {userIdBlob, *processName};
    HksReport(__func__, &processInfo, NULL, ret);
#endif
    
    return ret;
}

int32_t HksServiceAttestKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *certChain)
{
#ifdef HKS_SUPPORT_API_ATTEST_KEY
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksParamSet *newParamSet = NULL;
    int32_t ret;
    do {
        ret = HksCheckAttestKeyParams(&processInfo->processName, keyAlias, paramSet, certChain);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check attest key param fail");
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("GetKeyAndNewParamSet failed, ret = %d.", ret);
            break;
        }
        ret = HuksAccessAttestKey(&keyFromFile, newParamSet, certChain);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HuksAccessAttestKey fail, ret = %d.", ret);
            break;
        }

        ret = HksStoreKeyBlob(processInfo, keyAlias, HKS_STORAGE_TYPE_CERTCHAIN, certChain);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("store attest cert chain failed");
        }
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
#else
    (void)processInfo;
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return HKS_ERROR_NOT_SUPPORTED;
#endif
}

int32_t HksServiceGetCertificateChain(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *certChain)
{
#ifdef HKS_SUPPORT_API_GET_CERTIFICATE_CHAIN
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    int32_t ret = HksCheckGetCertificateChainParams(&processInfo->processName, keyAlias, paramSet, certChain);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    struct HksBlob certFromFile = { 0, NULL };
    ret = GetKeyData(processInfo, keyAlias, &certFromFile, HKS_STORAGE_TYPE_CERTCHAIN);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksGetKeyData fail, ret = %d.", ret);
        return ret;
    }
    if (memcpy_s(certChain->data, certChain->size, certFromFile.data, certFromFile.size) != EOK) {
        HKS_LOG_E("memcpy certChain fail.");
        ret = HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    certChain->size = certFromFile.size;
    HKS_FREE_BLOB(certFromFile);
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
#else
    (void)processInfo;
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return HKS_ERROR_NOT_SUPPORTED;
#endif
}

int32_t HksServiceWrapKey(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksBlob *targetKeyAlias, const struct HksParamSet *paramSet, struct HksBlob *wrappedData)
{
    (void)processName;
    (void)keyAlias;
    (void)targetKeyAlias;
    (void)paramSet;
    (void)wrappedData;
    return 0;
}

int32_t HksServiceUnwrapKey(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksBlob *targetKeyAlias, const struct HksBlob *wrappedData, const struct HksParamSet *paramSet)
{
    (void)processName;
    (void)keyAlias;
    (void)targetKeyAlias;
    (void)paramSet;
    (void)wrappedData;
    return 0;
}

int32_t HksServiceProvision(const struct HksBlob *srcData, const struct HksBlob *challengeIn)
{
    (void)srcData;
    (void)challengeIn;
    return 0;
}

int32_t HksServiceProvisionVerify(const struct HksBlob *srcData, const struct HksBlob *challengeIn)
{
    (void)srcData;
    (void)challengeIn;
    return 0;
}

int32_t HksServiceExportTrustCerts(const struct HksBlob *processName, struct HksBlob *certChain)
{
    (void)processName;
    (void)certChain;
    return 0;
}

int32_t HksServiceInit(const struct HksProcessInfo *processInfo, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *handle, struct HksBlob *token)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    do {
        ret = HksCheckServiceInitParams(&processInfo->processName, key, paramSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check ServiceInit params failed, ret = %d", ret);
            break;
        }

        ret = GetKeyAndNewParamSet(processInfo, key, paramSet, &keyFromFile, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("GetKeyAndNewParamSet failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessInit(&keyFromFile, newParamSet, handle, token);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HuksAccessInit failed, ret = %d", ret);
            break;
        }

        ret = CreateOperation(processInfo, handle, true);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("create operation failed, ret = %d", ret);
            break;
        }
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);

    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceUpdate(const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);
    int32_t ret;
    do {
        if (QueryOperation(processInfo, handle) == NULL) {
            HKS_LOG_E("operationHandle is not exist");
            ret = HKS_ERROR_NOT_EXIST;
            break;
        }

        ret = HuksAccessUpdate(handle, paramSet, inData, outData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HuksAccessUpdate fail, ret = %d", ret);
            DeleteOperation(handle);
            break;
        }
    } while (0);
    
    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

static int32_t AppendAndQueryInFinish(const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **newParamSet)
{
    int32_t ret;
    do {
        ret = AppendProcessNameTag(paramSet, &processInfo->processName, newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append tag processName failed, ret = %d", ret);
            break;
        }
        if (QueryOperation(processInfo, handle) == NULL) {
            HKS_LOG_E("operationHandle is not exist");
            ret = HKS_ERROR_NOT_EXIST;
            break;
        }
    } while (0);
    return ret;
}

int32_t HksServiceFinish(const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);

    struct HksParamSet *newParamSet = NULL;

    bool isStorage = false;
    uint32_t outSize = outData->size;

    struct HksParam *storageFlag = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_STORAGE_FLAG, &storageFlag);
    if ((ret == HKS_SUCCESS) && (storageFlag->uint32Param == HKS_STORAGE_PERSISTENT)) {
        isStorage = true;
        outSize = MAX_KEY_SIZE;
    }

    uint8_t *outBuffer = (uint8_t *)HksMalloc(outSize);
    if (outBuffer == NULL) {
        HksHitraceEnd(&traceId);

        return HKS_ERROR_MALLOC_FAIL;
    }
    struct HksBlob output = { outSize, outBuffer };
    (void)memset_s(output.data, output.size, 0, output.size);

    if (!isStorage) {
        if ((outData->size != 0) && (memcpy_s(output.data, output.size, outData->data, outData->size) != EOK)) {
            HKS_FREE_BLOB(output);
            DeleteOperation(handle);

            HksHitraceEnd(&traceId);

            return HKS_ERROR_BAD_STATE;
        }
    }

    do {
        ret = AppendAndQueryInFinish(handle, processInfo, paramSet, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("AppendAndQueryInFinish fail, ret = %d", ret);
            break;
        }

        ret = HuksAccessFinish(handle, newParamSet, inData, &output);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HuksAccessFinish fail, ret = %d", ret);
            break;
        }

        ret = StoreOrCopyKeyBlob(paramSet, processInfo, &output, outData, isStorage);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("StoreOrCopyKeyBlob fail, ret = %d", ret);
            break;
        }
    } while (0);
    (void)memset_s(output.data, output.size, 0, output.size);
    HKS_FREE_BLOB(output);
    DeleteOperation(handle);
    HksFreeParamSet(&newParamSet);

    HksHitraceEnd(&traceId);

    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

int32_t HksServiceAbort(const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet)
{
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT);
    int32_t ret;
    do {
        if (QueryOperation(processInfo, handle) == NULL) {
            HKS_LOG_E("operationHandle is not exist");
            ret = HKS_SUCCESS; /* return success if the handle is not found */
            break;
        }

        ret = HuksAccessAbort(handle, paramSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HuksAccessAbort fail, ret = %d", ret);
        }
        DeleteOperation(handle);
    } while (0);

    HksHitraceEnd(&traceId);
    
    HksReport(__func__, processInfo, paramSet, ret);

    return ret;
}

void HksServiceDeleteProcessInfo(const struct HksProcessInfo *processInfo)
{
#ifndef __LITEOS_M__
    HKS_LOG_I("remove session");
    DeleteSessionByProcessInfo(processInfo);

    if (processInfo->processName.size == 0) {
        HksServiceDeleteUserIDKeyAliasFile(processInfo->userId);
    } else {
        HksServiceDeleteUIDKeyAliasFile(*processInfo);
    }
#else
    (void)processInfo;
#endif
}

#endif

int32_t HksServiceGenerateRandom(const struct HksBlob *processName, struct HksBlob *random)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksCheckGenerateRandomParams(processName, random);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("check generate random params failed, ret = %d", ret);
            break;
        }

        ret = AppendProcessNameTag(NULL, processName, &newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append processName tag failed, ret = %d", ret);
            break;
        }

        ret = HuksAccessGenerateRandom(newParamSet, random);
    } while (0);

    HksFreeParamSet(&newParamSet);
    
#ifdef L2_STANDARD
    int userId = 0;
    struct HksBlob userIdBlob = { sizeof(int), (uint8_t *)&userId };
    struct HksProcessInfo processInfo = {userIdBlob, *processName};
    
    HksReport(__func__, &processInfo, NULL, ret);
#endif

    return ret;
}
