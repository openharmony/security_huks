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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_client_service_util.h"

#include <stddef.h>

#include "hks_client_check.h"
#include "hks_client_service_common.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_mem.h"
#include "hks_storage_manager.h"
#include "hks_template.h"

#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
#include "hks_bms_api_wrap.h"
#endif

#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#include "hks_config_parser.h"
#endif

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
#include "hks_useridm_api_wrap.h"
#endif

#include "securec.h"

#ifdef _STORAGE_LITE_
#include "hks_storage_adapter.h"
#endif

#ifndef _CUT_AUTHENTICATE_
#ifdef _STORAGE_LITE_

int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet)
{
    struct HksParamSet *tmpParamSet = NULL;
    int32_t ret = TranslateKeyInfoBlobToParamSet(NULL, key, &tmpParamSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    if (paramSet->paramSetSize < tmpParamSet->paramSetSize) {
        HksFreeParamSet(&tmpParamSet);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    if (memcpy_s(paramSet, paramSet->paramSetSize, tmpParamSet, tmpParamSet->paramSetSize) != EOK) {
        HKS_LOG_E("memcpy paramSet failed");
        ret = HKS_ERROR_INSUFFICIENT_MEMORY;
    } else {
        ret = HksFreshParamSet(paramSet, false);
    }

    HksFreeParamSet(&tmpParamSet);
    return ret;
}

#else /* _STORAGE_LITE_ */

static const uint32_t SENSITIVE_DELETE_TAG[] = {
    HKS_TAG_KEY, HKS_TAG_ACCESS_TOKEN_ID, HKS_TAG_USER_AUTH_ENROLL_ID_INFO,
    HKS_TAG_USER_AUTH_SECURE_UID, HKS_TAG_OWNER_ID, HKS_TAG_ACCOUNT_ID, HKS_TAG_SCREEN_STATE,
    HKS_TAG_DERIVE_MAIN_KEY_MODE
};

int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet)
{
    HKS_IF_TRUE_LOGE_RETURN(key->size < sizeof(struct HksParamSet), HKS_ERROR_INVALID_KEY_INFO,
        "get key paramset: invalid key size: %" LOG_PUBLIC "u", key->size)

    const struct HksParamSet *tmpParamSet = (const struct HksParamSet *)key->data;
    struct HksParamSet *outParamSet = NULL;
    int32_t ret = HksDeleteTagsFromParamSet(SENSITIVE_DELETE_TAG,
        sizeof(SENSITIVE_DELETE_TAG) / sizeof(SENSITIVE_DELETE_TAG[0]), tmpParamSet, &outParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "delete tag from paramSet failed, ret = %" LOG_PUBLIC "d.", ret)

    if (paramSet->paramSetSize < outParamSet->paramSetSize) {
        HksFreeParamSet(&outParamSet);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    if (memcpy_s(paramSet, paramSet->paramSetSize, outParamSet, outParamSet->paramSetSize) != EOK) {
        HksFreeParamSet(&outParamSet);
        HKS_LOG_E("copy paramSet failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    ret = HksFreshParamSet(paramSet, false);

    HksFreeParamSet(&outParamSet);
    return ret;
}

int32_t GetKeyFileData(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, struct HksBlob *key, enum HksStorageType mode)
{
    uint32_t size;
    int32_t ret = HksManageStoreGetKeyBlobSize(processInfo, paramSet, keyAlias, &size, mode);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyblob size from storage failed, ret = %" LOG_PUBLIC "d.", ret)

    HKS_IF_TRUE_LOGE_RETURN(size > MAX_KEY_SIZE, HKS_ERROR_INVALID_KEY_FILE,
        "invalid key size, size = %" LOG_PUBLIC "u", size)

    key->data = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_LOGE_RETURN(key->data, HKS_ERROR_MALLOC_FAIL, "get key data: malloc failed")

    key->size = size;
    ret = HksManageStoreGetKeyBlob(processInfo, paramSet, keyAlias, key, mode);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get keyblob from storage failed, ret = %" LOG_PUBLIC "d", ret);
        HKS_FREE_BLOB(*key);
    }
    return ret;
}

#ifdef HKS_ENABLE_UPGRADE_KEY
int32_t ConstructUpgradeKeyParamSet(const struct HksProcessInfo *processInfo, const struct HksParamSet *srcParamSet,
     struct HksParamSet **outParamSet)
{
    (void)srcParamSet;
    struct HksParamSet *paramSet = NULL;
    int32_t ret;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed!")

        struct HksParam processNameParam;
        processNameParam.tag = HKS_TAG_PROCESS_NAME;
        processNameParam.blob = processInfo->processName;

        ret = HksAddParams(paramSet, &processNameParam, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param processNameParam failed!")

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build param set failed!")

        *outParamSet = paramSet;
        return HKS_SUCCESS;
    } while (0);
    HksFreeParamSet(&paramSet);
    return ret;
}
#endif

#endif /* _STORAGE_LITE_ */
#endif /* _CUT_AUTHENTICATE_ */

#ifdef L2_STANDARD
static int32_t AddSpecificUserIdToParamSet(const struct HksOperation *operation, struct HksParamSet *paramSet)
{
    //when use HksUpdate, HksFinish, HksAbort, operation is not null
    HKS_IF_NULL_RETURN(operation, HKS_SUCCESS)
    struct HksParam *specificUserId = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &specificUserId);
    if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        HKS_IF_NOT_TRUE_RETURN(operation->isUserIdPassedDuringInit, HKS_SUCCESS)
        struct HksParam specificUserIdParam;
        specificUserIdParam.tag = HKS_TAG_SPECIFIC_USER_ID;
        specificUserIdParam.int32Param = operation->userIdPassedDuringInit;
        ret = HksAddParams(paramSet, &specificUserIdParam, 1);
    }
    return ret;
}

#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
static int32_t GetStorageLevelForSkipUpgradeApp(const struct HksProcessInfo *processInfo, struct HksParam *storageLevel)
{
    HKS_IF_NULL_RETURN(processInfo, HKS_SUCCESS)
    struct HksUpgradeFileTransferInfo info = { 0 };
    int32_t ret = HksMatchConfig("", processInfo->uidInt, processInfo->userIdInt, processInfo->accessTokenId, &info);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "match skip upgarde config failed.")
    if (info.skipTransfer) {
        storageLevel->uint32Param = HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP;
    }
    return HKS_SUCCESS;
}
#endif

static int32_t AddStorageLevelToParamSet(const struct HksProcessInfo *processInfo, struct HksParamSet *paramSet)
{
    struct HksParam *storageLevel = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &storageLevel);
    if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        struct HksParam storageLevelParam;
        storageLevelParam.tag = HKS_TAG_AUTH_STORAGE_LEVEL;
        storageLevelParam.uint32Param = HKS_AUTH_STORAGE_LEVEL_CE;

#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
        ret = GetStorageLevelForSkipUpgradeApp(processInfo, &storageLevelParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get default storage level for skip upgrade app failed.")
#endif
        ret = HksAddParams(paramSet, &storageLevelParam, 1);
    }
    return ret;
}

static int32_t AppendStorageLevelAndSpecificUserIdToParamSet(const struct HksProcessInfo *processInfo,
    const struct HksOperation *operation, struct HksParamSet *paramSet)
{
    int32_t ret = AddSpecificUserIdToParamSet(operation, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add specific userid tag failed")

    ret = AddStorageLevelToParamSet(processInfo, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add storage level tag failed")

    return HKS_SUCCESS;
}

int32_t AppendStorageLevelIfNotExistInner(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    do {
        if (paramSet != NULL) {
            ret = AppendToNewParamSet(paramSet, &newParamSet);
        } else {
            ret = HksInitParamSet(&newParamSet);
        }

        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append tag to new paramset failed")

        ret = AppendStorageLevelAndSpecificUserIdToParamSet(processInfo, NULL, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add default strategy failed")

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed")
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    *outParamSet = newParamSet;
    return ret;
}

int32_t AppendStorageLevelIfNotExist(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    return AppendStorageLevelIfNotExistInner(NULL, paramSet, outParamSet);
}
#endif

bool CheckProcessNameTagExist(const struct HksParamSet *paramSet)
{
    for (uint32_t i = 0; i < paramSet->paramsCnt; ++i) {
        if (paramSet->params[i].tag == HKS_TAG_PROCESS_NAME) {
            return true;
        }
    }
    return false;
}

#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
static bool HksCheckIsAcrossDevices(const struct HksParamSet *paramSet)
{
    if (HksCheckIsAllowedWrap(paramSet)) {
        return true;
    }
    struct HksParam *wrapTypeParam = NULL;
    if (HksGetParam(paramSet, HKS_TAG_KEY_WRAP_TYPE, &wrapTypeParam) == HKS_SUCCESS) {
        return true;
    }
    return false;
}

static int32_t AppendOwnerInfoForAcrossDevicesIfNeed(const struct HksProcessInfo *processInfo,
    struct HksParamSet *newParamSet, struct HksBlob *appInfo)
{
    HKS_IF_NOT_TRUE_RETURN(HksCheckIsAcrossDevices(newParamSet), HKS_SUCCESS)

    int32_t ret;
    do {
        ret = GetCallerName(processInfo, appInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "GetCallerName failed")

        struct HksParam paramArr[] = {
            { .tag = HKS_TAG_OWNER_ID, .blob = *appInfo },
            { .tag = HKS_TAG_OWNER_TYPE, .uint32Param = HksGetCallerType() },
        };

        ret = HksAddParams(newParamSet, paramArr, HKS_ARRAY_SIZE(paramArr));
    } while (0);

    return ret;
}
#endif
#if defined(L2_STANDARD) && defined(HKS_SUPPORT_GET_BUNDLE_INFO)
static int32_t AppendDeveloperId(const struct HksProcessInfo *processInfo, struct HksParamSet *outParamSet,
    struct HksBlob *developerId)
{
    int32_t ret = HksCheckAssetAccessGroup(processInfo, outParamSet);
    HKS_IF_TRUE_RETURN(ret == HKS_ERROR_PARAM_NOT_EXIST, HKS_SUCCESS)
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "groupid is invalid")

    do {
        ret = HksGetDeveloperId(processInfo, developerId);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get developerId failed")

        struct HksParam paramArr[] = {
            { .tag = HKS_TAG_DEVELOPER_ID, .blob = *developerId },
        };

        ret = HksAddParams(outParamSet, paramArr, HKS_ARRAY_SIZE(paramArr));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add developerInfo failed")
        return HKS_SUCCESS;
    } while (0);

    return ret;
}
#endif
int32_t AppendProcessInfoAndDefault(const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo,
    const struct HksOperation *operation, struct HksParamSet **outParamSet, bool checkGroup)
{
    int32_t ret;
    (void)operation;
    (void)checkGroup;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob appInfo = { 0, NULL };
    struct HksBlob developerId = { 0, NULL };
    do {
        if (paramSet != NULL) {
            ret = AppendToNewParamSet(paramSet, &newParamSet);
        } else {
            ret = HksInitParamSet(&newParamSet);
        }

        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append client service tag failed")

        // process name only can be inserted by service
        ret = HKS_ERROR_INVALID_ARGUMENT;
        HKS_IF_TRUE_BREAK(CheckProcessNameTagExist(newParamSet))

        struct HksParam paramArr[] = {
            { .tag = HKS_TAG_PROCESS_NAME, .blob = processInfo->processName },
            { .tag = HKS_TAG_USER_ID, .uint32Param = processInfo->userIdInt },
            { .tag = HKS_TAG_SCREEN_STATE, .boolParam = HksGetScreenState() },
#ifdef HKS_SUPPORT_ACCESS_TOKEN
            { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = processInfo->accessTokenId },
#endif
        };

        ret = HksAddParams(newParamSet, paramArr, HKS_ARRAY_SIZE(paramArr));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add processInfo failed")

#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
        ret = AppendOwnerInfoForAcrossDevicesIfNeed(processInfo, newParamSet, &appInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add ownerInfo failed")
#endif

#ifdef L2_STANDARD
        ret = AppendStorageLevelAndSpecificUserIdToParamSet(processInfo, operation, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add default strategy failed")
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
        if (checkGroup) { // only check access group id if needed
            ret = AppendDeveloperId(processInfo, newParamSet, &developerId);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append group key info failed, ret = %" LOG_PUBLIC "d", ret)
        }
#endif
#endif
        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed")

        *outParamSet = newParamSet;
        newParamSet = NULL;
    } while (0);

    HKS_FREE_BLOB(appInfo);
    HKS_FREE_BLOB(developerId);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t AppendNewInfoForUseKeyInService(const struct HksParamSet *paramSet,
    const struct HksProcessInfo *processInfo, struct HksParamSet **outParamSet)
{
    return AppendProcessInfoAndDefault(paramSet, processInfo, NULL, outParamSet, true);
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
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(enrolledInfo->data, enrolledInfo->size, &secInfo->enrolledInfoLen,
        sizeof(uint32_t)), HKS_ERROR_INSUFFICIENT_MEMORY, "copy enrolledInfoLen failed!")
    index += sizeof(secInfo->enrolledInfoLen);
    for (uint32_t i = 0; i < secInfo->enrolledInfoLen; ++i) {
        uint32_t authTypeInt = (uint32_t)secInfo->enrolledInfo[i].authType;
        HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(enrolledInfo->data + index, enrolledInfo->size - index, &authTypeInt,
            sizeof(uint32_t)), HKS_ERROR_INSUFFICIENT_MEMORY, "copy authType failed!")
        index += sizeof(authTypeInt);
        HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(enrolledInfo->data + index, enrolledInfo->size - index,
            &((secInfo->enrolledInfo[i]).enrolledId), sizeof(uint64_t)) != EOK, HKS_ERROR_INSUFFICIENT_MEMORY,
            "copy enrolledId failed!")
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
    struct HksParamSet **paramSet)
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
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ConstructEnrolledInfoBlob failed!")

        ret = HksAddParams(*paramSet, &tmpParam, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add params failed")

        ret = HksBuildParamSet(paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build append info failed")
    } while (0);
    HKS_FREE(enrolledInfo->data);
    return ret;
}

static int32_t BuildUserAuthParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;
    int32_t ret;
    do {
        ret = (paramSet != NULL) ? AppendToNewParamSet(paramSet, &newParamSet) : HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed")
        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build append info failed")
        *outParamSet = newParamSet;

        return HKS_SUCCESS;
    } while (0);

    HksFreeParamSet(&newParamSet);
    *outParamSet = NULL;
    return ret;
}

// callback
static int32_t AppendUserAuthInfo(const struct HksParamSet *paramSet, int32_t userId, uint32_t authAccessType,
    struct HksParamSet **outParamSet)
{
    (void)authAccessType;
    struct SecInfoWrap *secInfo = NULL;
    struct HksParamSet *newParamSet = NULL;
    int32_t ret;

    struct HksBlob enrolledInfo = { 0, NULL };
    do {
        ret = HksUserIdmGetSecInfo(userId, &secInfo); // callback
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get useriam sec info failed ret=%" LOG_PUBLIC "d", ret);
            ret = HKS_ERROR_GET_USERIAM_SECINFO_FAILED;
            break;
        }

        ret = (paramSet != NULL) ? AppendToNewParamSet(paramSet, &newParamSet) : HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed")

        ret = AppendSecUid(newParamSet, secInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append sec uid failed")

        ret = AddEnrolledInfoInParamSet(secInfo, &enrolledInfo, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AddEnrolledInfoInParamSet failed!")

        *outParamSet = newParamSet;
    } while (0);
    HKS_MEMSET_FREE_BLOB(enrolledInfo);
    if (secInfo != NULL) {
        HKS_MEMSET_FREE_PTR(secInfo->enrolledInfo, sizeof(struct EnrolledInfoWrap) * secInfo->enrolledInfoLen);
        HKS_MEMSET_FREE_PTR(secInfo, sizeof(struct SecInfoWrap));
    }
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        *outParamSet = NULL;
    }
    return ret;
}

// callback
static int32_t CheckIfEnrollAuthInfo(int32_t userId, enum HksUserAuthType authType)
{
    uint32_t numOfAuthInfo = 0;
    int32_t ret = HksUserIdmGetAuthInfoNum(userId, authType, &numOfAuthInfo); // callback
    HKS_IF_TRUE_LOGE_RETURN(ret == HKS_ERROR_CREDENTIAL_NOT_EXIST || numOfAuthInfo == 0,
        HKS_ERROR_CREDENTIAL_NOT_EXIST, "have not enroll the auth info.")

    return ret;
}

// callback
static int32_t CheckIfUserIamSupportCurType(int32_t userId, uint32_t userAuthType)
{
    const enum HksUserAuthType userAuthTypes[] = {
        HKS_USER_AUTH_TYPE_FINGERPRINT,
        HKS_USER_AUTH_TYPE_FACE,
        HKS_USER_AUTH_TYPE_PIN
    };
    int32_t ret;
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(userAuthTypes); ++i) {
        HKS_IF_TRUE_CONTINUE((userAuthType & userAuthTypes[i]) == 0);
        ret = CheckIfEnrollAuthInfo(userId, userAuthTypes[i]); // callback
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
            "no enrolled info of the user auth type: %" LOG_PUBLIC "d.", userAuthTypes[i])
    }
    return HKS_SUCCESS;
}

// callback
int32_t AppendNewInfoForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    uint32_t userAuthType = 0;
    uint32_t authAccessType = 0;
    int32_t ret = HksCheckAndGetUserAuthInfo(paramSet, processInfo->uidInt, &userAuthType, &authAccessType);
    if (ret == HKS_ERROR_NOT_SUPPORTED) {
        struct HksParamSet *newParamSet = NULL;
        ret = AppendProcessInfoAndDefault(paramSet, processInfo, NULL, &newParamSet, true);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
            "append process info and default strategy failed, ret = %" LOG_PUBLIC "d", ret)
        *outParamSet = newParamSet;
        return HKS_SUCCESS;
    }

    if (ret == HKS_SUCCESS) {
        HKS_LOG_I("support secure access");

        // Fine-grained access control: only valid user auth key purpose allowed to be set.
        ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check user auth key purpose validity failed")

        struct HksParamSet *userAuthParamSet = NULL;

        if (authAccessType == HKS_AUTH_ACCESS_ALWAYS_VALID) {
            HKS_LOG_I("authAccessType is always vaild, CheckIfUserIamSupportCurType pass.");
            ret = BuildUserAuthParamSet(paramSet, &userAuthParamSet);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Build UserAuthParamSet failed!")
        } else {
            HKS_IF_TRUE_LOGE_RETURN(HksCheckIsAllowedWrap(paramSet), HKS_ERROR_KEY_NOT_ALLOW_WRAP,
                "key with access control isn't allowed wrap!")

            void *data = HksLockUserIdm();
            HKS_IF_NULL_LOGE_RETURN(data, HKS_ERROR_SESSION_REACHED_LIMIT, "HksLockUserIdm fail")
            do {
                ret = CheckIfUserIamSupportCurType(processInfo->userIdInt, userAuthType); // callback
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
                    "UserIAM do not support current user auth or not enrolled cur auth info")

                // callback
                ret = AppendUserAuthInfo(paramSet, processInfo->userIdInt, authAccessType, &userAuthParamSet);
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append secure access info failed!")
            } while (false);
            HksUnlockUserIdm(data);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "CheckIfUserIamSupportCurType or AppendUserAuthInfo fail")
        }
        struct HksParamSet *newInfoParamSet = NULL;
        ret = AppendProcessInfoAndDefault(userAuthParamSet, processInfo, NULL, &newInfoParamSet, true);
        HksFreeParamSet(&userAuthParamSet);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
            "append process info and default strategy failed, ret = %" LOG_PUBLIC "d", ret)
        
        *outParamSet = newInfoParamSet;
        return HKS_SUCCESS;
    }
    return ret;
}
#else
int32_t AppendNewInfoForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    return AppendProcessInfoAndDefault(paramSet, processInfo, NULL, outParamSet, true);
}
#endif /* HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL */
#endif /* _CUT_AUTHENTICATE_ */