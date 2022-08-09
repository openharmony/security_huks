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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_secure_access.h"

#include "hks_log.h"
#include "hks_param.h"
#include "hks_type_inner.h"
#include "hks_mem.h"
#include "hks_keyblob.h"
#include "hks_keynode.h"
#include "hks_base_check.h"

#include "securec.h"

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL

#include "hks_crypto_hal.h"
#include "hks_core_hal_api.h"
#include "hks_useridm_api_wrap.h"

#define BYTES_PER_POS 8
#define S_TO_MS 1000
#define DEFAULT_TIME_OUT 3
#define AUTH_INFO_LEN (sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t))

struct HksSecureAccessInnerParams {
    const struct HksParamSet *initParamSet;
    uint32_t challengePos;
    bool isUserAuthAccess;
    bool isSecureSign;
    struct HksBlob *outToken;
};

struct HksAppendDataInnerParams {
    struct HuksKeyNode *keyNode;
    const struct HksParamSet *inParamSet;
    const struct HksBlob *inData;
};

static int32_t CheckChallengeTypeValidity(const struct HksParam *blobChallengeType,
    struct HksSecureAccessInnerParams *innerParams)
{
    if (blobChallengeType->uint32Param == HKS_CHALLENGE_TYPE_CUSTOM) {
        struct HksParam *challengePosParam = NULL;
        int32_t ret = HksGetParam(innerParams->initParamSet, HKS_TAG_CHALLENGE_POS, &challengePosParam);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get init paramSet's challenge pos failed!");
            return ret;
        }
        if (challengePosParam->uint32Param > HKS_CHALLENGE_POS_3) {
            HKS_LOG_E("challenge position should in range of 0~3!");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        innerParams->challengePos = challengePosParam->uint32Param;
    } else {
        innerParams->challengePos = 0;
    }

    if (blobChallengeType->uint32Param == HKS_CHALLENGE_TYPE_NONE) {
        // must set zero for ClientInit judgement
        innerParams->outToken->size = 0;
        return HKS_SUCCESS;
    }

    if (innerParams->outToken->size < TOKEN_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t CheckInitParamSetValidityAndGet(const struct HksParamSet *keyBlobParamSet,
    struct HksSecureAccessInnerParams *innerParams)
{
    struct HksParam *blobUserAuthType = NULL;
    int32_t ret = HksGetParam(keyBlobParamSet, HKS_TAG_USER_AUTH_TYPE, &blobUserAuthType);
    if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        innerParams->isUserAuthAccess = false;
        innerParams->isSecureSign = false;
        // must set zero for ClientInit judgement
        innerParams->outToken->size = 0;
        return HKS_SUCCESS;
    }

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get blob user auth type failed!");
        return ret;
    }

    struct HksParam *blobChallengeType = NULL;
    ret = HksGetParam(keyBlobParamSet, HKS_TAG_CHALLENGE_TYPE, &blobChallengeType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get blob challenge type failed!");
        return ret;
    }

    ret = CheckChallengeTypeValidity(blobChallengeType, innerParams);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check init paramSet's challenge type related params failed!");
        return ret;
    }

    struct HksParam *secureSignTag = NULL;
    ret = HksGetParam(keyBlobParamSet, HKS_TAG_KEY_SECURE_SIGN_TYPE, &secureSignTag);
    if (ret == HKS_SUCCESS) {
        ret = HksCheckSecureSignParams(secureSignTag->uint32Param);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("invalid key blob secure sign type!");
            return HKS_ERROR_BAD_STATE;
        }
        innerParams->isSecureSign = true;
    } else {
        innerParams->isSecureSign = false;
    }

    innerParams->isUserAuthAccess = true;
    return HKS_SUCCESS;
}

static int32_t AddChallengeParams(struct HksParamSet *paramSet, struct HksBlob *challengeBlob)
{
    int32_t ret = HksCryptoHalFillRandom(challengeBlob);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("generate challenge failed!");
        return ret;
    }

    struct HksParam challengeParam;
    challengeParam.tag = HKS_TAG_KEY_INIT_CHALLENGE;
    challengeParam.blob = *challengeBlob;
    ret = HksAddParams(paramSet, &challengeParam, 1);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("add challenge params fail");
        return ret;
    }
    return HKS_SUCCESS;
}

static int32_t AddKeyAccessTimeParams(struct HksParamSet *paramSet)
{
    uint64_t curTime = 0;
    int32_t ret = HksCoreHalElapsedRealTime(&curTime);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get elapsed real time failed!");
        return ret;
    }

    struct HksParam accessTimeParam;
    accessTimeParam.tag = HKS_TAG_ACCESS_TIME;
    accessTimeParam.uint32Param = curTime / S_TO_MS;
    ret = HksAddParams(paramSet, &accessTimeParam, 1);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("add access time param fail");
        return ret;
    }
    return HKS_SUCCESS;
}

static int32_t AssignToken(struct HksBlob *token, const struct HksBlob *challenge)
{
    if (token->size >= TOKEN_SIZE) {
        if (memcpy_s(token->data, token->size, challenge->data, challenge->size) != EOK) {
            HKS_LOG_E("copy token failed");
            return HKS_ERROR_BAD_STATE;
        }
        token->size = challenge->size;
        return HKS_SUCCESS;
    } else if (token->size == 0) {
        return HKS_SUCCESS;
    } else {
        HKS_LOG_E("token size is too small");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
}

static int32_t AddAppendDataPlaceholder(struct HksParamSet *paramSet, uint8_t *appendDataPlaceholder,
    uint32_t placeholderSize)
{
    struct HksParam signAuthParam = {
        .tag = HKS_TAG_APPENDED_DATA_PREFIX,
        .blob = {
            .size = placeholderSize,
            .data = appendDataPlaceholder
        }
    };

    int32_t ret = HksAddParams(paramSet, &signAuthParam, 1);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("add sign auth info params fail");
        return ret;
    }
    return HKS_SUCCESS;
}

static int32_t AddDefaultAuthRuntimeParams(struct HksParamSet *paramSet,
    struct HksSecureAccessInnerParams *innerParams, bool isNeedAppendAuthInfo)
{
    struct HksParam defineParams[] = {
        { .tag = HKS_TAG_IS_USER_AUTH_ACCESS, .boolParam = innerParams->isUserAuthAccess },
        { .tag = HKS_TAG_IF_NEED_APPEND_AUTH_INFO, .boolParam = isNeedAppendAuthInfo },
        { .tag = HKS_TAG_IS_APPEND_UPDATE_DATA, .boolParam = false },
        { .tag = HKS_TAG_KEY_AUTH_RESULT, .int32Param = HKS_AUTH_RESULT_INIT },
        { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = innerParams->challengePos }
    };

    int32_t ret = HksAddParams(paramSet, defineParams, sizeof(defineParams) / sizeof(defineParams[0]));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("add runtime defineParams fail");
        return ret;
    }
    return HKS_SUCCESS;
}

static int32_t BuildAuthRuntimeParamSet(struct HksSecureAccessInnerParams *innerParams, bool isNeedAppendAuthInfo,
    struct HksParamSet **outParamSet)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init keyNode auth runtime param set fail");
        return ret;
    }

    do {
        ret = AddDefaultAuthRuntimeParams(paramSet, innerParams, isNeedAppendAuthInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add auth runtime default params fail");
            break;
        }

        ret = AddKeyAccessTimeParams(paramSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add key access time params failed!");
            break;
        }

        uint8_t challenge[TOKEN_SIZE] = {0};
        struct HksBlob challengeBlob = { TOKEN_SIZE, challenge };
        ret = AddChallengeParams(paramSet, &challengeBlob);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add challenge params failed!");
            break;
        }

        if (isNeedAppendAuthInfo) {
            uint8_t appendPlaceholder[sizeof(struct HksSecureSignAuthInfo)] = {0};
            ret = AddAppendDataPlaceholder(paramSet, appendPlaceholder, sizeof(appendPlaceholder));
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("add append data info params fail");
                break;
            }
        }

        ret = HksBuildParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = AssignToken(innerParams->outToken, &challengeBlob);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("assign out token failed");
            break;
        }

        *outParamSet = paramSet;
        return HKS_SUCCESS;
    } while (0);

    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t HksVerifyKeyChallenge(const struct HuksKeyNode *keyNode, const struct HksUserAuthToken *token,
    uint32_t challengePos, uint32_t checkLen)
{
    struct HksParam *challenge = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_KEY_INIT_CHALLENGE, &challenge);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get init challenge failed!");
        return HKS_ERROR_BAD_STATE;
    }
    if (checkLen + challengePos * BYTES_PER_POS > challenge->blob.size) {
        HKS_LOG_E("check challenge too long!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (HksMemCmp(challenge->blob.data + challengePos * BYTES_PER_POS, token->challenge + challengePos * BYTES_PER_POS,
        checkLen) != 0) {
        HKS_LOG_E("verify challenge failed!");
        return HKS_ERROR_KEY_AUTH_FAILED;
    }
    return HKS_SUCCESS;
}

static int32_t HksVerifyKeyTimestamp(const struct HuksKeyNode *keyNode, const struct HksUserAuthToken *token)
{
    uint32_t timeOutInt = DEFAULT_TIME_OUT;
    struct HksParam *timeOut = NULL;
    int32_t ret = HksGetParam(keyNode->keyBlobParamSet, HKS_TAG_AUTH_TIMEOUT, &timeOut);
    if (ret == HKS_SUCCESS) {
        timeOutInt = timeOut->uint32Param;
    }

    struct HksParam *accessTime = NULL;
    ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_ACCESS_TIME, &accessTime);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get access time failed!");
        return HKS_ERROR_BAD_STATE;
    }
    
    // ms to s
    uint32_t authTokenTime = token->time / 1000;
    if (accessTime->uint32Param - authTokenTime > timeOutInt ||
        authTokenTime - accessTime->uint32Param > timeOutInt) {
        HKS_LOG_E("auth token time out!");
        return HKS_ERROR_KEY_AUTH_FAILED;
    }
    return HKS_SUCCESS;
}

static int32_t CheckAuthToken(const struct HksBlob *authTokenParam)
{
    if (authTokenParam->size != sizeof(struct HksUserAuthToken)) {
        HKS_LOG_E("size of authTokenParam not match HksUserAuthToken!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t ParseAuthToken(const struct HksBlob *inAuthTokenParam, struct HksUserAuthToken **outAuthToken)
{
    int32_t ret = CheckAuthToken(inAuthTokenParam);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    struct HksUserAuthToken *authToken = NULL;
    do {
        authToken = (struct HksUserAuthToken *)HksMalloc(sizeof(struct HksUserAuthToken));
        if (authToken == NULL) {
            HKS_LOG_E("malloc for authToken failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        if (memcpy_s(authToken, sizeof(struct HksUserAuthToken), inAuthTokenParam->data,
            inAuthTokenParam->size) != EOK) {
            HKS_LOG_E("memcpy for authToken failed!");
            ret = HKS_ERROR_BAD_STATE;
            break;
        }

        *outAuthToken = authToken;
        return HKS_SUCCESS;
    } while (0);

    HKS_FREE_PTR(authToken);
    return ret;
}

static int32_t GetAuthToken(const struct HksParamSet *paramSet, struct HksUserAuthToken **authToken)
{
    struct HksParam *authTokenParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_AUTH_TOKEN, &authTokenParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get auth token param failed!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    ret = ParseAuthToken(&authTokenParam->blob, authToken);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("parse auth token failed!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t GetChallengePos(const struct HksParamSet *paramSet, uint32_t *pos)
{
    struct HksParam *posParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_CHALLENGE_POS, &posParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get challenge pos failed!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    *pos = posParam->uint32Param;
    return ret;
}

static int32_t GetChallengeType(const struct HksParamSet *paramSet, uint32_t *type)
{
    struct HksParam *typeParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_CHALLENGE_TYPE, &typeParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get challenge type failed!");
        return HKS_ERROR_BAD_STATE;
    }
    *type = typeParam->uint32Param;
    return HKS_SUCCESS;
}

static int32_t VerifyCustomChallenge(const struct HuksKeyNode *keyNode, const struct HksUserAuthToken *authToken)
{
    uint32_t pos = 0;
    int32_t ret = GetChallengePos(keyNode->authRuntimeParamSet, &pos);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get challenge pos failed!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HksVerifyKeyChallenge(keyNode, authToken, pos, BYTES_PER_POS);
}

static int32_t VerifyNormalChallenge(const struct HuksKeyNode *keyNode, const struct HksUserAuthToken *authToken)
{
    return HksVerifyKeyChallenge(keyNode, authToken, 0, TOKEN_SIZE);
}

static int32_t VerifyChallengeOrTimeStamp(const struct HuksKeyNode *keyNode, const struct HksUserAuthToken *authToken)
{
    uint32_t blobChallengeType;
    int32_t ret = GetChallengeType(keyNode->keyBlobParamSet, &blobChallengeType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get challenge type failed!");
        return ret;
    }

    switch (blobChallengeType) {
        case HKS_CHALLENGE_TYPE_NORMAL:
            ret = VerifyNormalChallenge(keyNode, authToken);
            break;
        case HKS_CHALLENGE_TYPE_CUSTOM:
            ret = VerifyCustomChallenge(keyNode, authToken);
            break;
        case HKS_CHALLENGE_TYPE_NONE:
            ret = HksVerifyKeyTimestamp(keyNode, authToken);
            break;
        default:
            ret = HKS_ERROR_BAD_STATE;
            break;
    }
    return ret;
}

static int32_t VerifySecureUidIfNeed(const struct HksParamSet *keyBlobParamSet,
    const struct HksUserAuthToken *authToken, uint32_t userAuthType, uint32_t authAccessType)
{
    if ((userAuthType & HKS_USER_AUTH_TYPE_PIN) == 0 ||
        (authAccessType & HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD) == 0) {
        return HKS_SUCCESS;
    }

    struct HksParam *secUid = NULL;
    int32_t ret = HksGetParam(keyBlobParamSet, HKS_TAG_USER_AUTH_SECURE_UID, &secUid);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get sec uid failed!");
        return HKS_ERROR_BAD_STATE;
    }

    if (secUid->blob.size != sizeof(uint64_t)) {
        HKS_LOG_E("invalid sec uid param!");
        return HKS_ERROR_BAD_STATE;
    }

    if (HksMemCmp(secUid->blob.data, &authToken->secureUid, sizeof(uint64_t)) != 0) {
        HKS_LOG_E("check sec uid failed!");
        return HKS_ERROR_KEY_AUTH_FAILED;
    }
    return HKS_SUCCESS;
}

static int32_t VerifyEnrolledIdInfoIfNeed(const struct HksParamSet *keyBlobParamSet,
    const struct HksUserAuthToken *authToken, uint32_t blobAuthType, uint32_t authAccessType)
{
    if ((blobAuthType & (HKS_USER_AUTH_TYPE_FACE | HKS_USER_AUTH_TYPE_FINGERPRINT)) == 0 ||
        (authAccessType & HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL) == 0) {
        return HKS_SUCCESS;
    }

    uint32_t authTokenAuthType = 0;
    int32_t ret = HksConvertUserIamTypeToHksType(HKS_AUTH_TYPE, authToken->authType, &authTokenAuthType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("invalid user iam auth type:not support!");
        return HKS_ERROR_NOT_SUPPORTED;
    }

    if ((authTokenAuthType & blobAuthType) == 0) {
        HKS_LOG_E("current keyblob auth do not support current auth token auth type!");
        return HKS_ERROR_KEY_AUTH_FAILED;
    }

    struct HksParam *enrolledIdInfo = NULL;
    ret = HksGetParam(keyBlobParamSet, HKS_TAG_USER_AUTH_ENROLL_ID_INFO, &enrolledIdInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get enrolled info param failed!");
        return HKS_ERROR_BAD_STATE;
    }

    struct HksBlob enrolledIdInfoBlob = enrolledIdInfo->blob;
    if (enrolledIdInfoBlob.size < ENROLLED_ID_INFO_MIN_LEN) {
        HKS_LOG_E("get enrolled info param invalid!");
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t enrolledIdNum = 0;
    if (memcpy_s(&enrolledIdNum, sizeof(uint32_t), enrolledIdInfoBlob.data, sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("copy enrolled id len failed!");
        return HKS_ERROR_BAD_STATE;
    }
    uint32_t index = sizeof(uint32_t);

    for (uint32_t i = 0; i < enrolledIdNum && index < enrolledIdInfoBlob.size; ++i) {
        uint32_t authType = 0;
        if (memcpy_s(&authType, sizeof(uint32_t), enrolledIdInfoBlob.data + index, sizeof(uint32_t)) != EOK) {
            HKS_LOG_E("copy authType failed!");
            return HKS_ERROR_BAD_STATE;
        }
        index += sizeof(uint32_t);

        uint64_t enrolledId = 0;
        if (memcpy_s(&enrolledId, sizeof(uint64_t), enrolledIdInfoBlob.data + index, sizeof(uint64_t)) != EOK) {
            HKS_LOG_E("copy enrolledId failed!");
            return HKS_ERROR_BAD_STATE;
        }
        index += sizeof(uint64_t);
        if (authType == authTokenAuthType && enrolledId == authToken->enrolledId) {
            return HKS_SUCCESS;
        }
    }
    HKS_LOG_E("match enrolled id failed!");
    return HKS_ERROR_KEY_AUTH_FAILED;
}

static int32_t VerifyAuthTokenInfo(const struct HuksKeyNode *keyNode, const struct HksUserAuthToken *authToken)
{
    struct HksParamSet *keyBlobParamSet = keyNode->keyBlobParamSet;
    struct HksParam *userAuthType = NULL;
    int32_t ret = HksGetParam(keyBlobParamSet, HKS_TAG_USER_AUTH_TYPE, &userAuthType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get userAuthType type failed!");
        return HKS_ERROR_BAD_STATE;
    }

    struct HksParam *authAccessType = NULL;
    ret = HksGetParam(keyBlobParamSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &authAccessType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get auth access type failed!");
        return HKS_ERROR_BAD_STATE;
    }

    ret = VerifySecureUidIfNeed(keyBlobParamSet, authToken, userAuthType->uint32Param, authAccessType->uint32Param);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("verify sec uid failed!");
        return ret;
    }

    ret = VerifyEnrolledIdInfoIfNeed(keyBlobParamSet, authToken, userAuthType->uint32Param,
        authAccessType->uint32Param);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("verify enrolled id info failed!");
        return ret;
    }

    return ret;
}

static int32_t HksAddVerifiedAuthTokenIfNeed(struct HuksKeyNode *keyNode,
    const struct HksUserAuthToken *verifiedAuthToken)
{
    struct HksParam *isNeedSecureSignInfo = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_IF_NEED_APPEND_AUTH_INFO, &isNeedSecureSignInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get is secure sign failed!");
        return HKS_ERROR_BAD_STATE;
    }

    if (isNeedSecureSignInfo->boolParam == false) {
        return HKS_SUCCESS;
    }

    struct HksParamSet *newAuthRuntimeParamSet = NULL;
    ret = HksInitParamSet(&newAuthRuntimeParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init new auth param set fail");
        return ret;
    }

    struct HksParamSet *authRuntimeParamSet = keyNode->authRuntimeParamSet;
    if (authRuntimeParamSet != NULL) {
        ret = HksAddParams(newAuthRuntimeParamSet, authRuntimeParamSet->params, authRuntimeParamSet->paramsCnt);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(&newAuthRuntimeParamSet);
            HKS_LOG_E("add old auth runtime param set fail");
            return ret;
        }
    }

    struct HksParam verifiedAuthTokenParam = {
        .tag = HKS_TAG_VERIFIED_AUTH_TOKEN,
        .blob = {
            .size = sizeof(struct HksUserAuthToken),
            .data = (uint8_t *)verifiedAuthToken
        }
    };

    ret = HksAddParams(newAuthRuntimeParamSet, &verifiedAuthTokenParam, 1);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newAuthRuntimeParamSet);
        HKS_LOG_E("add verified authtoken to auth runtime param set fail");
        return ret;
    }

    ret = HksBuildParamSet(&newAuthRuntimeParamSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newAuthRuntimeParamSet);
        HKS_LOG_E("build paramSet fail");
        return ret;
    }
    HksFreeParamSet(&authRuntimeParamSet);
    keyNode->authRuntimeParamSet = newAuthRuntimeParamSet;
    return HKS_SUCCESS;
}

static int32_t CheckIfNeedVerifyParams(const struct HuksKeyNode *keyNode, bool *isNeedVerify,
    struct HksParam **outAuthResult)
{
    struct HksParam *isNeedSecureAccess = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_IS_USER_AUTH_ACCESS, &isNeedSecureAccess);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get isSecureAccess failed!");
        return HKS_ERROR_BAD_STATE;
    }

    struct HksParam *authResult = NULL;
    ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_KEY_AUTH_RESULT, &authResult);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get authResult failed!");
        return HKS_ERROR_BAD_STATE;
    }

    *outAuthResult = authResult;
    if (isNeedSecureAccess->boolParam == false) {
        *isNeedVerify = false;
        return HKS_SUCCESS;
    }

    if (authResult->uint32Param == HKS_AUTH_RESULT_SUCCESS) {
        *isNeedVerify = false;
        return HKS_SUCCESS;
    }

    *isNeedVerify = true;
    return HKS_SUCCESS;
}

static int32_t AssignVerifyResultAndFree(bool isSuccess, struct HksParam *authResult, struct HuksKeyNode *keyNode,
    struct HksUserAuthToken *authToken)
{
    if (isSuccess) {
        authResult->uint32Param = HKS_AUTH_RESULT_SUCCESS;
        int32_t ret = HksAddVerifiedAuthTokenIfNeed(keyNode, authToken);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add verified auth token failed!");
            HKS_FREE_PTR(authToken);
            return HKS_ERROR_BAD_STATE;
        }
    } else {
        authResult->uint32Param = HKS_AUTH_RESULT_FAILED;
        HKS_FREE_PTR(authToken);
        return HKS_ERROR_KEY_AUTH_FAILED;
    }
    HKS_FREE_PTR(authToken);
    return HKS_SUCCESS;
}


static int32_t GetUserAuthResult(const struct HuksKeyNode *keyNode, int32_t *authResult)
{
    struct HksParam *isSecureAccess = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_IS_USER_AUTH_ACCESS, &isSecureAccess);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get isSecureAccess failed!");
        return HKS_ERROR_BAD_STATE;
    }

    if (isSecureAccess->boolParam == false) {
        *authResult = HKS_AUTH_RESULT_NONE;
        return HKS_SUCCESS;
    }

    struct HksParam *authResultParam = NULL;
    ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_KEY_AUTH_RESULT, &authResultParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get authResult failed!");
        return HKS_ERROR_BAD_STATE;
    }
    *authResult = authResultParam->int32Param;
    return HKS_SUCCESS;
}

static int32_t CheckParamsAndGetAppendState(const struct HuksKeyNode *keyNode, struct HksParam **isAppendDataParam)
{
    if (keyNode == NULL) {
        HKS_LOG_E("the pointer param is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isAppendData = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_IS_APPEND_UPDATE_DATA, &isAppendData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get is append update param failed");
        return HKS_ERROR_BAD_STATE;
    }

    *isAppendDataParam = isAppendData;
    return HKS_SUCCESS;
}

static int32_t GetSupportAppendAuthInfoParams(const struct HuksKeyNode *keyNode, bool *isNeedAppendAuthInfo,
    int32_t *authResultOut)
{
    struct HksParam *isNeedAppendParam = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_IF_NEED_APPEND_AUTH_INFO, &isNeedAppendParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get is need append param failed");
        return HKS_ERROR_BAD_STATE;
    }

    int32_t authResult = (int32_t) HKS_AUTH_RESULT_NONE;
    ret = GetUserAuthResult(keyNode, &authResult);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get auth result failed");
        return HKS_ERROR_BAD_STATE;
    }

    *isNeedAppendAuthInfo = isNeedAppendParam->boolParam;
    *authResultOut = authResult;
    return HKS_SUCCESS;
}

static int32_t CheckIfNeedAppendUpdateData(const struct HksAppendDataInnerParams *innerParams, bool *outIsNeedAppend,
    int32_t *outAuthResult, struct HksBlob *appendedData, struct HksParam **isAppendDataParam)
{
    bool isNeedAppend = false;
    int32_t authResult = HKS_AUTH_RESULT_NONE;
    int32_t ret = GetSupportAppendAuthInfoParams(innerParams->keyNode, &isNeedAppend, &authResult);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get append auth support params failed");
        return ret;
    }

    *outAuthResult = authResult;
    if (isNeedAppend == false) {
        *outIsNeedAppend = false;
        return HKS_SUCCESS;
    }

    struct HksParam *isAlreadyAppendData = NULL;
    ret = CheckParamsAndGetAppendState(innerParams->keyNode, &isAlreadyAppendData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check is append data params failed");
        return ret;
    }

    if (isAlreadyAppendData->boolParam == true) {
        *outIsNeedAppend = false;
        return HKS_SUCCESS;
    }

    if (innerParams->inData == NULL || innerParams->inData->size == 0 || appendedData == NULL) {
        HKS_LOG_E("the in data is invalid");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (UINT32_MAX - innerParams->inData->size < sizeof(struct HksSecureSignAuthInfo)) {
        HKS_LOG_E("inData size is too large");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    *outIsNeedAppend = true;
    *isAppendDataParam = isAlreadyAppendData;
    return HKS_SUCCESS;
}

static int32_t GetSecureSignAuthInfo(const struct HuksKeyNode *keyNode, struct HksSecureSignAuthInfo *secureSignInfo)
{
    struct HksParam *authTokenParam = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_VERIFIED_AUTH_TOKEN, &authTokenParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get verified auth token failed");
        return HKS_ERROR_BAD_STATE;
    }

    if (authTokenParam->blob.size != sizeof(struct HksUserAuthToken)) {
        return HKS_ERROR_BAD_STATE;
    }

    struct HksUserAuthToken *authToken = (struct HksUserAuthToken *)authTokenParam->blob.data;
    uint32_t hksAuthType;
    ret = HksConvertUserIamTypeToHksType(HKS_AUTH_TYPE, authToken->authType, &hksAuthType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("invalid user iam auth type");
        return HKS_ERROR_BAD_STATE;
    }

    secureSignInfo->userAuthType = hksAuthType;
    secureSignInfo->credentialId = authToken->credentialId;
    secureSignInfo->authenticatorId = authToken->enrolledId;
    return HKS_SUCCESS;
}

static int32_t DoAppendPrefixAuthInfoToUpdateInData(const struct HuksKeyNode *keyNode,
    struct HksSecureSignAuthInfo *secureSignInfo, const struct HksBlob *inData, struct HksBlob *outDataBlob)
{
    uint32_t outDataSize = sizeof(uint32_t) + sizeof(struct HksSecureSignAuthInfo) + inData->size;
    uint8_t *outData = (uint8_t *)HksMalloc(outDataSize);
    if (outData == NULL) {
        HKS_LOG_E("malloc outData failed!");
        return HKS_ERROR_MALLOC_FAIL;
    }

    uint32_t version = SECURE_SIGN_VERSION;
    if (memcpy_s(outData, outDataSize, (uint8_t *)&version, sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("memcpy secure sign auth info version to outData failed!");
        HKS_FREE_PTR(outData);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (memcpy_s(outData + sizeof(uint32_t), outDataSize - sizeof(uint32_t), secureSignInfo,
        sizeof(struct HksSecureSignAuthInfo)) != EOK) {
        HKS_LOG_E("memcpy secure sign auth info to outData failed!");
        HKS_FREE_PTR(outData);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (memcpy_s(outData + sizeof(uint32_t) + sizeof(struct HksSecureSignAuthInfo),
        outDataSize - sizeof(uint32_t) - sizeof(struct HksSecureSignAuthInfo), inData->data,
        inData->size) != EOK) {
        HKS_LOG_E("memcpy inData to outData failed!");
        HKS_FREE_PTR(outData);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    struct HksParam *appendDataPrefixParam = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_APPENDED_DATA_PREFIX, &appendDataPrefixParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get append prefix data failed");
        HKS_FREE_PTR(outData);
        return HKS_ERROR_BAD_STATE;
    }

    if (memcpy_s(appendDataPrefixParam->blob.data, appendDataPrefixParam->blob.size, secureSignInfo,
        sizeof(struct HksSecureSignAuthInfo)) != EOK) {
        HKS_LOG_E("get append prefix data failed");
        HKS_FREE_PTR(outData);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    outDataBlob->data = outData;
    outDataBlob->size = outDataSize;
    return HKS_SUCCESS;
}

static int32_t CheckIfNeedAppendFinishData(const struct HksAppendDataInnerParams *innerParams, bool *outIsNeedAppend,
    int32_t *outAuthResult, uint32_t inOutDataOriginSize)
{
    bool isNeedAppend = false;
    int32_t authResult = HKS_AUTH_RESULT_NONE;
    int32_t ret = GetSupportAppendAuthInfoParams(innerParams->keyNode, &isNeedAppend, &authResult);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get append auth support params failed");
        return ret;
    }

    *outAuthResult = authResult;
    if (isNeedAppend == false) {
        *outIsNeedAppend = false;
        return HKS_SUCCESS;
    }

    if (authResult != HKS_AUTH_RESULT_SUCCESS) {
        HKS_LOG_E("key auth failed");
        return HKS_ERROR_KEY_AUTH_FAILED;
    }

    struct HksParam *isAlreadyAppendUpdateData = NULL;
    ret = CheckParamsAndGetAppendState(innerParams->keyNode, &isAlreadyAppendUpdateData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check is already append update data params failed");
        return ret;
    }

    if (isAlreadyAppendUpdateData->boolParam == false) {
        HKS_LOG_E("did not append update data");
        return HKS_ERROR_BAD_STATE;
    }

    if (innerParams->inData == NULL || innerParams->inData->size == 0) {
        HKS_LOG_E("the in data is invalid");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (inOutDataOriginSize < innerParams->inData->size ||
        inOutDataOriginSize - innerParams->inData->size < sizeof(struct HksSecureSignAuthInfo)) {
        HKS_LOG_E("outData origin buffer size is too small to append auth info");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    *outIsNeedAppend = true;
    return HKS_SUCCESS;
}

static int32_t DoAppendPrefixDataToFinishData(const struct HuksKeyNode *keyNode,
    struct HksAppendDataInnerParams *innerParams, struct HksBlob *inOutData, uint32_t inOutDataOriginSize)
{
    struct HksParam *appendDataPrefixParam = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_APPENDED_DATA_PREFIX, &appendDataPrefixParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get append prefix data failed");
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t cacheOutDataSize = sizeof(uint32_t) + sizeof(struct HksSecureSignAuthInfo) + innerParams->inData->size;
    uint8_t *cacheOutData = (uint8_t *)HksMalloc(cacheOutDataSize);
    if (cacheOutData == NULL) {
        HKS_LOG_E("malloc cacheOutData failed!");
        return HKS_ERROR_MALLOC_FAIL;
    }

    const uint32_t version = SECURE_SIGN_VERSION;
    if (memcpy_s(cacheOutData, cacheOutDataSize, &version, sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("memcpy secure sign auth info version to cacheOutData failed!");
        HKS_FREE_PTR(cacheOutData);
        return HKS_ERROR_BAD_STATE;
    }

    if (memcpy_s(cacheOutData + sizeof(uint32_t), cacheOutDataSize - sizeof(uint32_t), appendDataPrefixParam->blob.data,
        appendDataPrefixParam->blob.size) != EOK) {
        HKS_LOG_E("memcpy secure sign auth info to cacheOutData failed!");
        HKS_FREE_PTR(cacheOutData);
        return HKS_ERROR_BAD_STATE;
    }

    if (memcpy_s(cacheOutData + sizeof(uint32_t) + appendDataPrefixParam->blob.size,
        cacheOutDataSize - appendDataPrefixParam->blob.size - sizeof(uint32_t), innerParams->inData->data,
        innerParams->inData->size) != 0) {
        HKS_LOG_E("memcpy outData to cacheOutData failed!");
        HKS_FREE_PTR(cacheOutData);
        return HKS_ERROR_BAD_STATE;
    }

    if (memcpy_s(inOutData->data, inOutDataOriginSize, cacheOutData, cacheOutDataSize) != 0) {
        HKS_LOG_E("memcpy cacheOutData to inOutData failed!");
        HKS_FREE_PTR(cacheOutData);
        return HKS_ERROR_BAD_STATE;
    }
    inOutData->size = cacheOutDataSize;
    HKS_FREE_PTR(cacheOutData);
    return HKS_SUCCESS;
}

int32_t HksCoreSecureAccessInitParams(struct HuksKeyNode *keyNode, const struct HksParamSet *initParamSet,
    struct HksBlob *token)
{
    if (keyNode == NULL || initParamSet == NULL || token == NULL) {
        HKS_LOG_E("the pointer param is invalid");
        return HKS_ERROR_NULL_POINTER;
    }
    struct HksSecureAccessInnerParams innerParams;
    (void)memset_s(&innerParams, sizeof(innerParams), 0, sizeof(innerParams));

    innerParams.initParamSet = initParamSet;
    innerParams.outToken = token;

    int32_t ret = CheckInitParamSetValidityAndGet(keyNode->keyBlobParamSet, &innerParams);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check init params failed");
        return ret;
    }

    struct HksParamSet *authRuntimeParamSet = NULL;
    ret = BuildAuthRuntimeParamSet(&innerParams, innerParams.isSecureSign, &authRuntimeParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("build auth run time params failed");
        return ret;
    }

    keyNode->authRuntimeParamSet = authRuntimeParamSet;
    return HKS_SUCCESS;
}

int32_t HksCoreSecureAccessVerifyParams(struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    if (keyNode == NULL || paramSet == NULL) {
        HKS_LOG_E("the pointer param is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *authResult = NULL;
    bool isNeedSecureAccess = true;
    
    int32_t ret = CheckIfNeedVerifyParams(keyNode, &isNeedSecureAccess, &authResult);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check if need verify params failed!");
        return HKS_ERROR_BAD_STATE;
    }

    if (isNeedSecureAccess == false) {
        return HKS_SUCCESS;
    }

    if (authResult->uint32Param == HKS_AUTH_RESULT_FAILED) {
        HKS_LOG_E("check key auth failed");
        return HKS_ERROR_KEY_AUTH_FAILED;
    }

    struct HksUserAuthToken *authToken = NULL;
    do {
        ret = GetAuthToken(paramSet, &authToken);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get auth token failed!");
            break;
        }

        ret = HksVerifyAuthTokenSign(authToken);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("verify the auth token sign failed!");
            break;
        }

        ret = VerifyChallengeOrTimeStamp(keyNode, authToken);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("verify challenge failed!");
            break;
        }

        ret = VerifyAuthTokenInfo(keyNode, authToken);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("verify auth token info failed!");
            break;
        }
    } while (0);

    return AssignVerifyResultAndFree(ret == HKS_SUCCESS, authResult, keyNode, authToken);
}

int32_t HksCoreAppendAuthInfoBeforeUpdate(struct HuksKeyNode *keyNode, uint32_t pur,
    const struct HksParamSet *inParamSet, const struct HksBlob *inData, struct HksBlob *appendedData)
{
    // current only support append secure sign
    if (pur != HKS_KEY_PURPOSE_SIGN) {
        return HKS_SUCCESS;
    }

    bool isNeedAppend = false;
    int32_t authResult = HKS_AUTH_RESULT_NONE;
    struct HksParam *isAppendedData = NULL;
    struct HksAppendDataInnerParams innerParams = {
        .keyNode = keyNode,
        .inData = inData,
        .inParamSet = inParamSet
    };

    int32_t ret = CheckIfNeedAppendUpdateData(&innerParams, &isNeedAppend, &authResult, appendedData, &isAppendedData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get if need append update data params failed");
        return ret;
    }

    if (isNeedAppend == false) {
        return HKS_SUCCESS;
    }

    if (authResult != HKS_AUTH_RESULT_SUCCESS) {
        HKS_LOG_E("should do user auth success before update");
        return HKS_ERROR_KEY_AUTH_FAILED;
    }

    struct HksSecureSignAuthInfo secureSignInfo;
    ret = GetSecureSignAuthInfo(keyNode, &secureSignInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get secure sign auth info failed");
        return ret;
    }

    struct HksBlob outDataBlob = { 0, NULL };
    ret = DoAppendPrefixAuthInfoToUpdateInData(keyNode, &secureSignInfo, inData, &outDataBlob);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("do append prefix auth info to update in data failed");
        return ret;
    }

    isAppendedData->boolParam = true;
    *appendedData = outDataBlob;
    return HKS_SUCCESS;
}

int32_t HksCoreAppendAuthInfoBeforeFinish(struct HuksKeyNode *keyNode, uint32_t pur,
    const struct HksParamSet *inParamSet, const struct HksBlob *inData, struct HksBlob *appendedData)
{
    return HksCoreAppendAuthInfoBeforeUpdate(keyNode, pur, inParamSet, inData, appendedData);
}

int32_t HksCoreAppendAuthInfoAfterFinish(struct HuksKeyNode *keyNode, uint32_t pur,
    const struct HksParamSet *inParamSet, uint32_t inOutDataOriginSize, struct HksBlob *inOutData)
{
    if (pur != HKS_KEY_PURPOSE_SIGN) {
        return HKS_SUCCESS;
    }

    bool isNeedAppend = false;
    int32_t authResult = HKS_AUTH_RESULT_NONE;
    const struct HksBlob *inDataConst = (const struct HksBlob *)inOutData;
    struct HksAppendDataInnerParams innerParams = {
        .keyNode = keyNode,
        .inData = inDataConst,
        .inParamSet = inParamSet
    };

    int32_t ret = CheckIfNeedAppendFinishData(&innerParams, &isNeedAppend, &authResult, inOutDataOriginSize);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get if need append finish data params failed");
        return ret;
    }

    if (isNeedAppend == false) {
        return HKS_SUCCESS;
    }

    return DoAppendPrefixDataToFinishData(keyNode, &innerParams, inOutData, inOutDataOriginSize);
}
#else
int32_t HksCoreSecureAccessInitParams(struct HuksKeyNode *keyNode, const struct HksParamSet *initParamSet,
    struct HksBlob *token)
{
    (void)keyNode;
    (void)initParamSet;
    (void)token;
    return HKS_SUCCESS;
}

int32_t HksCoreSecureAccessVerifyParams(struct HuksKeyNode *keyNode, const struct HksParamSet *inParamSet)
{
    (void)keyNode;
    (void)inParamSet;
    return HKS_SUCCESS;
}

int32_t HksCoreAppendAuthInfoBeforeUpdate(struct HuksKeyNode *keyNode, uint32_t pur,
    const struct HksParamSet *inParamSet, const struct HksBlob *inData, struct HksBlob *appendedData)
{
    (void)keyNode;
    (void)pur;
    (void)inParamSet;
    (void)inData;
    (void)appendedData;
    return HKS_SUCCESS;
}

int32_t HksCoreAppendAuthInfoBeforeFinish(struct HuksKeyNode *keyNode, uint32_t pur,
    const struct HksParamSet *inParamSet, const struct HksBlob *inData, struct HksBlob *appendedData)
{
    (void)keyNode;
    (void)pur;
    (void)inParamSet;
    (void)inData;
    (void)appendedData;
    return HKS_SUCCESS;
}

int32_t HksCoreAppendAuthInfoAfterFinish(struct HuksKeyNode *keyNode, uint32_t pur,
    const struct HksParamSet *inParamSet, uint32_t inOutDataBufferSize, struct HksBlob *inOutData)
{
    (void)keyNode;
    (void)pur;
    (void)inParamSet;
    (void)inOutDataBufferSize;
    (void)inOutData;
    return HKS_SUCCESS;
}

#endif