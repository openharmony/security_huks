/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hks_access_control_test_common.h"
#include "hks_util.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksAccessControlPartTest {
static const uint8_t NONCE[HKS_AE_NONCE_LEN + 1] = "hahahahahaha";
static const uint8_t AAD[HKS_AE_AAD_LEN + 1] = "OH_authToken";
static uint8_t TAG[HKS_AE_TAG_LEN] = { 0 };

static struct HksParam g_authtokenImportHmacParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_authtokenHmacParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_authtokenImportAesParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }
};

static struct HksParam g_authtokenAesParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = HKS_AE_AAD_LEN,
            .data = (uint8_t *)AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = HKS_AE_NONCE_LEN,
            .data = (uint8_t *)NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = HKS_AE_TAG_LEN,
            .data = (uint8_t *)TAG
        }
    }
};

int32_t AuthTokenImportKey(const struct HksBlob *keyAlias, const struct HksParam *params, uint32_t paramCount,
    bool isMac)
{
    struct HksParamSet *importParamSet = nullptr;
    int32_t ret = InitParamSet(&importParamSet, params, paramCount);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    const char *atKey = isMac ? HKS_DEFAULT_USER_AT_MAC_KEY : HKS_DEFAULT_USER_AT_CIPHER_KEY;
    struct HksBlob key = {
        SHA256_KEY_LEN,
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(atKey))
    };

    ret = HksImportKey(keyAlias, importParamSet, &key);
    HksFreeParamSet(&importParamSet);
    return ret;
}

static int32_t AssignAuthToken(struct HksBlob *cipherTextOutData, struct HksBlob *challenge,
    const IDMParams &testIDMParams, HksUserAuthToken *authTokenHal)
{
    uint64_t curTime = 0;
    int32_t ret = HksElapsedRealTime(&curTime);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get elapsed real time failed!");
        return ret;
    }

    (void)memcpy_s(&authTokenHal->ciphertextData, AUTH_TOKEN_CIPHERTEXT_LEN,
        cipherTextOutData->data, cipherTextOutData->size);
    (void)memcpy_s(authTokenHal->tag, HKS_AE_TAG_LEN,
        cipherTextOutData->data + cipherTextOutData->size, HKS_AE_TAG_LEN);
    (void)memcpy_s(authTokenHal->iv, HKS_AE_NONCE_LEN, NONCE, HKS_AE_NONCE_LEN);
    authTokenHal->plaintextData.time = curTime + testIDMParams.time;
    authTokenHal->plaintextData.authType = testIDMParams.authType;
    authTokenHal->plaintextData.authMode = testIDMParams.authMode;
    authTokenHal->plaintextData.tokenType = testIDMParams.tokenType;

    if (memcpy_s(authTokenHal->plaintextData.challenge, TOKEN_CHALLENGE_LEN, challenge->data, challenge->size) != EOK) {
        HKS_LOG_E("memcpy_s failed");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

int32_t AuthTokenEncrypt(const IDMParams &testIDMParams, struct HksBlob *authChallenge, HksUserAuthToken *authTokenHal)
{
    int32_t ret = HKS_FAILURE;
    uint8_t alias[] = "AuthToken_Encrypt_Decrypt_KeyAlias";
    const struct HksBlob keyAlias = { sizeof(alias), alias };
    AuthTokenImportKey(&keyAlias, g_authtokenImportAesParams, sizeof(g_authtokenImportAesParams) / sizeof(HksParam),
        false);
    HksCiphertextData *cipherTextData = nullptr;
    struct HksParamSet *cipherParamSet = nullptr;
    do {
        cipherTextData = static_cast<struct HksCiphertextData *>(HksMalloc(AUTH_TOKEN_CIPHERTEXT_LEN));
        if (cipherTextData == nullptr) {
            break;
        }

        cipherTextData->secureUid = testIDMParams.secureUid;
        cipherTextData->enrolledId = testIDMParams.enrolledId;

        uint8_t authTokenCipher[AUTH_TOKEN_CIPHERTEXT_LEN] = {0};
        if (memcpy_s(authTokenCipher, AUTH_TOKEN_CIPHERTEXT_LEN, cipherTextData, AUTH_TOKEN_CIPHERTEXT_LEN) != EOK) {
            break;
        }
        struct HksBlob inData = { AUTH_TOKEN_CIPHERTEXT_LEN, authTokenCipher };

        ret = InitParamSet(&cipherParamSet, g_authtokenAesParams, sizeof(g_authtokenAesParams) / sizeof(HksParam));
        if (ret != HKS_SUCCESS) {
            break;
        }

        /// Init
        uint8_t handle[32] = {0};
        struct HksBlob handleEncrypt = { 32, handle };
        ret = HksInit(&keyAlias, cipherParamSet, &handleEncrypt, nullptr);
        if (ret != HKS_SUCCESS) {
            break;
        }
        // Update & Finish
        uint8_t cipher[HKS_AES_COMMON_SIZE] = {0};
        struct HksBlob cipherTextOutData = { HKS_AES_COMMON_SIZE, cipher };
        ret = TestUpdateLoopFinish(&handleEncrypt, cipherParamSet, &inData, &cipherTextOutData);
        if (ret != HKS_SUCCESS) {
            break;
        }

        cipherTextOutData.size -= HKS_AE_TAG_LEN;
        int ret = AssignAuthToken(&cipherTextOutData, authChallenge, testIDMParams, authTokenHal);
        if (ret != HKS_SUCCESS) {
            break;
        }

        HKS_FREE(cipherTextData);
        HksFreeParamSet(&cipherParamSet);
        return ret;
    } while (0);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HKS_FREE(cipherTextData);
    HksFreeParamSet(&cipherParamSet);
    return ret;
}

int32_t AuthTokenSign(const IDMParams &testIDMParams,  HksUserAuthToken *authTokenHal,
    std::vector<uint8_t>& token)
{
    int32_t ret = HKS_FAILURE;
    uint8_t alias[] = "AuthToken_Sign_Verify_KeyAlias";
    const struct HksBlob keyAlias = { sizeof(alias), alias };
    AuthTokenImportKey(&keyAlias, g_authtokenImportHmacParams, sizeof(g_authtokenImportHmacParams) / sizeof(HksParam),
        true);
    struct HksParamSet *hmacParamSet = nullptr;
    do {
        uint8_t authTokenData[AUTH_TOKEN_DATA_LEN] = {0};
        if (memcpy_s(authTokenData, AUTH_TOKEN_DATA_LEN, authTokenHal, AUTH_TOKEN_DATA_LEN) != EOK) {
            break;
        }
        struct HksBlob inData = { AUTH_TOKEN_DATA_LEN, authTokenData };

        ret = InitParamSet(&hmacParamSet, g_authtokenHmacParams, sizeof(g_authtokenHmacParams) / sizeof(HksParam));
        if (ret != HKS_SUCCESS) {
            break;
        }
        /// Init
        uint8_t handle[32] = {0};
        struct HksBlob handleHMAC = { 32, handle };

        ret = HksInit(&keyAlias, hmacParamSet, &handleHMAC, nullptr);
        if (ret != HKS_SUCCESS) {
            break;
        }
        // Update & Finish
        struct HksBlob outData = { SHA256_SIGN_LEN, authTokenHal->sign };

        ret = TestUpdateFinish(&handleHMAC, hmacParamSet, HKS_KEY_PURPOSE_MAC, &inData, &outData);
        if (ret != HKS_SUCCESS) {
            break;
        }

        for (uint32_t i = 0; i < AUTH_TOKEN_DATA_LEN; i++) {
            token.push_back(authTokenData[i]);
        }
        for (uint32_t i = 0; i < SHA256_SIGN_LEN; i++) {
            token.push_back(authTokenHal->sign[i]);
        }
        HksFreeParamSet(&hmacParamSet);
        return ret;
    } while (0);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&hmacParamSet);
    return ret;
}

static int32_t AppendToNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSetTest = nullptr;

    do {
        ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = HksFreshParamSet(const_cast<struct HksParamSet *>(paramSet), false);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append fresh paramset failed");
            break;
        }

        ret = HksInitParamSet(&newParamSetTest);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append init operation param set failed");
            break;
        }

        ret = HksAddParams(newParamSetTest, paramSet->params, paramSet->paramsCnt);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("append params failed");
            break;
        }
        HKS_LOG_E("AppendToNewParamSet end ");

        *outParamSet = newParamSetTest;
        return ret;
    } while (0);

    HksFreeParamSet(&newParamSetTest);
    return ret;
}

int32_t HksBuildAuthtoken(struct HksParamSet **initParamSet, struct HksBlob *authChallenge,
    const IDMParams &testIDMParams)
{
    struct HksParam tmpParams;
    std::vector<uint8_t> token;
    HksUserAuthToken *authTokenHal = nullptr;

    authTokenHal = static_cast<struct HksUserAuthToken *>(HksMalloc(AUTH_TOKEN_LEN));
    if (authTokenHal == nullptr) {
        return HKS_ERROR_NULL_POINTER;
    }

    int ret = AuthTokenEncrypt(testIDMParams, authChallenge, authTokenHal);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(authTokenHal);
        return ret;
    }

    ret = AuthTokenSign(testIDMParams, authTokenHal, token);
    HKS_FREE(authTokenHal);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint8_t authToken[AUTH_TOKEN_LEN] = {0};
    for (uint32_t i = 0; i < AUTH_TOKEN_LEN; i++) {
        authToken[i] = token[i];
    }
    tmpParams.tag = HKS_TAG_AUTH_TOKEN;
    tmpParams.blob.data = authToken;
    tmpParams.blob.size = AUTH_TOKEN_LEN;

    struct HksParamSet *newParamSet = nullptr;

    ret = AppendToNewParamSet(*initParamSet, &newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("AppendToNewParamSet failed!\n");
        return ret;
    }

    ret = HksAddParams(newParamSet, &tmpParams, 1);
    if (ret != 0) {
        HKS_LOG_I("HksAddParam failed!\n");
        return ret;
    }
    ret = HksBuildParamSet(&newParamSet);
    if (ret != 0) {
        HKS_LOG_I("HksBuildParamSet failed!\n");
        return ret;
    }

    *initParamSet = newParamSet;
    return ret;
}

int32_t HksBuildAuthTokenSecure(struct HksParamSet *paramSet,
    struct HksTestGenAuthTokenParams *genAuthTokenParams, struct HksParamSet **outParamSet)
{
    if (paramSet == nullptr || genAuthTokenParams == nullptr || outParamSet == nullptr) {
        return HKS_ERROR_NULL_POINTER;
    }
    struct HksParam tmpParams;
    std::vector<uint8_t> token;
    struct IDMParams testIDMParams = {genAuthTokenParams->secureUid,
        genAuthTokenParams->enrolledId, genAuthTokenParams->time, genAuthTokenParams->authType};

    HksUserAuthToken *authTokenHal = nullptr;
    authTokenHal = static_cast<struct HksUserAuthToken *>(HksMalloc(AUTH_TOKEN_LEN));
    if (authTokenHal == nullptr) {
        return HKS_ERROR_NULL_POINTER;
    }

    int ret = AuthTokenEncrypt(testIDMParams, genAuthTokenParams->authChallenge, authTokenHal);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(authTokenHal);
        return ret;
    }

    ret = AuthTokenSign(testIDMParams, authTokenHal, token);
    HKS_FREE(authTokenHal);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    uint8_t authToken[AUTH_TOKEN_LEN + 1] = {0};
    for (uint32_t i = 0; i < AUTH_TOKEN_LEN; i++) {
        authToken[i] = token[i];
    }
    tmpParams.tag = HKS_TAG_AUTH_TOKEN;
    tmpParams.blob.data = authToken;
    tmpParams.blob.size = AUTH_TOKEN_LEN;
    HKS_LOG_I("AuthToekn Data: %" LOG_PUBLIC "s", authToken);

    struct HksParamSet *newParamSet = nullptr;

    ret = AppendToNewParamSet(paramSet, &newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("AppendToNewParamSet failed!\n");
        return ret;
    }

    ret = HksAddParams(newParamSet, &tmpParams, 1);
    if (ret != 0) {
        HKS_LOG_I("HksAddParam failed!\n");
        return ret;
    }
    ret = HksBuildParamSet(&newParamSet);
    if (ret != 0) {
        HKS_LOG_I("HksBuildParamSet failed!\n");
        return ret;
    }

    *outParamSet = newParamSet;
    return ret;
}

int32_t AddAuthtokenUpdateFinish(struct HksBlob *handle,
    struct HksParamSet *initParamSet, uint32_t posNum)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(initParamSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksGetParam failed!\n");
        return ret;
    }

    struct HksBlob inData;
    uint8_t outDataS[DATA_COMMON_SIZE] = {0};
    struct HksBlob outDataSign = { DATA_COMMON_SIZE, outDataS };
    (void)posNum;
    if (algParam->uint32Param == HKS_ALG_RSA) {
        inData = { g_inData_32.length(),
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData_32.c_str())) };
        ret = TestUpdateFinish(handle, initParamSet, HKS_KEY_PURPOSE_ENCRYPT, &inData, &outDataSign);
    } else {
        inData = { g_inData.length(),
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str())) };
        ret = TestUpdateLoopFinish(handle, initParamSet, &inData, &outDataSign);
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("TestUpdateLoopFinish failed, ret : %" LOG_PUBLIC "d", ret);
    }
    return ret;
}

int32_t CheckAccessCipherTest(const TestAccessCaseParams &testCaseParams,
    const IDMParams &testIDMParams)
{
    struct HksParamSet *genParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, testCaseParams.genParams.data(), testCaseParams.genParams.size());
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("InitParamSet(gen) failed, ret : %" LOG_PUBLIC "d", ret);
        return ret;
    }
    uint8_t alias[] = "testCheckAuth";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        HKS_LOG_I("HksGenerateKey failed, ret : %" LOG_PUBLIC "d", ret);
        return ret;
    }

    struct HksParamSet *initParamSet = nullptr;
    ret = InitParamSet(&initParamSet, testCaseParams.initParams.data(), testCaseParams.initParams.size());
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("InitParamSet(init) failed, ret : %" LOG_PUBLIC "d", ret);
        return ret;
    }
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };

    uint8_t tmpHandle[32] = {0};
    struct HksBlob handle = { 32, tmpHandle };
    ret = HksInit(&keyAlias, initParamSet, &handle, &challengeBlob);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksBuildAuthtoken(&initParamSet, &challengeBlob, testIDMParams);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksBuildAuthtoken failed, ret : %" LOG_PUBLIC "d", ret);
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }
    ret = AddAuthtokenUpdateFinish(&handle, initParamSet, 0);

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&initParamSet);
    (void)HksDeleteKey(&keyAlias, nullptr);

    return (ret == testCaseParams.initResult) ? HKS_SUCCESS : HKS_FAILURE;
}

int32_t CheckAccessHmacTest(const TestAccessCaseParams &testCaseParams,
    const IDMParams &testIDMParams)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, testCaseParams.genParams.data(), testCaseParams.genParams.size());
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    uint8_t alias[] = "testCheckAuth";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        HKS_LOG_I("HksGenerateKey failed, ret : %" LOG_PUBLIC "d", ret);
        return ret;
    }

    struct HksParamSet *initParamSet = nullptr;
    ret = InitParamSet(&initParamSet, testCaseParams.initParams.data(), testCaseParams.initParams.size());
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };

    uint8_t handle[32] = {0};
    struct HksBlob handleHMAC = { 32, handle };
    ret = HksInit(&keyAlias, initParamSet, &handleHMAC, &challengeBlob);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    ret = HksBuildAuthtoken(&initParamSet, &challengeBlob, testIDMParams);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    struct HksBlob inData = { g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str())) };
    uint8_t out[HMAC_COMMON_SIZE] = {0};
    struct HksBlob outData = { HMAC_COMMON_SIZE, out };
    ret = TestUpdateFinish(&handleHMAC, initParamSet, HKS_KEY_PURPOSE_MAC, &inData, &outData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("TestUpdateFinish failed, ret : %" LOG_PUBLIC "d", ret);
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    return (ret == testCaseParams.initResult) ? HKS_SUCCESS : HKS_FAILURE;
}

static int32_t UpdateAndFinishForAgreeTest(const struct HksBlob *handle, struct HksParamSet *initParamSet,
    struct HksParamSet *finishParamSet, struct HksBlob *publicKey)
{
    struct HksBlob inData = { g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str())) };

    uint8_t outDataU[ECDH_COMMON_SIZE] = {0};
    struct HksBlob outDataUpdate = { ECDH_COMMON_SIZE, outDataU };
    int32_t ret = HksUpdate(handle, initParamSet, publicKey, &outDataUpdate);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint8_t outDataF[ECDH_COMMON_SIZE] = {0};
    struct HksBlob outDataFinish = { ECDH_COMMON_SIZE, outDataF };
    ret = HksFinish(handle, finishParamSet, (const struct HksBlob *)&inData, &outDataFinish);
    return ret;
}

int32_t CheckAccessAgreeTest(const TestAccessCaseParams &testCaseParams, struct HksParamSet *finishParamSet,
    const IDMParams &testIDMParams)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, testCaseParams.genParams.data(), testCaseParams.genParams.size());
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    uint8_t alias[] = "testCheckAuth";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return ret;
    }

    uint8_t pubKey[4096] = {0};
    struct HksBlob publicKey = { 4096, pubKey };
    ret = HksExportPublicKey(&keyAlias, genParamSet, &publicKey);
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    struct HksParamSet *initParamSet = nullptr;
    ret = InitParamSet(&initParamSet, testCaseParams.initParams.data(), testCaseParams.initParams.size());
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };

    uint8_t handleU[32] = {0};
    struct HksBlob handle = { 32, handleU };
    ret = HksInit(&keyAlias, initParamSet, &handle, &challengeBlob);
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    ret = HksBuildAuthtoken(&initParamSet, &challengeBlob, testIDMParams);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    ret = UpdateAndFinishForAgreeTest((const struct HksBlob *)&handle, initParamSet, finishParamSet, &publicKey);
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    return (ret == testCaseParams.initResult) ? HKS_SUCCESS : HKS_FAILURE;
}

static int32_t UpdateAndFinishForDeriveTest(const struct HksBlob *handleDerive, struct HksParamSet *initParamSet,
    struct HksParamSet *finishParamSet)
{
    struct HksBlob inData = { g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str())) };

    uint8_t tmpOut[DERIVE_COMMON_SIZE] = {0};
    struct HksBlob outData = { DERIVE_COMMON_SIZE, tmpOut };
    int32_t ret = HksUpdate(handleDerive, initParamSet, &inData, &outData);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint8_t outDataD[DERIVE_COMMON_SIZE] = {0};
    struct HksBlob outDataDerive = { DERIVE_COMMON_SIZE, outDataD };
    ret = HksFinish(handleDerive, finishParamSet, &inData, &outDataDerive);
    return ret;
}

int32_t CheckAccessDeriveTest(const TestAccessCaseParams &testCaseParams, struct HksParamSet *finishParamSet,
    const IDMParams &testIDMParams)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, testCaseParams.genParams.data(), testCaseParams.genParams.size());
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    uint8_t alias[] = "testCheckAuth";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return ret;
    }

    ret = InitParamSet(&initParamSet, testCaseParams.initParams.data(), testCaseParams.initParams.size());
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };
    // Init
    uint8_t handleD[32] = {0};
    struct HksBlob handleDerive = { 32, handleD };
    ret = HksInit(&keyAlias, initParamSet, &handleDerive, &challengeBlob);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    ret = HksBuildAuthtoken(&initParamSet, &challengeBlob, testIDMParams);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    ret = UpdateAndFinishForDeriveTest((const struct HksBlob *)&handleDerive, initParamSet, finishParamSet);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(&keyAlias, genParamSet);
        return ret;
    }

    HksDeleteKey(&keyAlias, genParamSet);
    return (ret == testCaseParams.initResult) ? HKS_SUCCESS : HKS_FAILURE;
}

int32_t ConstructRsaKeyPair(const struct HksBlob *nDataBlob, const struct HksBlob *dDataBlob,
    const struct HksBlob *eDataBlob, uint32_t keySize, struct HksBlob *outKey)
{
    struct HksKeyMaterialRsa material;
    material.keyAlg = HKS_ALG_RSA;
    material.keySize = keySize;
    material.nSize = nDataBlob->size;
    material.eSize = eDataBlob->size;
    material.dSize = dDataBlob->size;

    uint32_t size = sizeof(material) + material.nSize + material.eSize + material.dSize;
    uint8_t *data = static_cast<uint8_t *>(HksMalloc(size));
    if (data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    // copy struct material
    if (memcpy_s(data, size, &material, sizeof(material)) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t offset = sizeof(material);
    // copy nData
    if (memcpy_s(data + offset, size - offset, nDataBlob->data, nDataBlob->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }
    offset += material.nSize;

    // copy eData
    if (memcpy_s(data + offset, size - offset, eDataBlob->data, eDataBlob->size) != EOK) {
            HKS_FREE(data);
            return HKS_ERROR_BAD_STATE;
    }
    offset += material.eSize;

    // copy dData
    if (memcpy_s(data + offset, size - offset, dDataBlob->data, dDataBlob->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }

    outKey->data = data;
    outKey->size = size;
    return HKS_SUCCESS;
}

int32_t ConstructEd25519KeyPair(uint32_t keySize, uint32_t alg, struct HksBlob *ed25519PubData,
    struct HksBlob *ed25519PrivData, struct HksBlob *outKey)
{
    struct HksKeyMaterial25519 material;
    material.keyAlg = (enum HksKeyAlg)alg;
    material.keySize = keySize;
    material.pubKeySize = ed25519PubData->size;
    material.priKeySize = ed25519PrivData->size;
    material.reserved = 0;

    uint32_t size = sizeof(material) + material.pubKeySize + material.priKeySize;
    uint8_t *data = static_cast<uint8_t *>(HksMalloc(size));
    if (data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    // copy struct material
    if (memcpy_s(data, size, &material, sizeof(material)) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t offset = sizeof(material);
    // copy publicData
    if (memcpy_s(data + offset, size - offset, ed25519PubData, ed25519PubData->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }
    offset += material.pubKeySize;

    // copy privateData
    if (memcpy_s(data + offset, size - offset, ed25519PrivData, ed25519PrivData->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }

    outKey->data = data;
    outKey->size = size;
    return HKS_SUCCESS;
}

int32_t ConstructDsaKeyPair(uint32_t keySize, const struct TestDsaKeyParams *params, struct HksBlob *outKey)
{
    struct HksKeyMaterialDsa material;
    material.keyAlg = HKS_ALG_DSA;
    material.keySize = keySize;
    material.xSize = params->xData->size;
    material.ySize = params->yData->size;
    material.pSize = params->pData->size;
    material.qSize = params->qData->size;
    material.gSize = params->gData->size;

    uint32_t size = sizeof(material) + material.xSize + material.ySize +
        material.pSize + material.qSize + material.gSize;
    uint8_t *data = static_cast<uint8_t *>(HksMalloc(size));
    if (data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    // copy struct material
    if (memcpy_s(data, size, &material, sizeof(material)) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t offset = sizeof(material);
    // copy xData
    if (memcpy_s(data + offset, size - offset, params->xData->data, params->xData->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }

    offset += material.xSize;
    // copy yData
    if (memcpy_s(data + offset, size - offset, params->yData->data, params->yData->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }
    offset += material.ySize;

    // copy pData
    if (memcpy_s(data + offset, size - offset, params->pData->data, params->pData->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }
    offset += material.pSize;

    // copy qData
    if (memcpy_s(data + offset, size - offset, params->qData->data, params->qData->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }
    offset += material.qSize;

    // copy gData
    if (memcpy_s(data + offset, size - offset, params->gData->data, params->gData->size) != EOK) {
        HKS_FREE(data);
        return HKS_ERROR_BAD_STATE;
    }

    outKey->data = data;
    outKey->size = size;
    return HKS_SUCCESS;
}

int32_t GenParamSetAuthTest(struct HksParamSet **paramOutSet, const struct HksParamSet *genParamSet)
{
    struct HksParam localSecureKey = {
        .tag = HKS_TAG_SYMMETRIC_KEY_DATA,
        .blob = { .size = KEY_PARAMSET_SIZE, .data = static_cast<uint8_t *>(HksMalloc(KEY_PARAMSET_SIZE)) }
    };
    if (localSecureKey.blob.data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    int32_t ret = HksInitParamSet(paramOutSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed.";

    struct HksParam *algParam = nullptr;
    ret = HksGetParam(genParamSet, HKS_TAG_ALGORITHM, &algParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam alg failed.";

    if (algParam->uint32Param == HKS_ALG_AES || algParam->uint32Param == HKS_ALG_SM4) {
        localSecureKey.tag = HKS_TAG_SYMMETRIC_KEY_DATA;
    } else if (algParam->uint32Param == HKS_ALG_RSA || algParam->uint32Param == HKS_ALG_SM2 ||
        algParam->uint32Param == HKS_ALG_ECC || algParam->uint32Param == HKS_ALG_DSA ||
        algParam->uint32Param == HKS_ALG_X25519 || algParam->uint32Param == HKS_ALG_ED25519 ||
        algParam->uint32Param == HKS_ALG_DH) {
        localSecureKey.tag = HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA;
    } else if (algParam->uint32Param == HKS_ALG_HMAC || algParam->uint32Param == HKS_ALG_SM3 ||
        algParam->uint32Param == HKS_ALG_HKDF || algParam->uint32Param == HKS_ALG_PBKDF2) {
        localSecureKey.tag = HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA;
    } else {
        localSecureKey.tag = HKS_TAG_SYMMETRIC_KEY_DATA;
    }

    ret = HksAddParams(*paramOutSet, &localSecureKey, 1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams failed.";
    ret = HksBuildParamSet(paramOutSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams failed.";

    return ret;
}
}
