/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "native_huks_api.h"
#include "native_huks_param.h"
#include "native_huks_type.h"

using namespace testing::ext;
namespace {
class HksWrapKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksWrapKeyTest::SetUpTestCase(void)
{
}

void HksWrapKeyTest::TearDownTestCase(void)
{
}

void HksWrapKeyTest::SetUp()
{
}

void HksWrapKeyTest::TearDown()
{
}

OH_Huks_Result InitParamSet(struct OH_Huks_ParamSet **paramSet, const struct OH_Huks_Param *params, uint32_t paramCount)
{
    OH_Huks_Result ret = OH_Huks_InitParamSet(paramSet);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_AddParams(*paramSet, params, paramCount);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        OH_Huks_FreeParamSet(paramSet);
        return ret;
    }
    ret = OH_Huks_BuildParamSet(paramSet);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        OH_Huks_FreeParamSet(paramSet);
        return ret;
    }
    return ret;
}

#ifndef HKS_UNTRUSTED_RUNNING_ENV
static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = { 0 }; // this is a test value, for real use the iv should be different every time.

static struct OH_Huks_Param g_genEncDecParams[] = {
    {
        .tag = OH_HUKS_TAG_ALGORITHM,
        .uint32Param = OH_HUKS_ALG_AES
    }, {
        .tag = OH_HUKS_TAG_PURPOSE,
        .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = OH_HUKS_TAG_KEY_SIZE,
        .uint32Param = OH_HUKS_AES_KEY_SIZE_256
    }, {
        .tag = OH_HUKS_TAG_PADDING,
        .uint32Param = OH_HUKS_PADDING_NONE
    }, {
        .tag = OH_HUKS_TAG_BLOCK_MODE,
        .uint32Param = OH_HUKS_MODE_CBC
    }, {
        .tag = OH_HUKS_TAG_IS_ALLOWED_WRAP,
        .boolParam = true
    }
};

static struct OH_Huks_Param g_encryptParams[] = {
    {
        .tag = OH_HUKS_TAG_ALGORITHM,
        .uint32Param = OH_HUKS_ALG_AES
    }, {
        .tag = OH_HUKS_TAG_PURPOSE,
        .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = OH_HUKS_TAG_KEY_SIZE,
        .uint32Param = OH_HUKS_AES_KEY_SIZE_256
    }, {
        .tag = OH_HUKS_TAG_PADDING,
        .uint32Param = OH_HUKS_PADDING_NONE
    }, {
        .tag = OH_HUKS_TAG_BLOCK_MODE,
        .uint32Param = OH_HUKS_MODE_CBC
    }, {
        .tag = OH_HUKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static struct OH_Huks_Param g_decryptParams[] = {
    {
        .tag = OH_HUKS_TAG_ALGORITHM,
        .uint32Param = OH_HUKS_ALG_AES
    }, {
        .tag = OH_HUKS_TAG_PURPOSE,
        .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = OH_HUKS_TAG_KEY_SIZE,
        .uint32Param = OH_HUKS_AES_KEY_SIZE_256
    }, {
        .tag = OH_HUKS_TAG_PADDING,
        .uint32Param = OH_HUKS_PADDING_NONE
    }, {
        .tag = OH_HUKS_TAG_BLOCK_MODE,
        .uint32Param = OH_HUKS_MODE_CBC
    }, {
        .tag = OH_HUKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static const uint32_t AES_COMMON_SIZE = 1024;

OH_Huks_Result HksAesCipherTestEncrypt(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *encryptParamSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleEncrypt, encryptParamSet, inData, cipherText);
    return ret;
}

OH_Huks_Result HksAesCipherTestDecrypt(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *decryptParamSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText, const struct OH_Huks_Blob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleDecrypt = {sizeof(uint64_t), handleD};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleDecrypt, decryptParamSet, cipherText, plainText);
    return ret;
}

static void FreeFourParamset(OH_Huks_ParamSet **paramSet, OH_Huks_ParamSet **paramSet2, OH_Huks_ParamSet **paramSet3,
    OH_Huks_ParamSet **paramSet4)
{
    OH_Huks_FreeParamSet(paramSet);
    OH_Huks_FreeParamSet(paramSet2);
    OH_Huks_FreeParamSet(paramSet3);
    OH_Huks_FreeParamSet(paramSet4);
}

#endif

static struct OH_Huks_Param g_testImportKeyParam[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_AES},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_ECC_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_USER_AUTH_TYPE, .uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN},
    {.tag = OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID},
    {.tag = OH_HUKS_TAG_CHALLENGE_TYPE, .uint32Param = OH_HUKS_CHALLENGE_TYPE_NORMAL},
};

static struct OH_Huks_Param g_genTuiParams[] = {
    {
        .tag = OH_HUKS_TAG_ALGORITHM,
        .uint32Param = OH_HUKS_ALG_AES
    }, {
        .tag = OH_HUKS_TAG_PURPOSE,
        .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = OH_HUKS_TAG_KEY_SIZE,
        .uint32Param = OH_HUKS_AES_KEY_SIZE_256
    }, {
        .tag = OH_HUKS_TAG_PADDING,
        .uint32Param = OH_HUKS_PADDING_NONE
    }, {
        .tag = OH_HUKS_TAG_BLOCK_MODE,
        .uint32Param = OH_HUKS_MODE_CBC
    }, {
        .tag = OH_HUKS_TAG_USER_AUTH_TYPE,
        .uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN
    }, {
        .tag = OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID
    }, {
        .tag = OH_HUKS_TAG_CHALLENGE_TYPE,
        .uint32Param = OH_HUKS_CHALLENGE_TYPE_NORMAL
    }, {
        .tag = OH_HUKS_TAG_IS_ALLOWED_WRAP,
        .boolParam = true
    }
};

static struct OH_Huks_Param g_wrapParams[] = {
    {
        .tag = OH_HUKS_TAG_KEY_WRAP_TYPE,
        .uint32Param = OH_HUKS_KEY_WRAP_TYPE_HUK_BASED
    },
};

static const uint32_t WRAPPED_KEY_SIZE = 2048;

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest001
 * @tc.desc: test OH_Huks_WrapKey: success;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "wrap_key";
    struct OH_Huks_Blob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct OH_Huks_ParamSet *wrapParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&wrapParamSet, g_wrapParams, sizeof(g_wrapParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t WrappedData[WRAPPED_KEY_SIZE] = {0};
        struct OH_Huks_Blob wrappedKey = {WRAPPED_KEY_SIZE, WrappedData};

        /* wrap the key */
        ohResult = OH_Huks_WrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_NOT_SUPPORTED_API) << "OH_Huks_WrapKey fail";

        /* unwrap the key */
        ohResult = OH_Huks_UnwrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_NOT_SUPPORTED_API) << "OH_Huks_UnwrapKey fail";
    } while (0);
    OH_Huks_FreeParamSet(&wrapParamSet);
}

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest002
 * @tc.desc: test TUI PIN generate key: success;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "tui_pin_key";
    struct OH_Huks_Blob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genTuiParams, sizeof(g_genTuiParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_NOT_SUPPORTED_API) << "OH_Huks_GenerateKeyItem fail";
    } while (0);
        
    OH_Huks_FreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest003
 * @tc.desc: test TUI PIN import key: success;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest003, TestSize.Level0)
{
    uint8_t pubKey[32] = {
        0xfb, 0x8b, 0x9f, 0x12, 0xa0, 0x83, 0x19, 0xbe, 0x6a, 0x6f, 0x63, 0x2a, 0x7c, 0x86, 0xba, 0xca,
        0x64, 0x0b, 0x88, 0x96, 0xe2, 0xfa, 0x77, 0xbc, 0x71, 0xe3, 0x0f, 0x0f, 0x9e, 0x3c, 0xe5, 0xf9
    };
    struct OH_Huks_Blob publicKey = {32, pubKey};
    struct OH_Huks_ParamSet *testImportKeyParamSet = nullptr;
    struct OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&testImportKeyParamSet, g_testImportKeyParam,
            sizeof(g_testImportKeyParam) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char newKey[] = "test_import_tui";
        struct OH_Huks_Blob newKeyAlias = {.size = (uint32_t)strlen(newKey), .data = (uint8_t *)newKey};
        ohResult = OH_Huks_ImportKeyItem(&newKeyAlias, testImportKeyParamSet, &publicKey);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_NOT_SUPPORTED_API) << "OH_Huks_ImportKeyItem fail";
    } while (0);

    OH_Huks_FreeParamSet(&testImportKeyParamSet);
}
#else /* not HKS_UNTRUSTED_RUNNING_ENV */

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest001
 * @tc.desc: test OH_Huks_WrapKey: success;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "wrap_key";
    struct OH_Huks_Blob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    struct OH_Huks_ParamSet *wrapParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genEncDecParams, sizeof(g_genEncDecParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        /* 1. generate key */
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpInData[] = "HksWrapKeyTest_1";
        struct OH_Huks_Blob inData = { (uint32_t)strlen(tmpInData), (uint8_t *)tmpInData };
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {AES_COMMON_SIZE, cipher};

        /* 2. encrypt the data */
        ohResult = HksAesCipherTestEncrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksAesCipherTestEncrypt fail";

        ohResult = InitParamSet(&wrapParamSet, g_wrapParams, sizeof(g_wrapParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t WrappedData[WRAPPED_KEY_SIZE] = {0};
        struct OH_Huks_Blob wrappedKey = {WRAPPED_KEY_SIZE, WrappedData};

        /* 3. wrap the key */
        ohResult = OH_Huks_WrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_WrapKey fail";
        /* 4. delete the key */
        (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);

        /* 5. unwrap the key */
        ohResult = OH_Huks_UnwrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_UnwrapKey fail";

        ohResult = InitParamSet(&decryptParamSet, g_decryptParams, sizeof(g_decryptParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob plainText = {AES_COMMON_SIZE, plain};

        /* 6. decrypt the data */
        ohResult = HksAesCipherTestDecrypt(&keyAlias, decryptParamSet, &cipherText, &plainText, &inData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksAesCipherTestDecrypt fail";
    } while (0);
        
    FreeFourParamset(&genParamSet, &encryptParamSet, &decryptParamSet, &wrapParamSet);
}

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest002
 * @tc.desc: test TUI PIN generate key: success;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "tui_pin_key";
    struct OH_Huks_Blob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genTuiParams, sizeof(g_genTuiParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_WrapKey fail";
    } while (0);
        
    OH_Huks_FreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest003
 * @tc.desc: test TUI PIN import key: success;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest003, TestSize.Level0)
{
    uint8_t pubKey[32] = {
        0xfb, 0x8b, 0x9f, 0x12, 0xa0, 0x83, 0x19, 0xbe, 0x6a, 0x6f, 0x63, 0x2a, 0x7c, 0x86, 0xba, 0xca,
        0x64, 0x0b, 0x88, 0x96, 0xe2, 0xfa, 0x77, 0xbc, 0x71, 0xe3, 0x0f, 0x0f, 0x9e, 0x3c, 0xe5, 0xf9
    };
    struct OH_Huks_Blob publicKey = {32, pubKey};
    struct OH_Huks_ParamSet *testImportKeyParamSet = nullptr;
    struct OH_Huks_Result ohResult;

    
    do {
        ohResult = InitParamSet(&testImportKeyParamSet, g_testImportKeyParam,
            sizeof(g_testImportKeyParam) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char newKey[] = "test_import_tui";
        struct OH_Huks_Blob newKeyAlias = {.size = (uint32_t)strlen(newKey), .data = (uint8_t *)newKey};
        ohResult = OH_Huks_ImportKeyItem(&newKeyAlias, testImportKeyParamSet, &publicKey);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_ImportKeyItem fail";
    } while (0);

    OH_Huks_FreeParamSet(&testImportKeyParamSet);
}

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest004
 * @tc.desc: test TUI PIN generate key: success;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest004, TestSize.Level0)
{
    char tmpKeyAlias[] = "tui_pin_key";
    struct OH_Huks_Blob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genTuiParams, sizeof(g_genTuiParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        struct OH_Huks_Param *authTypeParam = nullptr;
        ohResult = OH_Huks_GetParam(genParamSet, OH_HUKS_TAG_USER_AUTH_TYPE, &authTypeParam);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        struct OH_Huks_Param *accessTypeParam = nullptr;
        ohResult = OH_Huks_GetParam(genParamSet, OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE, &accessTypeParam);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID;

        authTypeParam->uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_GenerateKeyItem fail";
    } while (0);
        
    OH_Huks_FreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest005
 * @tc.desc: test TUI PIN generate key: fail with pin;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest005, TestSize.Level0)
{
    char tmpKeyAlias[] = "tui_pin_key";
    struct OH_Huks_Blob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genTuiParams, sizeof(g_genTuiParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        struct OH_Huks_Param *authTypeParam = nullptr;
        ohResult = OH_Huks_GetParam(genParamSet, OH_HUKS_TAG_USER_AUTH_TYPE, &authTypeParam);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        struct OH_Huks_Param *accessTypeParam = nullptr;
        ohResult = OH_Huks_GetParam(genParamSet, OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE, &accessTypeParam);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID;

        authTypeParam->uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_PIN;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_PIN;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT | OH_HUKS_USER_AUTH_TYPE_PIN;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT |
            OH_HUKS_USER_AUTH_TYPE_PIN;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";
    } while (0);
        
    OH_Huks_FreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksWrapKeyTest.HksWrapKeyTest006
 * @tc.desc: test TUI PIN generate key: fail with clear password;
 * @tc.type: FUNC
 */
HWTEST_F(HksWrapKeyTest, HksWrapKeyTest006, TestSize.Level0)
{
    char tmpKeyAlias[] = "tui_pin_key";
    struct OH_Huks_Blob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genTuiParams, sizeof(g_genTuiParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        struct OH_Huks_Param *authTypeParam = nullptr;
        ohResult = OH_Huks_GetParam(genParamSet, OH_HUKS_TAG_USER_AUTH_TYPE, &authTypeParam);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        struct OH_Huks_Param *accessTypeParam = nullptr;
        ohResult = OH_Huks_GetParam(genParamSet, OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE, &accessTypeParam);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        authTypeParam->uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE;

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_WrapKey fail";

        authTypeParam->uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT;

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_WrapKey fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT;

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT) << "OH_Huks_WrapKey fail";
    } while (0);
        
    OH_Huks_FreeParamSet(&genParamSet);
}
#endif

}