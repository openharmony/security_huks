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

#include <cstdint>
#include <cstring>
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
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED) << "OH_Huks_GenerateKeyItem fail";
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
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED) << "OH_Huks_ImportKeyItem fail";
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
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_PIN;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT | OH_HUKS_USER_AUTH_TYPE_PIN;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT |
            OH_HUKS_USER_AUTH_TYPE_PIN;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_GenerateKeyItem fail";
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
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_WrapKey fail";

        authTypeParam->uint32Param = OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT;

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_WrapKey fail";

        authTypeParam->uint32Param =
            OH_HUKS_USER_AUTH_TYPE_TUI_PIN | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_FINGERPRINT;

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_ALWAYS_VALID;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_WrapKey fail";

        accessTypeParam->uint32Param = OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL;
        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT) << "OH_Huks_WrapKey fail";
    } while (0);
        
    OH_Huks_FreeParamSet(&genParamSet);
}
#endif


void ConcatBlob(OH_Huks_Blob *data1, OH_Huks_Blob *data2, OH_Huks_Blob *outData)
{
    printf("start concat blob \n");
    if (outData == NULL || data1 == NULL || data2 == NULL) {
        printf("quit concat blob ~\n");
        return;
    }

    uint32_t offset = 0;
    memcpy_s(outData->data, sizeof(uint32_t), &data1->size, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy_s(outData->data + offset, data1->size, data1->data, data1->size);
    offset += data1->size;

    memcpy_s(outData->data + offset, sizeof(uint32_t), &data2->size, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy_s(outData->data + offset, data2->size, data2->data, data2->size);
    outData->size = data1->size + data2->size + 2*sizeof(uint32_t);
    printf("===data1:%d, data2:%d, data3:%d!!\n",data1->size, data2->size, outData->size);
    return;
}

static struct OH_Huks_Param  gEnvelopIniSm2[] = {
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT | OH_HUKS_KEY_PURPOSE_ENCRYPT},
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    };

static struct OH_Huks_Param  gEnvelopEnSm2[] = {
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
};

char testAlias[] = "testSm2";
OH_Huks_Blob gSm2KeyAlias = {(uint32_t)strlen(testAlias), (uint8_t *)testAlias};

uint8_t sm4UintData[] = {
    0xb9, 0xef, 0x35, 0x49, 0xb7, 0x00, 0x91, 0x58, 0x0c, 0x6f, 0x43, 0x28, 0xf8, 0x95, 0x1c, 0x02,
};
OH_Huks_Blob gSm4Data = {sizeof(sm4UintData)/sizeof(sm4UintData[0]), sm4UintData};

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey001, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *rsaParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t rsaUintPubKey[] = {
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
            0x00, 0xa2, 0xd2, 0x3c, 0xe9, 0x87, 0x8b, 0x48, 0x34, 0xdd, 0x41, 0xe0, 0x65, 0x39, 0xcc, 0xea,
            0x25, 0x25, 0xa6, 0x9e, 0x9f, 0x20, 0xc6, 0x13, 0x9f, 0xb2, 0xa7, 0xf3, 0x77, 0x69, 0xfd, 0xa9,
            0xbd, 0xe8, 0x2c, 0xf3, 0x87, 0x3a, 0xc0, 0x2a, 0x01, 0x1f, 0x8d, 0x0f, 0x59, 0x28, 0x34, 0xfb,
            0xe3, 0x8d, 0x9b, 0xa1, 0xe0, 0xe4, 0x60, 0x7d, 0x20, 0x19, 0x49, 0x6f, 0x13, 0x5e, 0xae, 0x3e,
            0x4d, 0x6c, 0x31, 0x6c, 0x0b, 0x90, 0xf8, 0xd2, 0xf3, 0x45, 0x4f, 0x3b, 0x9f, 0x8e, 0x3b, 0x77,
            0x20, 0x9e, 0x54, 0xec, 0x7b, 0x54, 0x15, 0xf0, 0x09, 0x8f, 0x5a, 0xf9, 0x87, 0x9a, 0x27, 0x23,
            0x99, 0x64, 0x4d, 0x8c, 0x80, 0x5c, 0x2e, 0xee, 0xc3, 0x57, 0x6e, 0x3d, 0x91, 0xfb, 0x77, 0x67,
            0x3b, 0x8a, 0xed, 0x01, 0xb5, 0x91, 0x33, 0xa1, 0xaa, 0xb2, 0x0d, 0x49, 0x25, 0x7c, 0x4d, 0x42,
            0xde, 0xfb, 0xcd, 0xd6, 0x48, 0xb8, 0xce, 0xe7, 0x22, 0x71, 0x43, 0x54, 0x2c, 0x6b, 0xbb, 0xbf,
            0x63, 0xdc, 0xea, 0x6f, 0x77, 0x81, 0xe9, 0x07, 0xe0, 0x18, 0xb3, 0x1e, 0x78, 0x4b, 0xbc, 0x17,
            0x77, 0x62, 0x25, 0xd9, 0xe7, 0x23, 0x6c, 0x80, 0xad, 0xdc, 0x51, 0x18, 0x1b, 0x33, 0x56, 0x59,
            0x15, 0x43, 0xcf, 0x51, 0xd9, 0xbc, 0x6d, 0xf7, 0x68, 0xd1, 0xe8, 0xbf, 0x41, 0x36, 0xd1, 0x30,
            0x92, 0x7b, 0x48, 0xd1, 0x00, 0xe2, 0x9d, 0x8e, 0x94, 0xee, 0x20, 0x2a, 0x18, 0xb1, 0x04, 0xba,
            0xe7, 0x19, 0xdc, 0x69, 0x36, 0xf7, 0x34, 0x4b, 0x16, 0x10, 0x10, 0x2a, 0x46, 0x1c, 0x4e, 0x6e,
            0x62, 0xe1, 0x25, 0x79, 0xd5, 0x5c, 0xf3, 0x9a, 0xeb, 0x1f, 0x3d, 0x82, 0xa3, 0xaa, 0x79, 0xde,
            0x23, 0xa1, 0x2b, 0x50, 0x6d, 0x68, 0x3e, 0x77, 0x33, 0xe0, 0xc9, 0x18, 0xbc, 0x65, 0x58, 0x63,
            0x7b, 0x02, 0x03, 0x01, 0x00, 0x01,
        };
        OH_Huks_Blob rsaPubKey = {sizeof(rsaUintPubKey), rsaUintPubKey};

        OH_Huks_Param rsaParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_RSA},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_RSA_KEY_SIZE_2048},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
            {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
            {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
            {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = rsaPubKey},
        };

        ohResult = InitParamSet(&rsaParamSet, rsaParams,
            sizeof(rsaParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t rsaPrivate[] = {
            0x4a, 0xce, 0x89, 0xa6, 0xda, 0x85, 0x6d, 0x56, 0xb3, 0xab, 0xc9, 0x70, 0x5e, 0x3f, 0xb6, 0x0e,
            0x07, 0xdf, 0xdf, 0x9c, 0xb3, 0x05, 0xd4, 0x8d, 0xc0, 0xac, 0x9b, 0x13, 0x3d, 0x1b, 0xdb, 0xa0,
            0x46, 0x1a, 0xc8, 0x82, 0x80, 0xe0, 0x2a, 0x28, 0x34, 0xa6, 0x4a, 0x97, 0x91, 0x58, 0xc8, 0x8c,
            0x0f, 0xa2, 0xeb, 0xe1, 0xf8, 0x37, 0x54, 0x99, 0x7e, 0xa1, 0xce, 0x1e, 0xf3, 0x8b, 0x8c, 0x8d,
            0xec, 0x58, 0xb7, 0x32, 0x29, 0x36, 0x34, 0x46, 0x92, 0x67, 0x09, 0xb3, 0xb4, 0xb3, 0x74, 0x3a,
            0x77, 0x99, 0xd7, 0x4b, 0x1f, 0xf6, 0xa6, 0xb0, 0x99, 0x3d, 0x3e, 0x92, 0xba, 0xcf, 0x83, 0xd0,
            0x1e, 0x18, 0x68, 0x1a, 0xb5, 0xfe, 0x18, 0x6d, 0x9d, 0xc2, 0x39, 0x48, 0x2e, 0x52, 0xfc, 0x33,
            0x16, 0xb0, 0x58, 0xd5, 0xdf, 0x84, 0xbe, 0xfe, 0xe1, 0xfa, 0xa9, 0x65, 0x34, 0xb8, 0x97, 0xa3,
            0x9a, 0x45, 0x8a, 0x40, 0x4b, 0x09, 0xdf, 0x1c, 0x48, 0x57, 0x3f, 0xb2, 0x1f, 0xf3, 0x21, 0x7d,
            0xa8, 0xa5, 0xed, 0xe1, 0x61, 0x2f, 0xe0, 0xda, 0xae, 0x15, 0x22, 0x18, 0xf6, 0x84, 0x7d, 0x39,
            0xae, 0x35, 0x49, 0xec, 0xd8, 0x66, 0xff, 0x65, 0x7d, 0xd9, 0x74, 0x19, 0xad, 0x26, 0x64, 0xc0,
            0x2d, 0x93, 0xf5, 0x83, 0x7d, 0x8d, 0x98, 0x35, 0x2e, 0x67, 0xf9, 0xc0, 0xb1, 0xd7, 0x2b, 0xb5,
            0x49, 0x98, 0x3a, 0x31, 0xa0, 0x66, 0x71, 0x6e, 0x09, 0x70, 0xef, 0x56, 0x14, 0x9e, 0xb8, 0xd2,
            0x17, 0x99, 0x44, 0x69, 0xcd, 0x3d, 0xcb, 0x3c, 0xfe, 0xbe, 0x72, 0xc0, 0x43, 0x29, 0x86, 0x70,
            0x9d, 0xa3, 0xc0, 0x68, 0xf6, 0x7e, 0x48, 0x2c, 0x4e, 0x48, 0xe0, 0xf6, 0xa9, 0xcb, 0x28, 0x63,
            0xe8, 0x33, 0xfc, 0xb4, 0x1a, 0x06, 0xf4, 0x13, 0x20, 0xfd, 0x90, 0x90, 0x1c, 0x25, 0xd7, 0xf8,
        };
        OH_Huks_Blob rsaEnPrivateData = {sizeof(rsaPrivate), rsaPrivate};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &rsaEnPrivateData, &importKeyBlob);
        
        char importAlias[] = "importRsa";
        OH_Huks_Blob rsaKeyAlias = {(uint32_t)strlen(importAlias), (uint8_t *)importAlias};
        ohResult = OH_Huks_ImportWrappedKeyItem(&rsaKeyAlias, &gSm2KeyAlias, rsaParamSet, &importKeyBlob);

        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);

    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&rsaParamSet);
}

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey002, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *aesParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    char aesAlias[] = "testAes";
    OH_Huks_Blob aesAliasBlob = {(uint32_t)sizeof(aesAlias), (uint8_t *)aesAlias};
    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);

        OH_Huks_Param importAesParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_AES},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
            {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
            {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_AES_KEY_SIZE_128}
        };

        ohResult = InitParamSet(&aesParamSet, importAesParams,
            sizeof(importAesParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importAesData[] = {
            0xa5, 0xa4, 0xef, 0x4b, 0x87, 0x69, 0xf1, 0xd0, 0x7c, 0xd0, 0x55, 0x9a, 0xe0, 0xb8, 0x8c, 0x36,
        };
        OH_Huks_Blob aesBlob = {sizeof(importAesData), importAesData};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &aesBlob, &importKeyBlob);

        ohResult = OH_Huks_ImportWrappedKeyItem(&aesAliasBlob, &gSm2KeyAlias, aesParamSet, &importKeyBlob);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);
    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&aesParamSet);
}

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey003, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *dh2EnKeyParmSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);

        uint8_t dhPubKey[] = {
            0x30, 0x82, 0x02, 0x25, 0x30, 0x82, 0x01, 0x17, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x03, 0x01, 0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf2, 0x2d, 0xce, 0x12,
            0x41, 0xb3, 0x56, 0x96, 0x7e, 0xdd, 0xbd, 0x5d, 0x3d, 0x2c, 0x53, 0x2f, 0xc8, 0xc8, 0xe3, 0x8e,
            0x15, 0xe7, 0x37, 0x79, 0x75, 0xe7, 0x1e, 0x1d, 0x47, 0x06, 0xc5, 0xea, 0x5d, 0x0c, 0x6a, 0xaf,
            0xf7, 0xc9, 0x07, 0xbb, 0x9d, 0xd5, 0x48, 0x2d, 0x53, 0x98, 0x34, 0x0d, 0x5e, 0xed, 0xd1, 0x1a,
            0xd2, 0xf2, 0x4f, 0x40, 0x21, 0x0d, 0xd3, 0x42, 0x92, 0xe7, 0x64, 0x41, 0x7c, 0xdb, 0xef, 0x0b,
            0x69, 0xa4, 0xe2, 0x9e, 0xbe, 0xca, 0xf4, 0xd2, 0xcd, 0x02, 0xb4, 0xc9, 0xe6, 0x79, 0xf3, 0xbd,
            0xc8, 0xb4, 0x25, 0x58, 0x48, 0x5f, 0xc9, 0xc1, 0xda, 0x8d, 0x60, 0x3b, 0xae, 0x41, 0xd6, 0x08,
            0xf3, 0x2d, 0x9f, 0x8a, 0xb2, 0x71, 0xee, 0x80, 0x6d, 0x3e, 0x71, 0xeb, 0x5c, 0xd6, 0x59, 0x80,
            0xae, 0xaf, 0xf2, 0x0d, 0xb4, 0xf2, 0x6b, 0x0a, 0x0e, 0xba, 0x73, 0xa9, 0x89, 0x27, 0xfc, 0x84,
            0x44, 0xa1, 0x65, 0xe0, 0x99, 0x57, 0xb5, 0x64, 0x70, 0x92, 0x77, 0x52, 0x7e, 0xb4, 0x8e, 0x3c,
            0x25, 0xb0, 0x3f, 0xa9, 0x5b, 0x5b, 0x87, 0xb3, 0x91, 0xae, 0xac, 0x0f, 0x54, 0x95, 0x57, 0x40,
            0xdb, 0x7d, 0x4f, 0xd1, 0x30, 0x30, 0x0f, 0xc8, 0x4a, 0xcd, 0x4f, 0xa4, 0x55, 0xc4, 0x71, 0x4f,
            0x0c, 0x7c, 0x96, 0x01, 0x41, 0x79, 0x0d, 0x8f, 0xf3, 0x1e, 0xf6, 0x95, 0x5e, 0xe7, 0x0f, 0xfc,
            0x45, 0xe8, 0x8d, 0x52, 0x50, 0x72, 0xdd, 0x9e, 0xe3, 0xe3, 0xf4, 0x9e, 0x7f, 0xa0, 0x31, 0x56,
            0x5c, 0x32, 0xd7, 0xfa, 0xf6, 0xf6, 0x6a, 0x34, 0x23, 0xbf, 0xcd, 0x2a, 0x10, 0x1d, 0x7d, 0xaa,
            0x7c, 0x61, 0xc4, 0x26, 0xb5, 0x94, 0xf0, 0xf4, 0x58, 0xe1, 0xf3, 0x31, 0x3c, 0x10, 0x87, 0x0b,
            0x7a, 0x7e, 0x19, 0xa3, 0x7c, 0x23, 0x65, 0xc6, 0x94, 0x07, 0x76, 0xf7, 0x02, 0x01, 0x02, 0x03,
            0x82, 0x01, 0x06, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xeb, 0x11, 0x9d, 0xa5, 0x86, 0x10, 0x81,
            0xa9, 0x27, 0x70, 0xd4, 0x42, 0xa7, 0x60, 0xac, 0x36, 0x75, 0xa2, 0xae, 0xe1, 0x9a, 0x0e, 0x56,
            0xbf, 0xe7, 0xec, 0x4a, 0xf5, 0x25, 0x2a, 0x6a, 0xb8, 0xf1, 0xb3, 0x7a, 0x3b, 0xb9, 0xb4, 0xba,
            0x49, 0xf6, 0xce, 0x28, 0x40, 0xb6, 0x52, 0x39, 0x57, 0x1b, 0xb2, 0x72, 0x7c, 0x2d, 0xc7, 0x71,
            0xd0, 0xe6, 0x01, 0x32, 0xf8, 0xeb, 0xe5, 0x7e, 0x3d, 0xba, 0x0e, 0x40, 0x2a, 0xcc, 0xbd, 0x12,
            0x3c, 0x66, 0xbc, 0x88, 0x92, 0x27, 0x51, 0xd6, 0xc4, 0xc9, 0x29, 0x61, 0x62, 0x77, 0x1f, 0x98,
            0xd3, 0x5a, 0x85, 0xe0, 0xcf, 0xe2, 0x11, 0xf3, 0x3c, 0x1e, 0x1c, 0x26, 0x37, 0x0a, 0x4b, 0x45,
            0xcf, 0x84, 0x24, 0x0e, 0x83, 0x99, 0x72, 0x20, 0x84, 0xb1, 0x90, 0x56, 0x9e, 0x09, 0xd4, 0x2c,
            0x2d, 0x58, 0x9b, 0x93, 0xd7, 0x88, 0x87, 0xaa, 0xd6, 0x42, 0x0c, 0xd5, 0xe0, 0x7a, 0x00, 0x75,
            0x19, 0x54, 0x8c, 0xac, 0x0e, 0xfe, 0x3d, 0x3b, 0x23, 0xf7, 0x6e, 0x7d, 0x3e, 0xd3, 0x55, 0x81,
            0xfd, 0x3a, 0xb1, 0x95, 0x69, 0xed, 0x41, 0x7d, 0x15, 0x79, 0x28, 0xc6, 0xd4, 0x23, 0x8d, 0xeb,
            0x40, 0xc0, 0xc7, 0xaa, 0xac, 0xf2, 0xc1, 0x04, 0xbc, 0xfb, 0x66, 0x59, 0x2e, 0x11, 0xd1, 0xc0,
            0xb0, 0x48, 0xd3, 0x99, 0x9b, 0x70, 0x0d, 0xe9, 0x61, 0xd0, 0x7d, 0x4e, 0x0e, 0x42, 0x9b, 0xe9,
            0xb8, 0x7c, 0xc5, 0xcd, 0x26, 0xf4, 0x45, 0xe4, 0x8b, 0x3b, 0x01, 0x7a, 0xe2, 0x71, 0x74, 0xa4,
            0x52, 0x5d, 0xab, 0x7b, 0x86, 0xdc, 0x4e, 0x19, 0xcb, 0x59, 0x87, 0xed, 0xdf, 0x2f, 0xc9, 0xb0,
            0xbe, 0xed, 0x31, 0x2d, 0x25, 0xea, 0xdc, 0x7f, 0x00, 0x0a, 0x32, 0x5d, 0xf5, 0xec, 0x2c, 0xfb,
            0xb7, 0x64, 0x54, 0x1a, 0x6d, 0x53, 0xb1, 0xd1, 0xd4,
        };
        OH_Huks_Blob pubKeyBlob = {sizeof(dhPubKey), dhPubKey};
        OH_Huks_Param dhParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_DH},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_AGREE},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_DH_KEY_SIZE_2048},
            {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = pubKeyBlob},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        };

        ohResult = InitParamSet(&dh2EnKeyParmSet, dhParams,
            sizeof(dhParams) / sizeof(OH_Huks_Param));

        uint8_t enPriKeyData[] = {
            0x0a, 0xf4, 0xa7, 0x58, 0x3a, 0x55, 0xe4, 0xde, 0x15, 0x76, 0x1e, 0x99, 0x2c, 0x9d, 0x36, 0xbf,
            0x09, 0x4c, 0xd8, 0xa5, 0xa1, 0x61, 0xf7, 0x0b, 0x66, 0xa7, 0xe0, 0xf3, 0xef, 0xe3, 0x8e, 0x1c,
            0x28, 0x98, 0x90, 0x40, 0x8c, 0x58, 0xd2, 0xd2, 0x79, 0xbf, 0xba, 0xaf, 0xf6, 0x25, 0xea, 0xd2,
            0x06, 0xc8, 0x00, 0x7f, 0x65, 0x0a, 0x89, 0x22, 0xb3, 0x25, 0x5d, 0x26, 0x71, 0xd3, 0x2b, 0xd4,
            0x8d, 0x63, 0xb6, 0x30, 0xfd, 0x29, 0x71, 0x0f, 0x91, 0x23, 0x56, 0xf5, 0x37, 0x62, 0x73, 0x9c,
            0xc0, 0x88, 0xc2, 0x58, 0x99, 0x6e, 0xe2, 0x0b, 0x90, 0xed, 0x12, 0xeb, 0xc6, 0x69, 0x30, 0x7b,
            0x4a, 0xd6, 0xde, 0x03, 0x45, 0x53, 0xea, 0x4f, 0x99, 0xa2, 0x2a, 0xb3, 0xba, 0x89, 0x4a, 0xe1,
            0x47, 0xf5, 0x72, 0x79, 0x02, 0x11, 0xed, 0xa0, 0xcd, 0x06, 0x80, 0x78, 0x21, 0xfa, 0x3c, 0xa7,
            0xda, 0xf7, 0x0f, 0xfc, 0x1a, 0xb2, 0xab, 0xf6, 0xfd, 0xcf, 0xd6, 0x3a, 0x07, 0xb7, 0x00, 0x93,
            0x4a, 0xf5, 0x89, 0xab, 0xeb, 0x19, 0xf5, 0x64, 0xc7, 0x0b, 0x83, 0x06, 0x48, 0xc4, 0x56, 0x42,
            0x9e, 0x56, 0xff, 0x88, 0xf8, 0x44, 0x5c, 0xb6, 0x91, 0xe7, 0x65, 0xd0, 0xad, 0xf4, 0x3e, 0xb8,
            0x7a, 0x32, 0xf4, 0x26, 0x53, 0xfb, 0x1c, 0x98, 0xa7, 0xe0, 0x1d, 0x36, 0x81, 0x21, 0x42, 0xb5,
            0xdf, 0x53, 0xc3, 0xfc, 0x3b, 0x0f, 0xba, 0x3f, 0x16, 0xe0, 0x50, 0x2f, 0xaf, 0x5e, 0x86, 0xcb,
            0xe9, 0x6d, 0xe7, 0x9e, 0x58, 0x62, 0x05, 0x42, 0x4a, 0x14, 0x1b, 0xc9, 0x83, 0x7a, 0xbd, 0x04,
            0xf0, 0x9b, 0x14, 0x46, 0xad, 0xaf, 0xd1, 0x5b, 0x3f, 0xa7, 0x3c, 0x64, 0xff, 0x3e, 0xb7, 0xd9,
            0xb6, 0xa0, 0x66, 0xab, 0xbd, 0xe1, 0xc2, 0x4a, 0x36, 0x00, 0xca, 0x7f, 0x74, 0x34, 0x68, 0xaf,
        };
        OH_Huks_Blob enPriKeyBlob = {sizeof(enPriKeyData), enPriKeyData};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &enPriKeyBlob, &importKeyBlob);

        char dhAlias[] = "testDh";
        OH_Huks_Blob dhBlob = {(uint32_t)strlen(dhAlias), (uint8_t *)dhAlias};

        ohResult = OH_Huks_ImportWrappedKeyItem(&dhBlob, &gSm2KeyAlias, dh2EnKeyParmSet, &importKeyBlob);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);
    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&dh2EnKeyParmSet);
}

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey004, TestSize.Level0)
{
struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *dsaParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    char aesAlias[] = "testAes";
    OH_Huks_Blob aesAliasBlob = {(uint32_t)sizeof(aesAlias), (uint8_t *)aesAlias};
    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);

        OH_Huks_Param importDsaParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_DSA},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY},
            {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SHA256},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        };
        
        ohResult = InitParamSet(&dsaParamSet, importDsaParams,
            sizeof(importDsaParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importAesData[] = {
            0xa5, 0xa4, 0xef, 0x4b, 0x87, 0x69, 0xf1, 0xd0, 0x7c, 0xd0, 0x55, 0x9a, 0xe0, 0xb8, 0x8c, 0x36,
        };
        OH_Huks_Blob aesBlob = {sizeof(importAesData), importAesData};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &aesBlob, &importKeyBlob);
        ohResult = OH_Huks_ImportWrappedKeyItem(&aesAliasBlob, &gSm2KeyAlias, dsaParamSet, &importKeyBlob);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT);
    } while (0);
    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&dsaParamSet);
}

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey005, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *importParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    char sm4Alias[] = "testSm4";
    OH_Huks_Blob sm4AliasBlob = {(uint32_t)sizeof(sm4Alias), (uint8_t *)sm4Alias};
    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);

        OH_Huks_Param importAesParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
            {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB},
            {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
            {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE}
        };

        ohResult = InitParamSet(&importParamSet, importAesParams,
            sizeof(importAesParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importSm4Data[] = {
            0xd0, 0xf2, 0x71, 0x46, 0x8d, 0x2f, 0xe6, 0x67, 0x7a, 0xd1, 0x7d, 0xe9, 0xd9, 0xff, 0x04, 0x7e,
        };
        OH_Huks_Blob sm4Blob = {sizeof(importSm4Data), importSm4Data};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &sm4Blob, &importKeyBlob);

        ohResult = OH_Huks_ImportWrappedKeyItem(&sm4AliasBlob, &gSm2KeyAlias, importParamSet, &importKeyBlob);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);
    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}

//ECC
HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey006, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *importParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t eccUintPubKey[] = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x4b, 0x17, 0x35, 0x9e, 0x66,
            0x04, 0xd4, 0x61, 0xee, 0x17, 0x89, 0xc4, 0x91, 0xab, 0x63, 0x04, 0x4d, 0x10, 0x36, 0x34, 0x74,
            0xe8, 0x4b, 0x57, 0xc5, 0x16, 0x08, 0x4c, 0x6f, 0xc5, 0x72, 0x4f, 0xbf, 0x00, 0xd2, 0xfb, 0x14,
            0x78, 0x9d, 0xc2, 0x36, 0x2a, 0xd2, 0x41, 0x90, 0xaa, 0x1c, 0x9c, 0xf5, 0xd8, 0x5d, 0x8b, 0x6a,
            0x86, 0x8d, 0xb3, 0x06, 0x5e, 0x36, 0x6f, 0x7b, 0x6c, 0x13, 0x25,
        };
        OH_Huks_Blob eccPubKey = {sizeof(eccUintPubKey), eccUintPubKey};

        OH_Huks_Param rsaParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_ECC},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_ECC_KEY_SIZE_256},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_VERIFY | OH_HUKS_KEY_PURPOSE_SIGN},
            {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
            {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
            {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = eccPubKey},
        };

        ohResult = InitParamSet(&importParamSet, rsaParams,
            sizeof(rsaParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t eccPrivate[] = {
            0x6c, 0x0b, 0xd1, 0x03, 0xd2, 0x4e, 0x2d, 0xea, 0xc1, 0x9d, 0x50, 0xcd, 0xa0, 0x16, 0x69, 0xc2,
            0xa8, 0xfd, 0x41, 0xa0, 0x54, 0x86, 0x9a, 0x38, 0x86, 0x44, 0x39, 0x79, 0x31, 0xba, 0xd5, 0xf1,
        };
        OH_Huks_Blob eccEnPrivateData = {sizeof(eccPrivate), eccPrivate};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &eccEnPrivateData, &importKeyBlob);
        
        char importAlias[] = "importEcc";
        OH_Huks_Blob rsaKeyAlias = {(uint32_t)strlen(importAlias), (uint8_t *)importAlias};
        ohResult = OH_Huks_ImportWrappedKeyItem(&rsaKeyAlias, &gSm2KeyAlias, importParamSet, &importKeyBlob);

        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);

    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}

//SM2
HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey007, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *importParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t sm2UintPubKey[] = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x38, 0x9e, 0xd3, 0x95, 0xb7,
            0x98, 0xdf, 0x60, 0xbf, 0x5a, 0x14, 0x71, 0x45, 0x2b, 0xd6, 0xb7, 0x35, 0x1c, 0xd1, 0x38, 0x7a,
            0x11, 0x98, 0x8a, 0x28, 0xd1, 0x37, 0x9b, 0x75, 0x12, 0xd8, 0x06, 0x42, 0xc2, 0xbf, 0x3b, 0x52,
            0x18, 0x6e, 0x9c, 0x41, 0x2d, 0x77, 0xc0, 0xa1, 0x6d, 0x9e, 0x08, 0x9d, 0x4e, 0x16, 0x62, 0x57,
            0x97, 0x56, 0x10, 0xd4, 0x7b, 0x3a, 0x5f, 0x96, 0xf6, 0x8c, 0x19,
        };
        OH_Huks_Blob sm2PubKey = {sizeof(sm2UintPubKey), sm2UintPubKey};

        OH_Huks_Param sm2Params[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
            {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
            {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = sm2PubKey},
            {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3}
        };

        ohResult = InitParamSet(&importParamSet, sm2Params,
            sizeof(sm2Params) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t sm2Private[] = {
            0xa7, 0xde, 0x26, 0xf9, 0xe8, 0xad, 0xe8, 0x9b, 0x5a, 0x37, 0xca, 0x5b, 0x70, 0x18, 0x18, 0xe0,
            0x68, 0x04, 0xa9, 0x8b, 0x94, 0x9c, 0xcd, 0x86, 0x90, 0x22, 0x9f, 0x17, 0xfd, 0xc4, 0x9c, 0x51,
        };
        OH_Huks_Blob sm2EnPrivateData = {sizeof(sm2Private), sm2Private};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &sm2EnPrivateData, &importKeyBlob);
        
        char importAlias[] = "importsm2";
        OH_Huks_Blob sm2KeyAlias = {(uint32_t)strlen(importAlias), (uint8_t *)importAlias};
        ohResult = OH_Huks_ImportWrappedKeyItem(&sm2KeyAlias, &gSm2KeyAlias, importParamSet, &importKeyBlob);

        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);

    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey008, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *importParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importUintPubKey[] = {
            0x30, 0x82, 0x02, 0x25, 0x30, 0x82, 0x01, 0x17, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x03, 0x01, 0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf2, 0x2d, 0xce, 0x12,
            0x41, 0xb3, 0x56, 0x96, 0x7e, 0xdd, 0xbd, 0x5d, 0x3d, 0x2c, 0x53, 0x2f, 0xc8, 0xc8, 0xe3, 0x8e,
            0x15, 0xe7, 0x37, 0x79, 0x75, 0xe7, 0x1e, 0x1d, 0x47, 0x06, 0xc5, 0xea, 0x5d, 0x0c, 0x6a, 0xaf,
            0xf7, 0xc9, 0x07, 0xbb, 0x9d, 0xd5, 0x48, 0x2d, 0x53, 0x98, 0x34, 0x0d, 0x5e, 0xed, 0xd1, 0x1a,
            0xd2, 0xf2, 0x4f, 0x40, 0x21, 0x0d, 0xd3, 0x42, 0x92, 0xe7, 0x64, 0x41, 0x7c, 0xdb, 0xef, 0x0b,
            0x69, 0xa4, 0xe2, 0x9e, 0xbe, 0xca, 0xf4, 0xd2, 0xcd, 0x02, 0xb4, 0xc9, 0xe6, 0x79, 0xf3, 0xbd,
            0xc8, 0xb4, 0x25, 0x58, 0x48, 0x5f, 0xc9, 0xc1, 0xda, 0x8d, 0x60, 0x3b, 0xae, 0x41, 0xd6, 0x08,
            0xf3, 0x2d, 0x9f, 0x8a, 0xb2, 0x71, 0xee, 0x80, 0x6d, 0x3e, 0x71, 0xeb, 0x5c, 0xd6, 0x59, 0x80,
            0xae, 0xaf, 0xf2, 0x0d, 0xb4, 0xf2, 0x6b, 0x0a, 0x0e, 0xba, 0x73, 0xa9, 0x89, 0x27, 0xfc, 0x84,
            0x44, 0xa1, 0x65, 0xe0, 0x99, 0x57, 0xb5, 0x64, 0x70, 0x92, 0x77, 0x52, 0x7e, 0xb4, 0x8e, 0x3c,
            0x25, 0xb0, 0x3f, 0xa9, 0x5b, 0x5b, 0x87, 0xb3, 0x91, 0xae, 0xac, 0x0f, 0x54, 0x95, 0x57, 0x40,
            0xdb, 0x7d, 0x4f, 0xd1, 0x30, 0x30, 0x0f, 0xc8, 0x4a, 0xcd, 0x4f, 0xa4, 0x55, 0xc4, 0x71, 0x4f,
            0x0c, 0x7c, 0x96, 0x01, 0x41, 0x79, 0x0d, 0x8f, 0xf3, 0x1e, 0xf6, 0x95, 0x5e, 0xe7, 0x0f, 0xfc,
            0x45, 0xe8, 0x8d, 0x52, 0x50, 0x72, 0xdd, 0x9e, 0xe3, 0xe3, 0xf4, 0x9e, 0x7f, 0xa0, 0x31, 0x56,
            0x5c, 0x32, 0xd7, 0xfa, 0xf6, 0xf6, 0x6a, 0x34, 0x23, 0xbf, 0xcd, 0x2a, 0x10, 0x1d, 0x7d, 0xaa,
            0x7c, 0x61, 0xc4, 0x26, 0xb5, 0x94, 0xf0, 0xf4, 0x58, 0xe1, 0xf3, 0x31, 0x3c, 0x10, 0x87, 0x0b,
            0x7a, 0x7e, 0x19, 0xa3, 0x7c, 0x23, 0x65, 0xc6, 0x94, 0x07, 0x76, 0xf7, 0x02, 0x01, 0x02, 0x03,
            0x82, 0x01, 0x06, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xeb, 0x11, 0x9d, 0xa5, 0x86, 0x10, 0x81,
            0xa9, 0x27, 0x70, 0xd4, 0x42, 0xa7, 0x60, 0xac, 0x36, 0x75, 0xa2, 0xae, 0xe1, 0x9a, 0x0e, 0x56,
            0xbf, 0xe7, 0xec, 0x4a, 0xf5, 0x25, 0x2a, 0x6a, 0xb8, 0xf1, 0xb3, 0x7a, 0x3b, 0xb9, 0xb4, 0xba,
            0x49, 0xf6, 0xce, 0x28, 0x40, 0xb6, 0x52, 0x39, 0x57, 0x1b, 0xb2, 0x72, 0x7c, 0x2d, 0xc7, 0x71,
            0xd0, 0xe6, 0x01, 0x32, 0xf8, 0xeb, 0xe5, 0x7e, 0x3d, 0xba, 0x0e, 0x40, 0x2a, 0xcc, 0xbd, 0x12,
            0x3c, 0x66, 0xbc, 0x88, 0x92, 0x27, 0x51, 0xd6, 0xc4, 0xc9, 0x29, 0x61, 0x62, 0x77, 0x1f, 0x98,
            0xd3, 0x5a, 0x85, 0xe0, 0xcf, 0xe2, 0x11, 0xf3, 0x3c, 0x1e, 0x1c, 0x26, 0x37, 0x0a, 0x4b, 0x45,
            0xcf, 0x84, 0x24, 0x0e, 0x83, 0x99, 0x72, 0x20, 0x84, 0xb1, 0x90, 0x56, 0x9e, 0x09, 0xd4, 0x2c,
            0x2d, 0x58, 0x9b, 0x93, 0xd7, 0x88, 0x87, 0xaa, 0xd6, 0x42, 0x0c, 0xd5, 0xe0, 0x7a, 0x00, 0x75,
            0x19, 0x54, 0x8c, 0xac, 0x0e, 0xfe, 0x3d, 0x3b, 0x23, 0xf7, 0x6e, 0x7d, 0x3e, 0xd3, 0x55, 0x81,
            0xfd, 0x3a, 0xb1, 0x95, 0x69, 0xed, 0x41, 0x7d, 0x15, 0x79, 0x28, 0xc6, 0xd4, 0x23, 0x8d, 0xeb,
            0x40, 0xc0, 0xc7, 0xaa, 0xac, 0xf2, 0xc1, 0x04, 0xbc, 0xfb, 0x66, 0x59, 0x2e, 0x11, 0xd1, 0xc0,
            0xb0, 0x48, 0xd3, 0x99, 0x9b, 0x70, 0x0d, 0xe9, 0x61, 0xd0, 0x7d, 0x4e, 0x0e, 0x42, 0x9b, 0xe9,
            0xb8, 0x7c, 0xc5, 0xcd, 0x26, 0xf4, 0x45, 0xe4, 0x8b, 0x3b, 0x01, 0x7a, 0xe2, 0x71, 0x74, 0xa4,
            0x52, 0x5d, 0xab, 0x7b, 0x86, 0xdc, 0x4e, 0x19, 0xcb, 0x59, 0x87, 0xed, 0xdf, 0x2f, 0xc9, 0xb0,
            0xbe, 0xed, 0x31, 0x2d, 0x25, 0xea, 0xdc, 0x7f, 0x00, 0x0a, 0x32, 0x5d, 0xf5, 0xec, 0x2c, 0xfb,
            0xb7, 0x64, 0x54, 0x1a, 0x6d, 0x53, 0xb1, 0xd1, 0xd4,
        };
        OH_Huks_Blob importPubKey = {sizeof(importUintPubKey), importUintPubKey};

        OH_Huks_Param importParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_DH},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_DH_KEY_SIZE_2048},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_AGREE},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = importPubKey},
        };

        ohResult = InitParamSet(&importParamSet, importParams,
            sizeof(importParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importPrivate[] = {
            0x0a, 0xf4, 0xa7, 0x58, 0x3a, 0x55, 0xe4, 0xde, 0x15, 0x76, 0x1e, 0x99, 0x2c, 0x9d, 0x36, 0xbf,
            0x09, 0x4c, 0xd8, 0xa5, 0xa1, 0x61, 0xf7, 0x0b, 0x66, 0xa7, 0xe0, 0xf3, 0xef, 0xe3, 0x8e, 0x1c,
            0x28, 0x98, 0x90, 0x40, 0x8c, 0x58, 0xd2, 0xd2, 0x79, 0xbf, 0xba, 0xaf, 0xf6, 0x25, 0xea, 0xd2,
            0x06, 0xc8, 0x00, 0x7f, 0x65, 0x0a, 0x89, 0x22, 0xb3, 0x25, 0x5d, 0x26, 0x71, 0xd3, 0x2b, 0xd4,
            0x8d, 0x63, 0xb6, 0x30, 0xfd, 0x29, 0x71, 0x0f, 0x91, 0x23, 0x56, 0xf5, 0x37, 0x62, 0x73, 0x9c,
            0xc0, 0x88, 0xc2, 0x58, 0x99, 0x6e, 0xe2, 0x0b, 0x90, 0xed, 0x12, 0xeb, 0xc6, 0x69, 0x30, 0x7b,
            0x4a, 0xd6, 0xde, 0x03, 0x45, 0x53, 0xea, 0x4f, 0x99, 0xa2, 0x2a, 0xb3, 0xba, 0x89, 0x4a, 0xe1,
            0x47, 0xf5, 0x72, 0x79, 0x02, 0x11, 0xed, 0xa0, 0xcd, 0x06, 0x80, 0x78, 0x21, 0xfa, 0x3c, 0xa7,
            0xda, 0xf7, 0x0f, 0xfc, 0x1a, 0xb2, 0xab, 0xf6, 0xfd, 0xcf, 0xd6, 0x3a, 0x07, 0xb7, 0x00, 0x93,
            0x4a, 0xf5, 0x89, 0xab, 0xeb, 0x19, 0xf5, 0x64, 0xc7, 0x0b, 0x83, 0x06, 0x48, 0xc4, 0x56, 0x42,
            0x9e, 0x56, 0xff, 0x88, 0xf8, 0x44, 0x5c, 0xb6, 0x91, 0xe7, 0x65, 0xd0, 0xad, 0xf4, 0x3e, 0xb8,
            0x7a, 0x32, 0xf4, 0x26, 0x53, 0xfb, 0x1c, 0x98, 0xa7, 0xe0, 0x1d, 0x36, 0x81, 0x21, 0x42, 0xb5,
            0xdf, 0x53, 0xc3, 0xfc, 0x3b, 0x0f, 0xba, 0x3f, 0x16, 0xe0, 0x50, 0x2f, 0xaf, 0x5e, 0x86, 0xcb,
            0xe9, 0x6d, 0xe7, 0x9e, 0x58, 0x62, 0x05, 0x42, 0x4a, 0x14, 0x1b, 0xc9, 0x83, 0x7a, 0xbd, 0x04,
            0xf0, 0x9b, 0x14, 0x46, 0xad, 0xaf, 0xd1, 0x5b, 0x3f, 0xa7, 0x3c, 0x64, 0xff, 0x3e, 0xb7, 0xd9,
            0xb6, 0xa0, 0x66, 0xab, 0xbd, 0xe1, 0xc2, 0x4a, 0x36, 0x00, 0xca, 0x7f, 0x74, 0x34, 0x68, 0xaf,
        };
        OH_Huks_Blob importEnPrivateData = {sizeof(importPrivate), importPrivate};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &importEnPrivateData, &importKeyBlob);
        
        char importAlias[] = "importDh";
        OH_Huks_Blob sm2KeyAlias = {(uint32_t)strlen(importAlias), (uint8_t *)importAlias};
        ohResult = OH_Huks_ImportWrappedKeyItem(&sm2KeyAlias, &gSm2KeyAlias, importParamSet, &importKeyBlob);

        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);

    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey009, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *importParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importUintPubKey[] = {
            0x9d, 0xd2, 0x99, 0xde, 0xa3, 0xe8, 0x6f, 0x38, 0xf1, 0x40, 0x24, 0xc5, 0x59, 0x25, 0x17, 0x2c,
            0x6e, 0xc5, 0xa5, 0x7b, 0x66, 0x04, 0x99, 0x0f, 0x65, 0x09, 0xef, 0x9b, 0x4f, 0xce, 0xd6, 0xf3,
        };
        OH_Huks_Blob importPubKey = {sizeof(importUintPubKey), importUintPubKey};

        OH_Huks_Param importParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_ED25519},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_CURVE25519_KEY_SIZE_256},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
            {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = importPubKey},
            {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE}
        };

        ohResult = InitParamSet(&importParamSet, importParams,
            sizeof(importParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importPrivate[] = {
            0x0d, 0x9c, 0xe7, 0x07, 0xeb, 0x29, 0x84, 0xae, 0x84, 0xeb, 0xe3, 0x88, 0xbf, 0xd1, 0x9a, 0xec,
            0xf5, 0x55, 0x0f, 0x09, 0xdf, 0x28, 0xe5, 0xa4, 0xfa, 0x79, 0xfa, 0xb7, 0x31, 0x60, 0x0b, 0x59,
        };
        OH_Huks_Blob importEnPrivateData = {sizeof(importPrivate), importPrivate};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &importEnPrivateData, &importKeyBlob);
        
        char importAlias[] = "importEd";
        OH_Huks_Blob sm2KeyAlias = {(uint32_t)strlen(importAlias), (uint8_t *)importAlias};
        ohResult = OH_Huks_ImportWrappedKeyItem(&sm2KeyAlias, &gSm2KeyAlias, importParamSet, &importKeyBlob);

        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);

    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}

HWTEST_F(HksWrapKeyTest, HksEnvelopImporKey010, TestSize.Level0)
{
    struct OH_Huks_ParamSet *sm2GenerateKeyParamSet = NULL;
    struct OH_Huks_Result ohResult;
    struct OH_Huks_ParamSet *sm2KeyData = NULL;
    struct OH_Huks_ParamSet *importParamSet = NULL;
    struct OH_Huks_ParamSet *sm2EnKeyParmSet = NULL;

    do {
        ohResult = InitParamSet(&sm2GenerateKeyParamSet, gEnvelopIniSm2,
            sizeof(gEnvelopIniSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_GenerateKeyItem(&gSm2KeyAlias, sm2GenerateKeyParamSet, sm2KeyData);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleEncrypt = {sizeof(uint64_t), handleE};

        ohResult = InitParamSet(&sm2EnKeyParmSet, gEnvelopEnSm2,
            sizeof(gEnvelopEnSm2) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        ohResult = OH_Huks_InitSession(&gSm2KeyAlias, sm2EnKeyParmSet, &handleEncrypt, nullptr);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
        
        static const uint32_t AES_COMMON_SIZE = 1024;
        uint8_t cipher[AES_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherSm4Data = {AES_COMMON_SIZE, cipher};
        ohResult = OH_Huks_FinishSession(&handleEncrypt, sm2EnKeyParmSet, &gSm4Data, &cipherSm4Data);
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importUintPubKey[] = {
            0x35, 0x23, 0x9e, 0x59, 0xc9, 0x07, 0x0a, 0x66, 0xee, 0x64, 0x0e, 0x7d, 0x1e, 0x6f, 0xea, 0x0d,
            0x82, 0x3f, 0x84, 0xf7, 0x1f, 0x16, 0x08, 0xa0, 0xc1, 0x9e, 0x10, 0xca, 0x09, 0x98, 0x68, 0x7a,
        };
        OH_Huks_Blob importPubKey = {sizeof(importUintPubKey), importUintPubKey};

        OH_Huks_Param importParams[] = {
            {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_X25519},
            {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_CURVE25519_KEY_SIZE_256},
            {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_AGREE},
            {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
            {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
            {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
            {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = importPubKey},
            {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE},
        };

        ohResult = InitParamSet(&importParamSet, importParams,
            sizeof(importParams) / sizeof(OH_Huks_Param));
        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);

        uint8_t importPrivate[] = {
            0x66, 0xc1, 0x42, 0x4e, 0x49, 0x60, 0x2a, 0x51, 0x91, 0x9b, 0xd0, 0xec, 0xb2, 0x1e, 0xc1, 0x24,
            0xf3, 0xeb, 0xfb, 0xf8, 0x79, 0x6c, 0x3f, 0x16, 0xcc, 0x4d, 0x16, 0xb3, 0x98, 0x48, 0xca, 0x4d,
        };
        OH_Huks_Blob importEnPrivateData = {sizeof(importPrivate), importPrivate};

        uint8_t importKey[1000] = {0};
        OH_Huks_Blob importKeyBlob = {0, importKey};
        ConcatBlob(&cipherSm4Data, &importEnPrivateData, &importKeyBlob);
        
        char importAlias[] = "importX25519";
        OH_Huks_Blob sm2KeyAlias = {(uint32_t)strlen(importAlias), (uint8_t *)importAlias};
        ohResult = OH_Huks_ImportWrappedKeyItem(&sm2KeyAlias, &gSm2KeyAlias, importParamSet, &importKeyBlob);

        EXPECT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS);
    } while (0);

    OH_Huks_FreeParamSet(&sm2EnKeyParmSet);
    OH_Huks_FreeParamSet(&sm2GenerateKeyParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}
}