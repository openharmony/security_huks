/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "hks_derive_test_c.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_three_stage.h"

using namespace testing::ext;
namespace {
class HksDeriveTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDeriveTest::SetUpTestCase(void)
{
}

void HksDeriveTest::TearDownTestCase(void)
{
}

void HksDeriveTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksDeriveTest::TearDown()
{
}

const static struct HksBlob deriveKeyAlias = {
    (uint32_t)strlen("test_derive_key"),
    (uint8_t *)"test_derive_key"
};

static const std::string g_inData = "Hks_TestKdf_Derive_Test_00000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";

struct HksTestDeriveParam {
    int32_t expected;
    uint32_t deriveAlg;
    uint32_t finishAlg; // derived key algorithm
    uint32_t finishLen; // derived key length
    uint32_t keyBytes;
    uint32_t finishPur; // derived key purpose
};

/* param to gen key */
const static struct HksParam genDeriveParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};

/* param to derive key */
static struct HksParam kdfParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = 0
    }
};

/* param to set key info */
static struct HksParam finishParams[] = {
    {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS,
    }, {
        .tag = HKS_TAG_IS_KEY_ALIAS,
        .boolParam = true,
    }, {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = deriveKeyAlias
    }, {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES,
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    }
};

static struct HksTestDeriveParam testDeriveHmacKey[] = {
    /* hkdf success */
    { HKS_SUCCESS, HKS_ALG_HKDF, HKS_ALG_HMAC, 8, 1, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_HKDF, HKS_ALG_HMAC, 16, 2, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_HKDF, HKS_ALG_HMAC, 24, 3, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_HKDF, HKS_ALG_HMAC, 256, 32, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_HKDF, HKS_ALG_HMAC, 1024, 128, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_HKDF, HKS_ALG_HMAC, 1040, 130, HKS_KEY_PURPOSE_MAC },
    /* hkdf failed */
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_HKDF, HKS_ALG_HMAC, 8, 2, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_HKDF, HKS_ALG_HMAC, 16, 3, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_HKDF, HKS_ALG_HMAC, 24, 4, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_HKDF, HKS_ALG_HMAC, 256, 33, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_HKDF, HKS_ALG_HMAC, 1024, 129, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_HKDF, HKS_ALG_HMAC, 1040, 129, HKS_KEY_PURPOSE_MAC },
    /* pbkdf success */
    { HKS_SUCCESS, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 8, 1, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 16, 2, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 24, 3, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 256, 32, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 1024, 128, HKS_KEY_PURPOSE_MAC },
    { HKS_SUCCESS, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 1040, 130, HKS_KEY_PURPOSE_MAC },
    /* pbkdf failed */
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 8, 2, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 16, 3, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 24, 4, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 256, 33, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 1024, 129, HKS_KEY_PURPOSE_MAC },
    { HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_PBKDF2, HKS_ALG_HMAC, 1040, 129, HKS_KEY_PURPOSE_MAC },
};

static int32_t DeriveKey(const struct HksTestDeriveParamSet *deriveParamSetParams, const struct HksBlob *masterKey,
    struct HksBlob *derivedKey, struct HksBlob **saltData, struct HksBlob **infoData)
{
    struct HksParamSet *deriveParamSet = NULL;
    uint32_t saltSize = deriveParamSetParams->saltSize;
    uint32_t infoSize = deriveParamSetParams->infoSize;
    if (saltSize != 0) {
        HKS_TEST_ASSERT(TestConstuctBlob(saltData, true, saltSize, true, saltSize) == 0);
    }
    if (infoSize != 0) {
        HKS_TEST_ASSERT(TestConstuctBlob(infoData, true, infoSize, true, infoSize) == 0);
    }
    struct TestDeriveParamSetStructure paramStruct = {
        &deriveParamSet,
        deriveParamSetParams->paramSetExist,
        deriveParamSetParams->setAlg, deriveParamSetParams->alg,
        deriveParamSetParams->setPurpose, deriveParamSetParams->purpose,
        deriveParamSetParams->setDigest, deriveParamSetParams->digest,
        deriveParamSetParams->setIteration, deriveParamSetParams->iteration,
        deriveParamSetParams->setSalt, *saltData,
        deriveParamSetParams->setInfo, *infoData,
        deriveParamSetParams->setIsKeyAlias, deriveParamSetParams->isKeyAlias
    };
    int32_t ret = TestConstructDeriveParamSet(&paramStruct);
    HKS_TEST_ASSERT(ret == 0);

    ret = HksDeriveKeyRun(deriveParamSet, masterKey, derivedKey, 1);
    HksFreeParamSet(&deriveParamSet);
    return ret;
}

static int32_t BaseTestDerive(uint32_t index)
{
    /* 1. generate key */
    struct HksBlob *keyAlias = NULL;
    int32_t ret;
    if (g_testDeriveParams[index].genKeyParamSetParams.setKeyStorageFlag &&
        (g_testDeriveParams[index].genKeyParamSetParams.keyStorageFlag == HKS_STORAGE_TEMP)) {
        ret = GenerateLocalRandomKey(&keyAlias, &g_testDeriveParams[index].localKeyParams);
    } else {
        if (g_testDeriveParams[index].keyAliasParams.blobExist) {
            ret = GenerateKey(&keyAlias, &g_testDeriveParams[index].keyAliasParams,
                &g_testDeriveParams[index].genKeyParamSetParams, NULL);
        } else {
            ret = TestConstuctBlob(&keyAlias,
                g_testDeriveParams[index].masterKeyParams.blobExist,
                g_testDeriveParams[index].masterKeyParams.blobSize,
                g_testDeriveParams[index].masterKeyParams.blobDataExist,
                g_testDeriveParams[index].masterKeyParams.blobDataSize);
        }
    }
    HKS_TEST_ASSERT(ret == 0);

    /* 2. derive */
    struct HksBlob *derivedKey = NULL;
    ret = TestConstuctBlob(&derivedKey,
        g_testDeriveParams[index].derivedKeyParams.blobExist,
        g_testDeriveParams[index].derivedKeyParams.blobSize,
        g_testDeriveParams[index].derivedKeyParams.blobDataExist,
        g_testDeriveParams[index].derivedKeyParams.blobDataSize);
    HKS_TEST_ASSERT(ret == 0);

    struct HksBlob *saltData = NULL;
    struct HksBlob *infoData = NULL;
    ret = DeriveKey(&g_testDeriveParams[index].deriveParamSetParams, keyAlias, derivedKey, &saltData, &infoData);
    if (ret != g_testDeriveParams[index].expectResult) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", g_testDeriveParams[index].testId, ret);
    }
    HKS_TEST_ASSERT(ret == g_testDeriveParams[index].expectResult);

    /* 3. delete key */
    if (!(g_testDeriveParams[index].genKeyParamSetParams.setKeyStorageFlag &&
        (g_testDeriveParams[index].genKeyParamSetParams.keyStorageFlag == HKS_STORAGE_TEMP)) &&
        (g_testDeriveParams[index].keyAliasParams.blobExist)) {
        HKS_TEST_ASSERT(HksDeleteKeyForDe(keyAlias, NULL) == 0);
    }
    TestFreeBlob(&keyAlias);
    TestFreeBlob(&derivedKey);
    TestFreeBlob(&saltData);
    TestFreeBlob(&infoData);

    return ret;
}

static void DeriveKeyThreeStage(int32_t expected)
{
    int32_t ret = HKS_SUCCESS;
    /* gen key paramset */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, genDeriveParams, HKS_ARRAY_SIZE(genDeriveParams));
    EXPECT_EQ(ret, HKS_SUCCESS);

    /* derive paramset */
    struct HksParamSet *deriveParamSet = nullptr;
    ret = InitParamSet(&deriveParamSet, kdfParams, HKS_ARRAY_SIZE(kdfParams));
    EXPECT_EQ(ret, HKS_SUCCESS);

    /* finish paramset */
    struct HksParamSet *finishParamSet = nullptr;
    ret = InitParamSet(&finishParamSet, finishParams, HKS_ARRAY_SIZE(finishParams));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob inData = {
        (uint32_t)g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };

    /* gen key */
    ret = HksGenerateKeyForDe(&deriveKeyAlias, genParamSet, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Derive gen key failed";

    /* derive init */
    uint8_t handleDTest[sizeof(uint64_t)] = {0};
    struct HksBlob handleDerive = { sizeof(uint64_t), handleDTest };
    ret = HksInitForDe(&deriveKeyAlias, deriveParamSet, &handleDerive, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Derive Init failed.";

    /* derive update */
    uint8_t tmpOut[HKS_TEST_MAX_KEY_SIZE] = {0};
    struct HksBlob outData = { HKS_TEST_MAX_KEY_SIZE, tmpOut };
    ret = HksUpdateForDe(&handleDerive, deriveParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Derive Update failed.";

    /* derive finish */
    uint8_t outDataD[HKS_TEST_MAX_KEY_SIZE] = {0};
    struct HksBlob outDataDerive = { HKS_TEST_MAX_KEY_SIZE, outDataD };
    ret = HksFinishForDe(&handleDerive, finishParamSet, &inData, &outDataDerive);
    EXPECT_EQ(ret, expected) << "Derive Finish failed.";

    /* delete key */
    EXPECT_EQ(HksDeleteKeyForDe(&deriveKeyAlias, nullptr), HKS_SUCCESS);

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&deriveParamSet);
    HksFreeParamSet(&finishParamSet);
}

#ifndef _CUT_AUTHENTICATE_
/**
 * @tc.name: HksDeriveTest.HksDeriveTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveTest, HksDeriveTest001, TestSize.Level0)
{
    int32_t ret = BaseTestDerive(0);
    ASSERT_TRUE(ret == 0);
}
#endif /* _CUT_AUTHENTICATE_ */

/**
 * @tc.name: HksDeriveTest.HksDeriveTest002
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveTest, HksDeriveTest002, TestSize.Level0)
{
    int32_t ret = BaseTestDerive(1);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: HksDeriveTest.HksDeriveTest003
 * @tc.desc: The static function test derive hmac key;
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveTest, HksDeriveTest003, TestSize.Level0)
{
    uint32_t index = 0;
    for (index = 0; index < HKS_ARRAY_SIZE(testDeriveHmacKey); ++index) {
        kdfParams[0].uint32Param = testDeriveHmacKey[index].deriveAlg;
        kdfParams[3].uint32Param = testDeriveHmacKey[index].keyBytes;
        finishParams[3].uint32Param = testDeriveHmacKey[index].finishAlg;
        finishParams[4].uint32Param = testDeriveHmacKey[index].finishLen;
        finishParams[5].uint32Param = testDeriveHmacKey[index].finishPur;
        DeriveKeyThreeStage(testDeriveHmacKey[index].expected);
    }
}

}