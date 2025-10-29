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

#include "hks_agreement_test.h"

#include <vector>

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_test_three_stage.h"

using namespace testing::ext;
namespace {
#ifndef _CUT_AUTHENTICATE_

class HksAgreementTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAgreementTest::SetUpTestCase(void)
{
}

void HksAgreementTest::TearDownTestCase(void)
{
}

void HksAgreementTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksAgreementTest::TearDown()
{
}

static struct HksBlob g_keyAlias01001 = {
    (uint32_t)strlen("HksX25519AgreeKeyAliasTest001_1"),
    (uint8_t *)"HksX25519AgreeKeyAliasTest001_1"
};
static struct HksBlob g_keyAlias02001 = {
    (uint32_t)strlen("HksX25519AgreeKeyAliasTest001_2"),
    (uint8_t *)"HksX25519AgreeKeyAliasTest001_2"
};
static struct HksBlob g_keyAliasFinal1001 = {
    (uint32_t)strlen("HksX25519AgreeKeyAliasTest001_final"),
    (uint8_t *)"HksX25519AgreeKeyAliasTest001_final"
};
static struct HksBlob g_keyAliasFinal2001 = {
    (uint32_t)strlen("HksX25519AgreeKeyAliasTest002_final"),
    (uint8_t *)"HksX25519AgreeKeyAliasTest002_final"
};
static const std::string g_inData = "Hks_X25519_Agree_Test_0000000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";

static struct HksParam g_genParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }
};

static struct HksParam g_agreeParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = 512
    }
};

static struct HksParam g_agreeParams01Finish001[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag = HKS_TAG_IS_KEY_ALIAS,
        .boolParam = true
    }, {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_512
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal1001
    }
};

static struct HksParam g_agreeParams01Finish002[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag = HKS_TAG_IS_KEY_ALIAS,
        .boolParam = true
    }, {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_512
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal2001
    }
};

struct HksUpdateAgreeParams {
    int32_t expected;
    uint32_t agreeFinAlg;
    uint32_t agreeFinLen;
    uint32_t agreeFinPur;
};

const static std::vector<HksUpdateAgreeParams> testHmacAgree = {
    {HKS_ERROR_INVALID_ARGUMENT, HKS_ALG_HMAC, 8, HKS_KEY_PURPOSE_MAC},
    {HKS_SUCCESS, HKS_ALG_HMAC, 256, HKS_KEY_PURPOSE_MAC}
};

static const uint32_t X25519_COMMON_SIZE = 4096;
const int TMP_SIZE = 512;
const int X25519_KEY_SIZE = 32;
const struct HksTestAgreeParams g_testAgreeParams[] = {
    /* ree x25519 success */
    { 0, HKS_SUCCESS, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        { true, true, HKS_ALG_X25519, true, HKS_CURVE25519_KEY_SIZE_256, true,
            HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY, true, HKS_DIGEST_SHA256,
            false, 0, false, 0, true, HKS_STORAGE_TEMP },
        { 0 },
        { true, true, HKS_ALG_X25519, true,
            HKS_CURVE25519_KEY_SIZE_256, true, false },
        { true, TMP_SIZE, true, TMP_SIZE },
        { true, X25519_KEY_SIZE, true, X25519_KEY_SIZE },
        { true, X25519_KEY_SIZE, true, X25519_KEY_SIZE },
        { true, X25519_KEY_SIZE, true, X25519_KEY_SIZE }
    },
};

static int32_t AgreeKey(const struct HksTestAgreeParamSet *agreeParamSetParams, struct HksBlob *privateKey,
    struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    struct HksParamSet *agreeParamSetTest = NULL;
    struct TestAgreeParamSetStructure paramStruct = {
        &agreeParamSetTest,
        agreeParamSetParams->paramSetExist,
        agreeParamSetParams->setAlg, agreeParamSetParams->alg,
        agreeParamSetParams->setKeySize, agreeParamSetParams->keySize,
        agreeParamSetParams->setIsKeyAlias, agreeParamSetParams->isKeyAlias
    };
    int32_t ret = TestConstructAgreeParamSet(&paramStruct);
    HKS_TEST_ASSERT(ret == 0);

    ret = HksAgreeKeyRun(agreeParamSetTest, privateKey, peerPublicKey, agreedKey, 1);
    HksFreeParamSet(&agreeParamSetTest);
    return ret;
}

static int32_t HksX25519AgreeExport(const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2,
    struct HksBlob *publicKey1, struct HksBlob *publicKey2, const struct HksParamSet *genParamSet)
{
    int32_t ret = HksExportPublicKeyForDe(keyAlias1, genParamSet, publicKey1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey01 failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = HksExportPublicKeyForDe(keyAlias2, genParamSet, publicKey2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey02 failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    return HKS_SUCCESS;
}

static void HksX25519AgreeFreeParamSet(struct HksParamSet *paramSet1, struct HksParamSet *paramSet2,
    struct HksParamSet *paramSet3, struct HksParamSet *paramSet4, struct HksParamSet *paramSet5)
{
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
    HksFreeParamSet(&paramSet3);
    HksFreeParamSet(&paramSet4);
    HksFreeParamSet(&paramSet5);
}

static void HksX25519AgreeFreeBlob(struct HksBlob *blob1, struct HksBlob *blob2, struct HksBlob *blob3, struct HksBlob *blob4)
{
    HKS_FREE(blob1->data);
    HKS_FREE(blob2->data);
    HKS_FREE(blob3->data);
    HKS_FREE(blob4->data);
}

static int32_t MallocAndCheckBlobData(struct HksBlob *blob, const uint32_t blobSize)
{
    blob->data = (uint8_t *)HksMalloc(blobSize);
    if (blob->data == NULL) {
        HKS_LOG_E("could not alloc memory");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static int32_t HksX25519AgreeFinish(const struct HksBlob *keyAlias, const struct HksBlob *publicKey,
    const struct HksParamSet *initParamSet, const struct HksParamSet *finishParamSet, struct HksBlob *outData)
{
    struct HksBlob inData = {
        (uint32_t)g_inData.length(),
        (uint8_t *)g_inData.c_str()
    };

    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    int32_t ret = HksInitForDe(keyAlias, initParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint8_t outDataU[X25519_COMMON_SIZE] = {0};
    struct HksBlob outDataUpdate = { X25519_COMMON_SIZE, outDataU };
    ret = HksUpdateForDe(&handle, initParamSet, publicKey, &outDataUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksFinishForDe(&handle, finishParamSet, &inData, outData);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    return HKS_SUCCESS;
}

static void TestThreeStageAgree(int32_t expected)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams, HKS_ARRAY_SIZE(g_genParams));
    EXPECT_EQ(ret, HKS_SUCCESS) << "Agree InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams, HKS_ARRAY_SIZE(g_agreeParams));
    EXPECT_EQ(ret, HKS_SUCCESS) << "Agree InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish001, HKS_ARRAY_SIZE(g_agreeParams01Finish001));
    EXPECT_EQ(ret, HKS_SUCCESS) << "Agree InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams, HKS_ARRAY_SIZE(g_agreeParams));
    EXPECT_EQ(ret, HKS_SUCCESS) << "Agree InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams01Finish002, HKS_ARRAY_SIZE(g_agreeParams01Finish002));
    EXPECT_EQ(ret, HKS_SUCCESS) << "Agree InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Agree GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Agree GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_CURVE25519_KEY_SIZE_256, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_CURVE25519_KEY_SIZE_256, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksX25519AgreeExport(&g_keyAlias01001, &g_keyAlias02001, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = X25519_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = X25519_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksX25519AgreeFinish(&g_keyAlias01001, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, expected) << "HksX25519AgreeFinish01 failed.";
    ret = HksX25519AgreeFinish(&g_keyAlias02001, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, expected) << "HksX25519AgreeFinish02 failed.";

    HksDeleteKeyForDe(&g_keyAlias01001, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02001, genParamSet);
    HksDeleteKeyForDe(&g_keyAliasFinal1001, NULL);
    HksDeleteKeyForDe(&g_keyAliasFinal2001, NULL);
    HksX25519AgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksX25519AgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksAgreementTest.HksAgreementTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksAgreementTest, HksAgreementTest001, TestSize.Level0)
{
     /* 1. generate key */
    struct HksBlob *privateKey = NULL;
    struct HksBlob *peerPubKeyAlias = NULL;
    struct HksBlob *peerPublicKey = NULL;
    int32_t ret;

    if (g_testAgreeParams[0].genKeyParamSetParams.setKeyStorageFlag &&
        (g_testAgreeParams[0].genKeyParamSetParams.keyStorageFlag == HKS_STORAGE_TEMP)) {
        ret = GenerateLocalX25519Key(&privateKey, NULL, &g_testAgreeParams[0].localPrivateKeyParams, NULL);
        ASSERT_TRUE(ret == 0);
        ret = GenerateLocalX25519Key(NULL, &peerPublicKey, NULL, &g_testAgreeParams[0].localPublicKeyParams);
        ASSERT_TRUE(ret == 0);
    }
    /* 2. agreeKey */
    struct HksBlob *agreeKey = NULL;
    ret = TestConstuctBlob(&agreeKey,
        g_testAgreeParams[0].agreedKeyParams.blobExist,
        g_testAgreeParams[0].agreedKeyParams.blobSize,
        g_testAgreeParams[0].agreedKeyParams.blobDataExist,
        g_testAgreeParams[0].agreedKeyParams.blobDataSize);
    ASSERT_TRUE(ret == 0);

    ret = AgreeKey(&g_testAgreeParams[0].agreeParamSetParams, privateKey, peerPublicKey, agreeKey);
    ASSERT_TRUE(ret == g_testAgreeParams[0].expectResult);

    /* 3. delete key */
    if (!(g_testAgreeParams[0].genKeyParamSetParams.setKeyStorageFlag &&
        (g_testAgreeParams[0].genKeyParamSetParams.keyStorageFlag == HKS_STORAGE_TEMP)) &&
        ((g_testAgreeParams[0].keyAlias1Params.blobExist) &&
        (g_testAgreeParams[0].keyAlias2Params.blobExist))) {
        ret = HksDeleteKeyForDe(privateKey, NULL);
        ASSERT_TRUE(ret == 0);
        ret = HksDeleteKeyForDe(peerPubKeyAlias, NULL);
        ASSERT_TRUE(ret == 0);
    }
    TestFreeBlob(&privateKey);
    TestFreeBlob(&peerPubKeyAlias);
    TestFreeBlob(&peerPublicKey);
    TestFreeBlob(&agreeKey);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: HksAgreementTest.HksAgreementTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksAgreementTest, HksAgreementTest002, TestSize.Level0)
{
     /* 1. generate key */
    struct HksBlob *privateKey = NULL;
    struct HksBlob *peerPubKeyAlias = NULL;
    struct HksBlob *peerPublicKey = NULL;
    struct HksBlob *privateKey2 = NULL;
    struct HksBlob *peerPublicKey2 = NULL;
    int32_t ret;

    if (g_testAgreeParams[0].genKeyParamSetParams.setKeyStorageFlag &&
        (g_testAgreeParams[0].genKeyParamSetParams.keyStorageFlag == HKS_STORAGE_TEMP)) {
        ret = GenerateLocalX25519Key(&privateKey, &peerPublicKey, &g_testAgreeParams[0].localPrivateKeyParams, \
            &g_testAgreeParams[0].localPublicKeyParams);
        ASSERT_TRUE(ret == 0);
        ret = GenerateLocalX25519Key(&privateKey2, &peerPublicKey2, &g_testAgreeParams[0].localPrivateKeyParams, \
            &g_testAgreeParams[0].localPublicKeyParams);
        ASSERT_TRUE(ret == 0);
    }
    /* 2. agreeKey */
    struct HksBlob *agreeKey = NULL;
    ret = TestConstuctBlob(&agreeKey, g_testAgreeParams[0].agreedKeyParams.blobExist, \
        g_testAgreeParams[0].agreedKeyParams.blobSize, g_testAgreeParams[0].agreedKeyParams.blobDataExist, \
        g_testAgreeParams[0].agreedKeyParams.blobDataSize);
    ASSERT_TRUE(ret == 0);

    struct HksBlob *agreeKey2 = NULL;
    ret = TestConstuctBlob(&agreeKey2, g_testAgreeParams[0].agreedKeyParams.blobExist, \
        g_testAgreeParams[0].agreedKeyParams.blobSize, g_testAgreeParams[0].agreedKeyParams.blobDataExist, \
        g_testAgreeParams[0].agreedKeyParams.blobDataSize);
    ASSERT_TRUE(ret == 0);

    ret = AgreeKey(&g_testAgreeParams[0].agreeParamSetParams, privateKey, peerPublicKey2, agreeKey);
    ASSERT_TRUE(ret == g_testAgreeParams[0].expectResult);

    ret = AgreeKey(&g_testAgreeParams[0].agreeParamSetParams, privateKey2, peerPublicKey, agreeKey2);
    ASSERT_TRUE(ret == g_testAgreeParams[0].expectResult);
    EXPECT_EQ(agreeKey->size, agreeKey2->size);
    EXPECT_EQ(memcmp(agreeKey->data, agreeKey2->data, agreeKey->size), 0);

    /* 3. delete key */
    if (!(g_testAgreeParams[0].genKeyParamSetParams.setKeyStorageFlag && \
        (g_testAgreeParams[0].genKeyParamSetParams.keyStorageFlag == HKS_STORAGE_TEMP)) && \
        ((g_testAgreeParams[0].keyAlias1Params.blobExist) && (g_testAgreeParams[0].keyAlias2Params.blobExist))) {
        ASSERT_TRUE(HksDeleteKeyForDe(privateKey, NULL) == 0);
        ASSERT_TRUE(HksDeleteKeyForDe(peerPubKeyAlias, NULL) == 0);
    }
    TestFreeBlob(&privateKey);
    TestFreeBlob(&peerPubKeyAlias);
    TestFreeBlob(&peerPublicKey);
    TestFreeBlob(&agreeKey);
    TestFreeBlob(&agreeKey2);
}

/**
 * @tc.name: HksAgreementTest.HksAgreementTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksAgreementTest, HksAgreementTest003, TestSize.Level0)
{
    for (auto &test : testHmacAgree) {
        g_agreeParams01Finish001[2].uint32Param = test.agreeFinAlg;
        g_agreeParams01Finish001[3].uint32Param = test.agreeFinLen;
        g_agreeParams01Finish001[4].uint32Param = test.agreeFinPur;

        g_agreeParams01Finish002[2].uint32Param = test.agreeFinAlg;
        g_agreeParams01Finish002[3].uint32Param = test.agreeFinLen;
        g_agreeParams01Finish002[4].uint32Param = test.agreeFinPur;

        TestThreeStageAgree(test.expected);
    }
}

#endif /* _CUT_AUTHENTICATE_ */
}