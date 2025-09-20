/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_aead_length_test.h"

#include "securec.h"
#include <gtest/gtest.h>
#include <vector>

#include "hks_api.h"
#include "hks_param.h"
#include "hks_mem.h"
#include "hks_test_log.h"

#ifdef L2_STANDARD
using namespace testing::ext;
namespace Unittest::HksAeadLengthPartTest {
class HksAeadLengthTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAeadLengthTest::SetUpTestCase(void)
{
}

void HksAeadLengthTest::TearDownTestCase(void)
{
}

void HksAeadLengthTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksAeadLengthTest::TearDown()
{
}

static void InitAll()
{
    g_cipherBlob.size = MAX_TEST_BLOB_SIZE;
    g_aeadLenParam.uint32Param = HKS_AE_TAG_LEN;
    g_aeadTagParam.blob.size = HKS_AE_TAG_LEN;
    (void)memset_s(g_aeadTag, HKS_AE_TAG_LEN + 1, 0, HKS_AE_TAG_LEN + 1);
    (void)memset_s(g_cipherBlob.data, MAX_TEST_BLOB_SIZE, 0, MAX_TEST_BLOB_SIZE);
}

static int32_t TestConstructGenerateKeyParamSetOut(struct HksParamSet **outParamSet,
    bool paramSetExist, uint32_t paramSetSize)
{
    if (!paramSetExist) {
        return HKS_SUCCESS;
    }
    struct HksParamSet *tempParamSet = (struct HksParamSet *)HksMalloc(paramSetSize);
    if (tempParamSet == NULL) {
        return HKS_FAILURE;
    }
    (void)memset_s(tempParamSet, paramSetSize, 0, paramSetSize);
    tempParamSet->paramSetSize = paramSetSize;

    *outParamSet = tempParamSet;
    return HKS_SUCCESS;
}

static int32_t GenerateAesKey(bool local)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed";

    ret = HksAddParams(genParamSet, g_genAesKey, HKS_ARRAY_SIZE(g_genAesKey));
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams failed";
    if (local) {
        ret = HksAddParams(genParamSet, &g_localParam, 1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams is key alias failed";
        ret = TestConstructGenerateKeyParamSetOut(&paramSetOut, true, MAX_KEY_BLOB_SIZE);
        EXPECT_EQ(ret, 0);
    }

    ret = HksBuildParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksBuildParamSet failed";

    ret = HksGenerateKey(&g_keyBlob, genParamSet, paramSetOut);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    if (local) {
        struct HksParam *keyParam = nullptr;
        ret = HksGetParam(paramSetOut, HKS_TAG_SYMMETRIC_KEY_DATA, &keyParam);
        EXPECT_EQ(ret, HKS_SUCCESS);
        g_localKey.data = (uint8_t *)HksMalloc(MAX_KEY_BLOB_SIZE);
        if (g_localKey.data == nullptr) {
            HksFreeParamSet(&genParamSet);
            HksFreeParamSet(&paramSetOut);
            return HKS_ERROR_MALLOC_FAIL;
        }
        if (keyParam == nullptr) {
            HksFreeParamSet(&genParamSet);
            HksFreeParamSet(&paramSetOut);
            return HKS_ERROR_NULL_POINTER;
        }
        g_localKey.size = keyParam->blob.size;
        (void)memcpy_s(g_localKey.data, MAX_KEY_BLOB_SIZE, keyParam->blob.data, keyParam->blob.size);
    }

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&paramSetOut);
    return ret;
}

static void DeleteAesKey(bool local)
{
    if (local) {
        HKS_FREE_BLOB(g_localKey);
        return;
    }

    int32_t ret = HksDeleteKey(&g_keyBlob, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteAesKey failed.";
}

static int32_t TestOneStageEncrypt(
    struct HksParam *encryptParam, uint32_t paramCount, int32_t expected, uint32_t aeadTagLen, bool local)
{
    InitAll();
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed";
    ret = HksAddParams(encryptParamSet, encryptParam, paramCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams failed";
    if (aeadTagLen < INVALID_AEAD_TAG_LEN) {
        /* indicate aead tag len */
        g_aeadLenParam.uint32Param = aeadTagLen;
        ret = HksAddParams(encryptParamSet, &g_aeadLenParam, 1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams aead failed";
    }
    if (local) {
        /* local encrypt */
        ret = HksAddParams(encryptParamSet, &g_isAliasParam, 1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams local failed";
    }

    ret = HksBuildParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksBuildParamSet failed.";

    if (local) {
        ret = HksEncrypt(&g_localKey, encryptParamSet, &g_plainBlob, &g_cipherBlob);
        EXPECT_EQ(ret, expected) << "HksEncrypt failed.";
    } else {
        ret = HksEncrypt(&g_keyBlob, encryptParamSet, &g_plainBlob, &g_cipherBlob);
        EXPECT_EQ(ret, expected) << "HksEncrypt failed.";
    }

    HksFreeParamSet(&encryptParamSet);
    return ret;
}

static int32_t TestOneStageDecrypt(
    struct HksParam *decryptParam, uint32_t paramCount, int32_t expected, uint32_t aeadTagLen, bool local)
{
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed";
    ret = HksAddParams(decryptParamSet, decryptParam, paramCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams failed";
    if (aeadTagLen < INVALID_AEAD_TAG_LEN) {
        /* indicate aead tag len */
        g_aeadLenParam.uint32Param = aeadTagLen;
        ret = HksAddParams(decryptParamSet, &g_aeadLenParam, 1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams aead failed";
    }
    if (local) {
        ret = HksAddParams(decryptParamSet, &g_isAliasParam, 1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams local failed";
    }

    uint8_t *plain = (uint8_t *)HksMalloc(MAX_TEST_BLOB_SIZE);
    struct HksBlob plainText = {
        .size = MAX_TEST_BLOB_SIZE,
        .data = plain
    };

    if (local) {
        ret = HksDecrypt(&g_localKey, decryptParamSet, &g_cipherBlob, &plainText);
        EXPECT_EQ(ret, expected);
    } else {
        ret = HksDecrypt(&g_keyBlob, decryptParamSet, &g_cipherBlob, &plainText);
        EXPECT_EQ(ret, expected);
    }

    HksFreeParamSet(&decryptParamSet);
    HKS_FREE_BLOB(plainText);
    return ret;
}

static int32_t TestThreeStageEncrypt(
    struct HksParam *encryptParam, uint32_t paramCount, int32_t expected, uint32_t aeadTagLen)
{
    InitAll();
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed";
    ret = HksAddParams(encryptParamSet, encryptParam, paramCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams failed";
    if (aeadTagLen < INVALID_AEAD_TAG_LEN) {
        /* indicate aead tag len */
        g_aeadLenParam.uint32Param = aeadTagLen;
        ret = HksAddParams(encryptParamSet, &g_aeadLenParam, 1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams aead failed";
    } else {
        aeadTagLen = HKS_AE_TAG_LEN;
    }

    ret = HksBuildParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksBuildParamSet failed.";

    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = {
        .size = sizeof(uint64_t),
        .data = tmpHandle
    };
    ret = HksInit(&g_keyBlob, encryptParamSet, &handle, nullptr);
    EXPECT_EQ(ret, expected) << "encrypt HksInit failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksFinish(&handle, encryptParamSet, &g_plainBlob, &g_cipherBlob);
    EXPECT_EQ(ret, expected) << "encrypt HksFinish failed.";

    uint32_t txtSize = g_cipherBlob.size - aeadTagLen;
    (void)memcpy_s(g_aeadTag, HKS_AE_TAG_LEN, g_cipherBlob.data + txtSize, aeadTagLen);
    g_aeadTagParam.blob.size = aeadTagLen;
    (void)memset_s(g_cipherBlob.data + txtSize, MAX_TEST_BLOB_SIZE - txtSize, 0, MAX_TEST_BLOB_SIZE - txtSize);
    g_cipherBlob.size = txtSize;
    return ret;
}

static int32_t TestThreeStageDecrypt(
    struct HksParam *decryptParam, uint32_t paramCount, int32_t expected, uint32_t aeadTagLen)
{
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed";
    ret = HksAddParams(decryptParamSet, decryptParam, paramCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams failed";
    if (aeadTagLen < INVALID_AEAD_TAG_LEN) {
        /* indicate aead tag len */
        g_aeadLenParam.uint32Param = aeadTagLen;
        ret = HksAddParams(decryptParamSet, &g_aeadLenParam, 1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAddParams aead failed";
    }

    ret = HksAddParams(decryptParamSet, &g_aeadTagParam, 1);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksBuildParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksBuildParamSet failed.";

    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = {
        .size = sizeof(uint64_t),
        .data = tmpHandle
    };
    ret = HksInit(&g_keyBlob, decryptParamSet, &handle, nullptr);
    if (expected == HKS_ERROR_CRYPTO_ENGINE_ERROR || expected == HKS_ERROR_INVALID_ARGUMENT) {
        EXPECT_EQ(ret, HKS_SUCCESS) << "decrypt HksInit failed.";
    } else {
        EXPECT_EQ(ret, expected) << "decrypt HksInit failed.";
    }
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint8_t *plain = (uint8_t *)HksMalloc(MAX_TEST_BLOB_SIZE);
    struct HksBlob plainText = {
        .size = MAX_TEST_BLOB_SIZE,
        .data = plain
    };

    ret = HksFinish(&handle, decryptParamSet, &g_cipherBlob, &plainText);
    EXPECT_EQ(ret, expected) << "decrypt HksFinish failed.";
    HKS_FREE_BLOB(plainText);
    return ret;
}

static void TestOneStageEncryptAndDecrypt(const AeadLenAndExpect &aeadParam, bool local, uint32_t mode)
{
    int32_t ret = GenerateAesKey(local);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateAesKey failed.";

    uint32_t enParamCount = 0;
    uint32_t deParamCount = 0;
    struct HksParam *encryptParam = nullptr;
    struct HksParam *decryptParam = nullptr;
    if (mode == HKS_MODE_GCM) {
        encryptParam = g_aesGcmEncrypt;
        decryptParam = g_aesGcmDecrypt;
        enParamCount = HKS_ARRAY_SIZE(g_aesGcmEncrypt);
        deParamCount = HKS_ARRAY_SIZE(g_aesGcmDecrypt);
    } else if (mode == HKS_MODE_CCM) {
        encryptParam = g_aesCcmEncrypt;
        decryptParam = g_aesCcmDecrypt;
        enParamCount = HKS_ARRAY_SIZE(g_aesCcmEncrypt);
        deParamCount = HKS_ARRAY_SIZE(g_aesCcmDecrypt);
    } else {
        HKS_TEST_LOG_E("mode %u is invalid", mode);
        return;
    }

    auto [enAeadTagLen, enExpected, deAeadTagLen, deExpected] = aeadParam;
    ret = TestOneStageEncrypt(encryptParam, enParamCount, enExpected, enAeadTagLen, local);
    EXPECT_EQ(ret, enExpected) << "TestOneStageEncryptAndDecrypt failed.";
    ret = TestOneStageDecrypt(decryptParam, deParamCount, deExpected, deAeadTagLen, local);
    EXPECT_EQ(ret, deExpected) << "TestOneStageEncryptAndDecrypt failed.";

    DeleteAesKey(local);
}

static void TestThreeStageEncryptAndDecrypt(const AeadLenAndExpect &aeadParam, uint32_t mode)
{
    int32_t ret = GenerateAesKey(false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateAesKey failed.";

    uint32_t enParamCount = 0;
    uint32_t deParamCount = 0;
    struct HksParam *encryptParam = nullptr;
    struct HksParam *decryptParam = nullptr;
    if (mode == HKS_MODE_GCM) {
        encryptParam = g_aesGcmEncrypt;
        decryptParam = g_aesGcmDecrypt;
        enParamCount = HKS_ARRAY_SIZE(g_aesGcmEncrypt);
        deParamCount = HKS_ARRAY_SIZE(g_aesGcmDecrypt);
    } else if (mode == HKS_MODE_CCM) {
        encryptParam = g_aesCcmEncrypt;
        decryptParam = g_aesCcmDecrypt;
        enParamCount = HKS_ARRAY_SIZE(g_aesCcmEncrypt);
        deParamCount = HKS_ARRAY_SIZE(g_aesCcmDecrypt);
    } else {
        HKS_TEST_LOG_E("mode %u is invalid", mode);
        return;
    }

    auto [enAeadTagLen, enExpected, deAeadTagLen, deExpected] = aeadParam;
    ret = TestThreeStageEncrypt(encryptParam, enParamCount, enExpected, enAeadTagLen);
    EXPECT_EQ(ret, enExpected) << "TestThreeStageEncryptAndDecrypt failed.";
    ret = TestThreeStageDecrypt(decryptParam, deParamCount, deExpected, deAeadTagLen);
    EXPECT_EQ(ret, deExpected) << "TestThreeStageEncryptAndDecrypt failed.";

    DeleteAesKey(false);
}

static void TestOnlyEncrypt(const std::vector<std::pair<uint32_t, int32_t>> &testExpected, uint32_t mode)
{
    uint32_t enParamCount = 0;
    struct HksParam *encryptParam = nullptr;
    if (mode == HKS_MODE_GCM) {
        encryptParam = g_aesGcmEncrypt;
        enParamCount = HKS_ARRAY_SIZE(g_aesGcmEncrypt);
    } else if (mode == HKS_MODE_CCM) {
        encryptParam = g_aesCcmEncrypt;
        enParamCount = HKS_ARRAY_SIZE(g_aesCcmEncrypt);
    } else {
        HKS_TEST_LOG_E("mode %u is invalid", mode);
        return;
    }

    int32_t ret = HKS_SUCCESS;
    auto testEncrypt = [&] (bool local, int32_t expected, uint32_t aeadTagLen) {
        ret = GenerateAesKey(local);
        EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateAesKey failed.";
        ret = TestOneStageEncrypt(encryptParam, enParamCount, expected, aeadTagLen, local);
        EXPECT_EQ(ret, expected) << "TestOneStageEncrypt failed.";
        DeleteAesKey(local);
    };

    for (auto &[aeadTagLen, expected] : testExpected) {
        /* one stage not local */
        testEncrypt(false, expected, aeadTagLen);
        /* one stage local */
        testEncrypt(true, expected, aeadTagLen);
        /* three stage */
        ret = GenerateAesKey(false);
        EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateAesKey failed.";
        ret = TestThreeStageEncrypt(encryptParam, enParamCount, expected, aeadTagLen);
        EXPECT_EQ(ret, expected) << "TestThreeStageEncrypt failed.";
        DeleteAesKey(false);
    }
}

static void TestEncryptAndDecrypt(const std::vector<AeadLenAndExpect> &testExpected, uint32_t mode)
{
    for (auto &test : testExpected) {
        /* one stage not local */
        TestOneStageEncryptAndDecrypt(test, false, mode);
        /* one stage local */
        TestOneStageEncryptAndDecrypt(test, true, mode);
        /* three stage */
        TestThreeStageEncryptAndDecrypt(test, mode);
    }
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest001
 * @tc.desc: AES-GCM Encrypt and Decrypt with aead length is 16.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest001, TestSize.Level0)
{
    TestEncryptAndDecrypt(aesGcmEncAndDecExpected, HKS_MODE_GCM);
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest002
 * @tc.desc: AES-GCM Encrypt with aead length is 12/20.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest002, TestSize.Level0)
{
    TestOnlyEncrypt(aesGcmEncExpected, HKS_MODE_GCM);
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest003
 * @tc.desc: AES-GCM Encrypt with aead length is 16, Decrypt with aead length is 12.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest003, TestSize.Level0)
{
    TestEncryptAndDecrypt(aesGcmEncAndDecExpected1, HKS_MODE_GCM);
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest004
 * @tc.desc: AES-CCM Encrypt with aead length is 2/4/6/8/10/12/14/16.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest004, TestSize.Level0)
{
    TestEncryptAndDecrypt(aesCcmEncAndDecExpected, HKS_MODE_CCM);
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest005
 * @tc.desc: AES-CCM Encrypt with aead length is 0/1/2/3/5/7/9/11/13/15/17/18.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest005, TestSize.Level0)
{
    TestOnlyEncrypt(aesCcmEncExpected, HKS_MODE_CCM);
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest006
 * @tc.desc: AES-CCM Encrypt with aead length is 16 and Decrypt with aead length is 5/12.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest006, TestSize.Level0)
{
    /* one stage, AEAD tag will not be carried by inparamset, so a mismatch cannot occur */
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    AeadLenAndExpect test1{16, HKS_SUCCESS, 12, HKS_ERROR_CRYPTO_ENGINE_ERROR};
#else
    AeadLenAndExpect test1{16, HKS_SUCCESS, 12, HKS_ERROR_INVALID_ARGUMENT};
#endif
    AeadLenAndExpect test2{16, HKS_SUCCESS, 12, HKS_ERROR_CODE_AEAD_TAG_LEN_NOT_EQUAL};
    AeadLenAndExpect test3{16, HKS_SUCCESS, 5, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID};
    /* not local */
    TestOneStageEncryptAndDecrypt(test1, false, HKS_MODE_CCM);
    TestOneStageEncryptAndDecrypt(test3, false, HKS_MODE_CCM);
    /* local */
    auto &[enLen, enExp, deLen, deExp] = test1;
    int32_t temp = deExp;
    deExp = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    TestOneStageEncryptAndDecrypt(test1, true, HKS_MODE_CCM);
    TestOneStageEncryptAndDecrypt(test3, false, HKS_MODE_CCM);
    /* three stage */
    deExp = temp;
    TestThreeStageEncryptAndDecrypt(test2, HKS_MODE_CCM);
    TestThreeStageEncryptAndDecrypt(test3, HKS_MODE_CCM);
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest007
 * @tc.desc: AES-CCM Encrypt and Decrypt without indicate aead length, Decrypt with aead blob size is 5/12.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest007, TestSize.Level0)
{
    int32_t ret = HKS_SUCCESS;
    auto testInvalidDecrypt = [&] (bool local) {
        ret = GenerateAesKey(local);
        EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateAesKey failed.";
        TestOneStageEncrypt(
            g_aesCcmEncrypt, HKS_ARRAY_SIZE(g_aesCcmEncrypt),
            HKS_SUCCESS, INVALID_AEAD_TAG_LEN, local);
        uint32_t length = strlen(g_cipherText);
        for (uint32_t i = 0; i < 5; ++i) {
            g_cipherText[length - i -1] = '\0';
        }
        int32_t expected = HKS_SUCCESS;
#ifdef HKS_UNTRUSTED_RUNNING_ENV
        expected = HKS_ERROR_CRYPTO_ENGINE_ERROR;
#else
        expected = HKS_ERROR_INVALID_ARGUMENT;
#endif
        if (local) {
            expected = HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
        TestOneStageDecrypt(g_aesCcmDecrypt, HKS_ARRAY_SIZE(g_aesCcmDecrypt), expected, INVALID_AEAD_TAG_LEN, local);
        DeleteAesKey(local);
    };
    /* one stage not local */
    testInvalidDecrypt(false);
    /* one stage local */
    testInvalidDecrypt(true);

    /* three stage */
    ret = GenerateAesKey(false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateAesKey failed.";
    TestThreeStageEncrypt(
        g_aesCcmEncrypt, HKS_ARRAY_SIZE(g_aesCcmEncrypt),
        HKS_SUCCESS, INVALID_AEAD_TAG_LEN);
    g_aeadTagParam.blob.size = 5;
    TestThreeStageDecrypt(
        g_aesCcmDecrypt, HKS_ARRAY_SIZE(g_aesCcmDecrypt),
        HKS_ERROR_CODE_AEAD_TAG_LEN_NOT_EQUAL, INVALID_AEAD_TAG_LEN);
    DeleteAesKey(false);
}

/**
 * @tc.name: HksAeadLengthTest.HksAeadLengthTest008
 * @tc.desc: AES-CCM Encrypt with aead length is 12, Decrypt with padding pre Aead.
 * @tc.type: FUNC
 */
HWTEST_F(HksAeadLengthTest, HksAeadLengthTest008, TestSize.Level0)
{
    int32_t ret = HKS_SUCCESS;
    ret = GenerateAesKey(false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateAesKey failed.";
    TestThreeStageEncrypt(g_aesCcmEncrypt, HKS_ARRAY_SIZE(g_aesCcmEncrypt), HKS_SUCCESS, 12);
    char tmpAead[HKS_AE_TAG_LEN + 1] = {0};
    for (int i = 4; i <= HKS_AE_TAG_LEN; ++i) {
        tmpAead[i] = g_aeadTag[i - 4];
    }
    for (int j = 0; j <= HKS_AE_TAG_LEN; ++j) {
        g_aeadTag[j] = tmpAead[j];
    }
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    TestThreeStageDecrypt(g_aesCcmDecrypt, HKS_ARRAY_SIZE(g_aesCcmDecrypt), HKS_ERROR_CRYPTO_ENGINE_ERROR, 12);
#else
    TestThreeStageDecrypt(g_aesCcmDecrypt, HKS_ARRAY_SIZE(g_aesCcmDecrypt), HKS_ERROR_INVALID_ARGUMENT, 12);
#endif
    
    DeleteAesKey(false);
}

}

#endif // L2_STANDARD