/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_mlkem_encap_decap_test.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::MlKemEncap {

class HksMlKemEncapTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksMlKemEncapTest::SetUpTestCase(void)
{
}

void HksMlKemEncapTest::TearDownTestCase(void)
{
}

void HksMlKemEncapTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksMlKemEncapTest::TearDown()
{
#ifdef L2_STANDARD
    std::system("find /data/service/el1/public/huks_service -user root -delete");
#endif
}

#ifdef L2_STANDARD
#ifdef HKS_UNTRUSTED_RUNNING_ENV

static struct HksParam g_genEncapParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
};

static struct HksParam g_genDecapParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
};

static struct HksParam g_encapParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
};

static struct HksParam g_decapParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
};

static struct HksParam g_genEncapParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_1024 },
};

static struct HksParam g_genDecapParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_1024 },
};

static struct HksParam g_encapParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_1024 },
};

static struct HksParam g_decapParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_1024 },
};

static struct HksParam g_sharedKeyParams001[] = {
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static struct HksParam g_sharedKeyParamsNoKeySize[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
};

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest001
 * @tc.desc: alg-ML-KEM-768 purpose-WRAP encapsulate with null shared key (dummy path).
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksMlKemEncapKeyAliasTest001";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genEncapParams001, sizeof(g_genEncapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encapParamSet = nullptr;
    ret = InitParamSet(&encapParamSet, g_encapParams001, sizeof(g_encapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encap) failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(&keyAlias, encapParamSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncapsulate failed.";

    EXPECT_NE(encapResult.encapsulatedData.data, nullptr);
    EXPECT_EQ(encapResult.encapsulatedData.size, (uint32_t)HKS_ML_KEM_768_CIPHERTEXT_LEN);
    EXPECT_NE(encapResult.sharedSecret.data, nullptr);
    EXPECT_EQ(encapResult.sharedSecret.size, (uint32_t)HKS_ML_KEM_SHARED_SECRET_LEN);

    FreeHksEncapsulationResult(&encapResult);

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest002
 * @tc.desc: alg-ML-KEM-768 encapsulate then decapsulate, verify sharedSecret matches.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest002, TestSize.Level0)
{
    char encapKeyAlias[] = "HksMlKemEncapKeyAliasTest002";
    char decapKeyAlias[] = "HksMlKemDecapKeyAliasTest002";
    struct HksBlob encapKeyAliasBlob = { (uint32_t)strlen(encapKeyAlias), (uint8_t *)encapKeyAlias };
    struct HksBlob decapKeyAliasBlob = { (uint32_t)strlen(decapKeyAlias), (uint8_t *)decapKeyAlias };

    struct HksParamSet *genEncapParamSet = nullptr;
    int32_t ret = InitParamSet(&genEncapParamSet, g_genEncapParams001, sizeof(g_genEncapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(genEncap) failed.";

    struct HksParamSet *genDecapParamSet = nullptr;
    ret = InitParamSet(&genDecapParamSet, g_genDecapParams001, sizeof(g_genDecapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(genDecap) failed.";

    struct HksParamSet *encapParamSet = nullptr;
    ret = InitParamSet(&encapParamSet, g_encapParams001, sizeof(g_encapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encap) failed.";

    struct HksParamSet *decapParamSet = nullptr;
    ret = InitParamSet(&decapParamSet, g_decapParams001, sizeof(g_decapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decap) failed.";

    ret = HksGenerateKey(&encapKeyAliasBlob, genEncapParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey(encap) failed.";

    ret = HksGenerateKey(&decapKeyAliasBlob, genDecapParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey(decap) failed.";

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(&decapKeyAliasBlob, encapParamSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncapsulate failed.";

    EXPECT_EQ(encapResult.encapsulatedData.size, (uint32_t)HKS_ML_KEM_768_CIPHERTEXT_LEN);
    EXPECT_EQ(encapResult.sharedSecret.size, (uint32_t)HKS_ML_KEM_SHARED_SECRET_LEN);

    uint8_t decapSharedSecretData[HKS_ML_KEM_SHARED_SECRET_LEN] = { 0 };
    struct HksBlob decapSharedSecret = { HKS_ML_KEM_SHARED_SECRET_LEN, decapSharedSecretData };

    ret = HksDecapsulate(&decapKeyAliasBlob, decapParamSet, nullptr, nullptr, &decapSharedSecret);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDecapsulate failed.";

    EXPECT_EQ(memcmp(encapResult.sharedSecret.data, decapSharedSecret.data, HKS_ML_KEM_SHARED_SECRET_LEN), 0)
        << "sharedSecret mismatch after decapsulate.";

    FreeHksEncapsulationResult(&encapResult);

    ret = HksDeleteKey(&encapKeyAliasBlob, genEncapParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&decapKeyAliasBlob, genDecapParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genEncapParamSet);
    HksFreeParamSet(&genDecapParamSet);
    HksFreeParamSet(&encapParamSet);
    HksFreeParamSet(&decapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest003
 * @tc.desc: alg-ML-KEM-1024 encapsulate with sharedKeyParamSet containing KEY_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest003, TestSize.Level0)
{
    char decapKeyAlias[] = "HksMlKemEncapKeyAliasTest003";
    char sharedKeyAlias[] = "HksMlKemSharedKeyAliasTest003";
    struct HksBlob decapKeyAliasBlob = { (uint32_t)strlen(decapKeyAlias), (uint8_t *)decapKeyAlias };
    struct HksBlob sharedKeyAliasBlob = { (uint32_t)strlen(sharedKeyAlias), (uint8_t *)sharedKeyAlias };

    struct HksParamSet *genDecapParamSet = nullptr;
    int32_t ret = InitParamSet(&genDecapParamSet, g_genDecapParams002, sizeof(g_genDecapParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(genDecap) failed.";

    struct HksParamSet *encapParamSet = nullptr;
    ret = InitParamSet(&encapParamSet, g_encapParams002, sizeof(g_encapParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encap) failed.";

    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = InitParamSet(&sharedKeyParamSet, g_sharedKeyParams001, sizeof(g_sharedKeyParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(sharedKey) failed.";

    ret = HksGenerateKey(&decapKeyAliasBlob, genDecapParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey(decap) failed.";

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(&decapKeyAliasBlob, encapParamSet, &sharedKeyAliasBlob, sharedKeyParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncapsulate with sharedKeyParamSet failed.";

    FreeHksEncapsulationResult(&encapResult);

    ret = HksDeleteKey(&decapKeyAliasBlob, genDecapParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&sharedKeyAliasBlob, sharedKeyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genDecapParamSet);
    HksFreeParamSet(&encapParamSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest004
 * @tc.desc: HksEncapsulate with sharedKeyParamSet missing HKS_TAG_KEY_SIZE, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest004, TestSize.Level0)
{
    char decapKeyAlias[] = "HksMlKemEncapKeyAliasTest004";
    struct HksBlob decapKeyAliasBlob = { (uint32_t)strlen(decapKeyAlias), (uint8_t *)decapKeyAlias };

    struct HksParamSet *genDecapParamSet = nullptr;
    int32_t ret = InitParamSet(&genDecapParamSet, g_genDecapParams001, sizeof(g_genDecapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(genDecap) failed.";

    struct HksParamSet *encapParamSet = nullptr;
    ret = InitParamSet(&encapParamSet, g_encapParams001, sizeof(g_encapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encap) failed.";

    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = InitParamSet(&sharedKeyParamSet, g_sharedKeyParamsNoKeySize, sizeof(g_sharedKeyParamsNoKeySize) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(sharedKey no keySize) failed.";

    ret = HksGenerateKey(&decapKeyAliasBlob, genDecapParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(&decapKeyAliasBlob, encapParamSet, nullptr, sharedKeyParamSet, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS) << "HksEncapsulate should fail without KEY_SIZE in sharedKeyParamSet.";

    ret = HksDeleteKey(&decapKeyAliasBlob, genDecapParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genDecapParamSet);
    HksFreeParamSet(&encapParamSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest005
 * @tc.desc: HksEncapsulate with null keyAlias, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest005, TestSize.Level0)
{
    struct HksParamSet *encapParamSet = nullptr;
    int32_t ret = InitParamSet(&encapParamSet, g_encapParams001, sizeof(g_encapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encap) failed.";

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(nullptr, encapParamSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksEncapsulate null keyAlias check failed.";

    HksFreeParamSet(&encapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest006
 * @tc.desc: HksEncapsulate with null paramSet, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest006, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksMlKemEncapKeyAliasTest006";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genEncapParams001, sizeof(g_genEncapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(&keyAlias, nullptr, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksEncapsulate null paramSet check failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest007
 * @tc.desc: HksEncapsulate with null encapResult, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest007, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksMlKemEncapKeyAliasTest007";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genEncapParams001, sizeof(g_genEncapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *encapParamSet = nullptr;
    ret = InitParamSet(&encapParamSet, g_encapParams001, sizeof(g_encapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksEncapsulate(&keyAlias, encapParamSet, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksEncapsulate null encapResult check failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest008
 * @tc.desc: HksDecapsulate with null keyAlias, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest008, TestSize.Level0)
{
    struct HksParamSet *decapParamSet = nullptr;
    int32_t ret = InitParamSet(&decapParamSet, g_decapParams001, sizeof(g_decapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t decapData[HKS_ML_KEM_SHARED_SECRET_LEN] = { 0 };
    struct HksBlob decapBlob = { HKS_ML_KEM_SHARED_SECRET_LEN, decapData };

    ret = HksDecapsulate(nullptr, decapParamSet, nullptr, nullptr, &decapBlob);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksDecapsulate null keyAlias check failed.";

    HksFreeParamSet(&decapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest009
 * @tc.desc: HksDecapsulate with null paramSet, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest009, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksMlKemDecapKeyAliasTest009";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genDecapParams001, sizeof(g_genDecapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t decapData[HKS_ML_KEM_SHARED_SECRET_LEN] = { 0 };
    struct HksBlob decapBlob = { HKS_ML_KEM_SHARED_SECRET_LEN, decapData };

    ret = HksDecapsulate(&keyAlias, nullptr, nullptr, nullptr, &decapBlob);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksDecapsulate null paramSet check failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest010
 * @tc.desc: HksDecapsulate with null encapOrsharedSecret, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest010, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksMlKemDecapKeyAliasTest010";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genDecapParams001, sizeof(g_genDecapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *decapParamSet = nullptr;
    ret = InitParamSet(&decapParamSet, g_decapParams001, sizeof(g_decapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksDecapsulate(&keyAlias, decapParamSet, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksDecapsulate null encapOrsharedSecret check failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&decapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest011
 * @tc.desc: FreeHksEncapsulationResult with null, expect no crash.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest011, TestSize.Level0)
{
    FreeHksEncapsulationResult(nullptr);
    EXPECT_EQ(1, 1);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest012
 * @tc.desc: FreeHksEncapsulationResult with valid result after Encapsulate, verify cleanup.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest012, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksMlKemEncapKeyAliasTest012";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genEncapParams001, sizeof(g_genEncapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *encapParamSet = nullptr;
    ret = InitParamSet(&encapParamSet, g_encapParams001, sizeof(g_encapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(&keyAlias, encapParamSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeHksEncapsulationResult(&encapResult);
    EXPECT_EQ(encapResult.encapsulatedData.size, 0);
    EXPECT_EQ(encapResult.sharedSecret.size, 0);

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest013
 * @tc.desc: alg-ML-KEM-1024 encapsulate with null shared key (dummy path).
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest013, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksMlKemEncapKeyAliasTest013";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genEncapParams002, sizeof(g_genEncapParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *encapParamSet = nullptr;
    ret = InitParamSet(&encapParamSet, g_encapParams002, sizeof(g_encapParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulate(&keyAlias, encapParamSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    EXPECT_EQ(encapResult.encapsulatedData.size, (uint32_t)HKS_ML_KEM_1024_CIPHERTEXT_LEN);

    FreeHksEncapsulationResult(&encapResult);

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encapParamSet);
}

/**
 * @tc.name: HksMlKemEncapTest.HksMlKemEncapTest014
 * @tc.desc: HksDecapsulate with sharedKeyParamSet missing KEY_SIZE, expect error.
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemEncapTest, HksMlKemEncapTest014, TestSize.Level0)
{
    char decapKeyAlias[] = "HksMlKemDecapKeyAliasTest014";
    struct HksBlob decapKeyAliasBlob = { (uint32_t)strlen(decapKeyAlias), (uint8_t *)decapKeyAlias };

    struct HksParamSet *genDecapParamSet = nullptr;
    int32_t ret = InitParamSet(&genDecapParamSet, g_genDecapParams001, sizeof(g_genDecapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *decapParamSet = nullptr;
    ret = InitParamSet(&decapParamSet, g_decapParams001, sizeof(g_decapParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = InitParamSet(&sharedKeyParamSet, g_sharedKeyParamsNoKeySize, sizeof(g_sharedKeyParamsNoKeySize) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&decapKeyAliasBlob, genDecapParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t decapData[HKS_ML_KEM_SHARED_SECRET_LEN] = { 0 };
    struct HksBlob decapBlob = { HKS_ML_KEM_SHARED_SECRET_LEN, decapData };

    ret = HksDecapsulate(&decapKeyAliasBlob, decapParamSet, nullptr, sharedKeyParamSet, &decapBlob);
    EXPECT_NE(ret, HKS_SUCCESS) << "HksDecapsulate should fail without KEY_SIZE in sharedKeyParamSet.";

    ret = HksDeleteKey(&decapKeyAliasBlob, genDecapParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&genDecapParamSet);
    HksFreeParamSet(&decapParamSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

#endif // HKS_UNTRUSTED_RUNNING_ENV
#endif // L2_STANDARD
} // namespace Unittest::MlKemEncap