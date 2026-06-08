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

#include "hks_local_sign_verify_test.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::LocalSignVerify {

class HksLocalSignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksLocalSignVerifyTest::SetUpTestCase(void)
{
}

void HksLocalSignVerifyTest::TearDownTestCase(void)
{
}

void HksLocalSignVerifyTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksLocalSignVerifyTest::TearDown()
{
#ifdef L2_STANDARD
    std::system("find /data/service/el1/public/huks_service -user root -delete");
#endif
}

#ifdef L2_STANDARD

static struct HksParam g_rsaGenParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
};

static struct HksParam g_rsaSignParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
};

static struct HksParam g_rsaVerifyParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
};

static struct HksParam g_eccGenParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
};

static struct HksParam g_eccSignParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
};

static struct HksParam g_eccVerifyParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
};

static struct HksParam g_ed25519GenParams003[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::ED25519_KEY_SIZE_256 },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
};

static struct HksParam g_ed25519SignParams003[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::ED25519_KEY_SIZE_256 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
};

static struct HksParam g_ed25519VerifyParams003[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = Unittest::LocalSignVerify::ED25519_KEY_SIZE_256 },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
};

const uint32_t LOCAL_PARAMSET_SIZE = 4096;

static int32_t LocalSignVerify(const struct HksParam *genParams, uint32_t genParamCount,
    const struct HksParam *signParams, uint32_t signParamCount,
    const struct HksParam *verifyParams, uint32_t verifyParamCount,
    uint32_t signOutMaxSize)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, genParams, genParamCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    uint8_t paramSetOutBuffer[LOCAL_PARAMSET_SIZE] = { 0 };
    struct HksParamSet *paramSetOut = (struct HksParamSet *)paramSetOutBuffer;
    paramSetOut->paramSetSize = LOCAL_PARAMSET_SIZE;

    ret = HksGenerateKey(nullptr, genParamSet, paramSetOut);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey(local) failed.";
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return ret;
    }

    struct HksParam *priKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetPrivateKey failed.";
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return ret;
    }

    struct HksBlob privateKey = { priKeyParam->blob.size, (uint8_t *)HksMalloc(priKeyParam->blob.size) };
    EXPECT_NE(privateKey.data, nullptr);
    if (privateKey.data == nullptr) {
        HksFreeParamSet(&genParamSet);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(privateKey.data, privateKey.size, priKeyParam->blob.data, priKeyParam->blob.size);

    struct HksParam *pubKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetPublicKey failed.";
    if (ret != HKS_SUCCESS) {
        HKS_FREE_BLOB(privateKey);
        HksFreeParamSet(&genParamSet);
        return ret;
    }

    struct HksBlob publicKey = { pubKeyParam->blob.size, (uint8_t *)HksMalloc(pubKeyParam->blob.size) };
    EXPECT_NE(publicKey.data, nullptr);
    if (publicKey.data == nullptr) {
        HKS_FREE_BLOB(privateKey);
        HksFreeParamSet(&genParamSet);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(publicKey.data, publicKey.size, pubKeyParam->blob.data, pubKeyParam->blob.size);

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, signParams, signParamCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(sign) failed.";

    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t signOutData[signOutMaxSize] = { 0 };
    struct HksBlob signature = { signOutMaxSize, signOutData };

    ret = HksSign(&privateKey, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksSign(local) failed.";
    if (ret != HKS_SUCCESS) {
        HKS_FREE_BLOB(privateKey);
        HKS_FREE_BLOB(publicKey);
        HksFreeParamSet(&genParamSet);
        HksFreeParamSet(&signParamSet);
        return ret;
    }

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, verifyParams, verifyParamCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(verify) failed.";

    ret = HksVerify(&publicKey, verifyParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksVerify(local) failed.";

    HKS_FREE_BLOB(privateKey);
    HKS_FREE_BLOB(publicKey);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
    return ret;
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest001
 * @tc.desc: alg-RSA-2048 pur-SIGN/VERIFY pad-PSS digest-SHA256, IS_KEY_ALIAS=false local sign+verify.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest001, TestSize.Level0)
{
    int32_t ret = LocalSignVerify(g_rsaGenParams001, sizeof(g_rsaGenParams001) / sizeof(HksParam),
        g_rsaSignParams001, sizeof(g_rsaSignParams001) / sizeof(HksParam),
        g_rsaVerifyParams001, sizeof(g_rsaVerifyParams001) / sizeof(HksParam),
        Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 / HKS_BITS_PER_BYTE);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest002
 * @tc.desc: alg-ECC-256 pur-SIGN/VERIFY digest-SHA256, IS_KEY_ALIAS=false local sign+verify.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest002, TestSize.Level0)
{
    int32_t ret = LocalSignVerify(g_eccGenParams002, sizeof(g_eccGenParams002) / sizeof(HksParam),
        g_eccSignParams002, sizeof(g_eccSignParams002) / sizeof(HksParam),
        g_eccVerifyParams002, sizeof(g_eccVerifyParams002) / sizeof(HksParam),
        Unittest::LocalSignVerify::COMMON_SIZE);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest003
 * @tc.desc: alg-Ed25519 pur-SIGN/VERIFY, IS_KEY_ALIAS=false local sign+verify.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest003, TestSize.Level0)
{
    int32_t ret = LocalSignVerify(g_ed25519GenParams003, sizeof(g_ed25519GenParams003) / sizeof(HksParam),
        g_ed25519SignParams003, sizeof(g_ed25519SignParams003) / sizeof(HksParam),
        g_ed25519VerifyParams003, sizeof(g_ed25519VerifyParams003) / sizeof(HksParam),
        Unittest::LocalSignVerify::COMMON_SIZE);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest004
 * @tc.desc: HksSign with null key, IS_KEY_ALIAS=false, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest004, TestSize.Level0)
{
    struct HksParamSet *signParamSet = nullptr;
    int32_t ret = InitParamSet(&signParamSet, g_rsaSignParams001, sizeof(g_rsaSignParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t signOutData[Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 / HKS_BITS_PER_BYTE] = { 0 };
    struct HksBlob signature = { sizeof(signOutData), signOutData };

    ret = HksSign(nullptr, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest005
 * @tc.desc: HksSign with null paramSet, IS_KEY_ALIAS=false, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest005, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_rsaGenParams001, sizeof(g_rsaGenParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t paramSetOutBuffer[LOCAL_PARAMSET_SIZE] = { 0 };
    struct HksParamSet *paramSetOut = (struct HksParamSet *)paramSetOutBuffer;
    paramSetOut->paramSetSize = LOCAL_PARAMSET_SIZE;

    ret = HksGenerateKey(nullptr, genParamSet, paramSetOut);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParam *priKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob privateKey = { priKeyParam->blob.size, (uint8_t *)HksMalloc(priKeyParam->blob.size) };
    EXPECT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, privateKey.size, priKeyParam->blob.data, priKeyParam->blob.size);

    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t signOutData[Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 / HKS_BITS_PER_BYTE] = { 0 };
    struct HksBlob signature = { sizeof(signOutData), signOutData };

    ret = HksSign(&privateKey, nullptr, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HKS_FREE_BLOB(privateKey);
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest006
 * @tc.desc: HksVerify with null key, IS_KEY_ALIAS=false, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest006, TestSize.Level0)
{
    struct HksParamSet *verifyParamSet = nullptr;
    int32_t ret = InitParamSet(&verifyParamSet, g_rsaVerifyParams001, sizeof(g_rsaVerifyParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t fakeSign[64] = { 0 };
    struct HksBlob signature = { sizeof(fakeSign), fakeSign };

    ret = HksVerify(nullptr, verifyParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest007
 * @tc.desc: HksVerify with null paramSet, IS_KEY_ALIAS=false, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest007, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_rsaGenParams001, sizeof(g_rsaGenParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t paramSetOutBuffer[LOCAL_PARAMSET_SIZE] = { 0 };
    struct HksParamSet *paramSetOut = (struct HksParamSet *)paramSetOutBuffer;
    paramSetOut->paramSetSize = LOCAL_PARAMSET_SIZE;

    ret = HksGenerateKey(nullptr, genParamSet, paramSetOut);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParam *pubKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob publicKey = { pubKeyParam->blob.size, (uint8_t *)HksMalloc(pubKeyParam->blob.size) };
    EXPECT_NE(publicKey.data, nullptr);
    (void)memcpy_s(publicKey.data, publicKey.size, pubKeyParam->blob.data, pubKeyParam->blob.size);

    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t fakeSign[64] = { 0 };
    struct HksBlob signature = { sizeof(fakeSign), fakeSign };

    ret = HksVerify(&publicKey, nullptr, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HKS_FREE_BLOB(publicKey);
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest008
 * @tc.desc: HksSign with null srcData, IS_KEY_ALIAS=false, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest008, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_rsaGenParams001, sizeof(g_rsaGenParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t paramSetOutBuffer[LOCAL_PARAMSET_SIZE] = { 0 };
    struct HksParamSet *paramSetOut = (struct HksParamSet *)paramSetOutBuffer;
    paramSetOut->paramSetSize = LOCAL_PARAMSET_SIZE;

    ret = HksGenerateKey(nullptr, genParamSet, paramSetOut);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParam *priKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob privateKey = { priKeyParam->blob.size, (uint8_t *)HksMalloc(priKeyParam->blob.size) };
    EXPECT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, privateKey.size, priKeyParam->blob.data, priKeyParam->blob.size);

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_rsaSignParams001, sizeof(g_rsaSignParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t signOutData[Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 / HKS_BITS_PER_BYTE] = { 0 };
    struct HksBlob signature = { sizeof(signOutData), signOutData };

    ret = HksSign(&privateKey, signParamSet, nullptr, &signature);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HKS_FREE_BLOB(privateKey);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest009
 * @tc.desc: HksSign with null signature output, IS_KEY_ALIAS=false, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest009, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_rsaGenParams001, sizeof(g_rsaGenParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t paramSetOutBuffer[LOCAL_PARAMSET_SIZE] = { 0 };
    struct HksParamSet *paramSetOut = (struct HksParamSet *)paramSetOutBuffer;
    paramSetOut->paramSetSize = LOCAL_PARAMSET_SIZE;

    ret = HksGenerateKey(nullptr, genParamSet, paramSetOut);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParam *priKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob privateKey = { priKeyParam->blob.size, (uint8_t *)HksMalloc(priKeyParam->blob.size) };
    EXPECT_NE(privateKey.data, nullptr);
    (void)memcpy_s(privateKey.data, privateKey.size, priKeyParam->blob.data, priKeyParam->blob.size);

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_rsaSignParams001, sizeof(g_rsaSignParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };

    ret = HksSign(&privateKey, signParamSet, &inData, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HKS_FREE_BLOB(privateKey);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksLocalSignVerifyTest.HksLocalSignVerifyTest010
 * @tc.desc: HksSign local then verify with tampered data, expect failure.
 * @tc.type: FUNC
 */
HWTEST_F(HksLocalSignVerifyTest, HksLocalSignVerifyTest010, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_rsaGenParams001, sizeof(g_rsaGenParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint8_t paramSetOutBuffer[LOCAL_PARAMSET_SIZE] = { 0 };
    struct HksParamSet *paramSetOut = (struct HksParamSet *)paramSetOutBuffer;
    paramSetOut->paramSetSize = LOCAL_PARAMSET_SIZE;

    ret = HksGenerateKey(nullptr, genParamSet, paramSetOut);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParam *priKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA, &priKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob privateKey = { priKeyParam->blob.size, (uint8_t *)HksMalloc(priKeyParam->blob.size) };
    (void)memcpy_s(privateKey.data, privateKey.size, priKeyParam->blob.data, priKeyParam->blob.size);

    struct HksParam *pubKeyParam = nullptr;
    ret = HksGetParam(paramSetOut, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pubKeyParam);
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob publicKey = { pubKeyParam->blob.size, (uint8_t *)HksMalloc(pubKeyParam->blob.size) };
    (void)memcpy_s(publicKey.data, publicKey.size, pubKeyParam->blob.data, pubKeyParam->blob.size);

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_rsaSignParams001, sizeof(g_rsaSignParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t signOutData[Unittest::LocalSignVerify::RSA_KEY_SIZE_2048 / HKS_BITS_PER_BYTE] = { 0 };
    struct HksBlob signature = { sizeof(signOutData), signOutData };

    ret = HksSign(&privateKey, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS);

    signature.data[0] = ~signature.data[0];

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_rsaVerifyParams001, sizeof(g_rsaVerifyParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksVerify(&publicKey, verifyParamSet, &inData, &signature);
    EXPECT_NE(ret, HKS_SUCCESS) << "Verify should fail with tampered signature.";

    HKS_FREE_BLOB(privateKey);
    HKS_FREE_BLOB(publicKey);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

#endif // L2_STANDARD
} // namespace Unittest::LocalSignVerify