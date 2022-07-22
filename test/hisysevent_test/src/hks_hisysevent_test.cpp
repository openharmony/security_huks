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

#include "hks_hisysevent_test.h"

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_hisysevent_test_common.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"

namespace OHOS {
namespace Security {
namespace Huks {

using namespace testing::ext;

static const uint32_t TEST_DATA_SIZE = 2048;
static const uint8_t TEST_CERT_COUNT = 4;

static const char g_genKeyAlias[] = "hksHiSysEventTestKey";
static const char g_plainText[] = "hksHiSysEventTestPlain";

struct HksParam g_abnormalParams[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR },
};

struct HksParam g_normalParams[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
};

static int32_t BuildParamSet(const struct HksParam *params, uint32_t paramCnt, struct HksParamSet **tmpParamSetOut)
{
    int32_t ret;
    ret = HksInitParamSet(tmpParamSetOut);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init paramSet failed");
        return ret;
    }

    ret = HksAddParams(*tmpParamSetOut, params, paramCnt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("add params failed");
        HksFreeParamSet(tmpParamSetOut);
        return ret;
    }

    ret = HksBuildParamSet(tmpParamSetOut);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("build paramSet failed");
        HksFreeParamSet(tmpParamSetOut);
        return ret;
    }

    return HKS_SUCCESS;
}

class HksHiSysEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHiSysEventTest::SetUpTestCase(void)
{
}

void HksHiSysEventTest::TearDownTestCase(void)
{
}

void HksHiSysEventTest::SetUp()
{

}

void HksHiSysEventTest::TearDown()
{
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest001
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceKeyExist'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest001, TestSize.Level0)
{
    HksHiSysEventQueryStart();
    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    (void)HksKeyExist(&keyAlias, nullptr);
    int ret = HksHiSysEventQueryResult("HksServiceKeyExist");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest002
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceGenerateKey' and 'HksServiceDeleteKey'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest002, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    (void)HksGenerateKey(&keyAlias, paramInSet, nullptr);

    ret = HksHiSysEventQueryResult("HksServiceGenerateKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksDeleteKey(&keyAlias, paramInSet);
    ret = HksHiSysEventQueryResult("HksServiceDeleteKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest003
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceSign' and 'HksServiceVerify'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest003, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    struct HksBlob inData = { (uint32_t)strlen(g_plainText), (uint8_t *)g_plainText };
    uint8_t sign[TEST_DATA_SIZE] = {0};
    struct HksBlob signedData = { TEST_DATA_SIZE, sign };
    (void)HksSign(&keyAlias, paramInSet, &inData, &signedData);

    ret = HksHiSysEventQueryResult("HksServiceSign");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksVerify(&keyAlias, paramInSet, &inData, &signedData);
    ret = HksHiSysEventQueryResult("HksServiceVerify");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest004
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceEncrypt' and 'HksServiceDecrypt'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest004, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    struct HksBlob inData = { (uint32_t)strlen(g_plainText), (uint8_t *)g_plainText };
    uint8_t cipherData[TEST_DATA_SIZE] = {0};
    struct HksBlob cipherText = { TEST_DATA_SIZE, cipherData };
    (void)HksEncrypt(&keyAlias, paramInSet, &inData, &cipherText);

    ret = HksHiSysEventQueryResult("HksServiceEncrypt");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksDecrypt(&keyAlias, paramInSet, &inData, &cipherText);
    ret = HksHiSysEventQueryResult("HksServiceDecrypt");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest005
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceGetKeyParamSet' and 'HksServiceGenerateRandom'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest005, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    uint8_t data[TEST_DATA_SIZE] = {0};
    struct HksBlob inData = { TEST_DATA_SIZE, data };

    (void)HksGetKeyParamSet(&keyAlias, nullptr, paramInSet);

    ret = HksHiSysEventQueryResult("HksServiceGetKeyParamSet");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksGenerateRandom(paramInSet, &inData);
    ret = HksHiSysEventQueryResult("HksServiceGenerateRandom");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest006
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceExportPublicKey' and 'HksServiceImportKey'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest006, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    uint8_t publicData[TEST_DATA_SIZE] = {0};
    struct HksBlob publicKey = { TEST_DATA_SIZE, publicData };

    (void)HksExportPublicKey(&keyAlias, paramInSet, &publicKey);

    ret = HksHiSysEventQueryResult("HksServiceExportPublicKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksImportKey(&keyAlias, paramInSet, &publicKey);
    ret = HksHiSysEventQueryResult("HksServiceImportKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest007
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceImportWrappedKey' and 'HksServiceAgreeKey'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest007, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    uint8_t data[TEST_DATA_SIZE] = {0};
    struct HksBlob inData = { TEST_DATA_SIZE, data };

    (void)HksImportWrappedKey(&keyAlias, &keyAlias, paramInSet, &inData);

    ret = HksHiSysEventQueryResult("HksServiceImportWrappedKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksAgreeKey(paramInSet, &keyAlias, &keyAlias, &keyAlias);
    ret = HksHiSysEventQueryResult("HksServiceAgreeKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest008
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceDeriveKey' and 'HksServiceMac'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest008, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    uint8_t data[TEST_DATA_SIZE] = {0};
    struct HksBlob inData = { TEST_DATA_SIZE, data };

    (void)HksDeriveKey(paramInSet, &keyAlias, &inData);

    ret = HksHiSysEventQueryResult("HksServiceDeriveKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksMac(&keyAlias, paramInSet, &inData, &inData);
    ret = HksHiSysEventQueryResult("HksServiceMac");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest009
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceInit', 'HksServiceUpdate' and 'HksServiceFinish'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest009, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    uint8_t data[TEST_DATA_SIZE] = {0};
    struct HksBlob inData = { TEST_DATA_SIZE, data };

    (void)HksInit(&keyAlias, paramInSet, &inData, NULL);

    ret = HksHiSysEventQueryResult("HksServiceInit");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksUpdate(&inData, paramInSet, &inData, &inData);
    ret = HksHiSysEventQueryResult("HksServiceUpdate");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksHiSysEventQueryStart();
    (void)HksFinish(&inData, paramInSet, &inData, &inData);
    ret = HksHiSysEventQueryResult("HksServiceFinish");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    HksFreeParamSet(&paramInSet);
}

static void FreeCertChain(struct HksCertChain **certChain, const uint32_t pos)
{
    if (certChain == nullptr || *certChain == nullptr) {
        return;
    }

    if ((*certChain)->certs == nullptr) {
        HKS_FREE_PTR(*certChain);
        return;
    }

    for (uint32_t j = 0; j < pos; j++) {
        if ((*certChain)->certs[j].data != nullptr) {
            HKS_FREE_PTR((*certChain)->certs[j].data);
        }
    }

    if ((*certChain)->certs != nullptr) {
        HKS_FREE_PTR((*certChain)->certs);
    }

    if (*certChain != nullptr) {
        HKS_FREE_PTR(*certChain);
    }
}

static int32_t ConstructCertChain(struct HksCertChain **certChain)
{
    *certChain = (struct HksCertChain *)HksMalloc(sizeof(struct HksCertChain));
    if (*certChain == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    (*certChain)->certsCount = TEST_CERT_COUNT;

    (*certChain)->certs = (struct HksBlob *)HksMalloc(sizeof(struct HksBlob) * ((*certChain)->certsCount));
    if ((*certChain)->certs == nullptr) {
        HKS_FREE_PTR(*certChain);
        return HKS_ERROR_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < (*certChain)->certsCount; i++) {
        (*certChain)->certs[i].size = TEST_DATA_SIZE;
        (*certChain)->certs[i].data = (uint8_t *)HksMalloc((*certChain)->certs[i].size);
        if ((*certChain)->certs[i].data == nullptr) {
            FreeCertChain(certChain, i);
            return HKS_ERROR_MALLOC_FAIL;
        }
    }
    return HKS_SUCCESS;
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest010
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'HksServiceAttestKey'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest010, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_abnormalParams, sizeof(g_abnormalParams) / sizeof(g_abnormalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    HksCertChain *certChain = nullptr;
    ret = ConstructCertChain(&certChain);
    EXPECT_EQ(ret, HKS_SUCCESS) << "construct certChain failed";

    (void)HksAttestKey(&keyAlias, paramInSet, certChain);

    ret = HksHiSysEventQueryResult("HksServiceAttestKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

    FreeCertChain(&certChain, TEST_CERT_COUNT);
    HksFreeParamSet(&paramInSet);
}

/**
 * @tc.name: HksHiSysEventTest.HksHiSysEventTest011
 * @tc.desc: the normal test is for hisysevent;
             the test interface is 'HksServiceGenerateKey'.
 * @tc.type: FUNC
 */
HWTEST_F(HksHiSysEventTest, HksHiSysEventTest011, TestSize.Level0)
{
    HksHiSysEventQueryStart();

    struct HksBlob keyAlias = { (uint32_t)strlen(g_genKeyAlias), (uint8_t *)g_genKeyAlias };
    struct HksParamSet *paramInSet = nullptr;
    int ret;
    ret = BuildParamSet(g_normalParams, sizeof(g_normalParams) / sizeof(g_normalParams[0]), &paramInSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "create paramSet failed, ret = " << ret;

    (void)HksGenerateKey(&keyAlias, paramInSet, nullptr);

    ret = HksHiSysEventQueryResult("HksServiceGenerateKey");
    EXPECT_EQ(ret, HKS_HISYSEVENT_QUERY_FAILED) << "query failed, ret = " << ret;

    (void)HksDeleteKey(&keyAlias, paramInSet);

    HksFreeParamSet(&paramInSet);
}

}  // namespace Huks
}  // namespace Security
}  // namespace OHOS