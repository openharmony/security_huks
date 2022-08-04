/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hks_attest_key_nonids_test.h"

#include <gtest/gtest.h>

#include "hks_attest_key_test_common.h"

using namespace testing::ext;
namespace Unittest::AttestKey {
static struct HksBlob g_secInfo = { sizeof(SEC_INFO_DATA), (uint8_t *)SEC_INFO_DATA };
static struct HksBlob g_challenge = { sizeof(CHALLENGE_DATA), (uint8_t *)CHALLENGE_DATA };
static struct HksBlob g_version = { sizeof(VERSION_DATA), (uint8_t *)VERSION_DATA };

class HksAttestKeyNonIdsTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAttestKeyNonIdsTest::SetUpTestCase(void)
{
}

void HksAttestKeyNonIdsTest::TearDownTestCase(void)
{
}

void HksAttestKeyNonIdsTest::SetUp()
{
}

void HksAttestKeyNonIdsTest::TearDown()
{
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest001
 * @tc.desc: attest and get cert suc.
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest001, TestSize.Level0)
{
    struct HksBlob keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    int32_t ret = TestGenerateKey(&keyAlias);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksParam commonParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias },
    };
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, commonParams, sizeof(commonParams) / sizeof(commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&keyAlias, paramSet, certChain);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksAttestKey fail, ret is %d!", ret);
    }
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HKS_LOG_I("Attest key success!");
    ret = ValidateCertChainTest(certChain, commonParams, NON_IDS_PARAM);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HKS_LOG_I("Validate key success!");
    FreeCertChain(&certChain, certChain->certsCount);
    certChain = NULL;

    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&keyAlias, NULL);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest002
 * @tc.desc: attest without cert data.
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest002, TestSize.Level0)
{
    struct HksBlob keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    int32_t ret = TestGenerateKey(&keyAlias);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksParam commonParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias },
    };
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, commonParams, sizeof(commonParams) / sizeof(commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { true, true, false, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&keyAlias, paramSet, certChain);;
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    FreeCertChain(&certChain, certChain->certsCount);
    certChain = NULL;

    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&keyAlias, NULL);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest003
 * @tc.desc: attest without cert count.
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest003, TestSize.Level0)
{
    struct HksBlob keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    int32_t ret = TestGenerateKey(&keyAlias);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksParam commonParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias },
    };
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, commonParams, sizeof(commonParams) / sizeof(commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { true, false, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&keyAlias, paramSet, certChain);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    FreeCertChain(&certChain, certChain->certsCount);

    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&keyAlias, NULL);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest002
 * @tc.desc: attest without cert chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest004, TestSize.Level0)
{
    struct HksBlob keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    int32_t ret = TestGenerateKey(&keyAlias);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksParam commonParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias },
    };
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, commonParams, sizeof(commonParams) / sizeof(commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { false, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&keyAlias, paramSet, certChain);;
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
    if (certChain != NULL) {
        FreeCertChain(&certChain, certChain->certsCount);
    }

    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&keyAlias, NULL);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest002
 * @tc.desc: attest with base64.
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest005, TestSize.Level0)
{
    struct HksBlob keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    int32_t ret = TestGenerateKey(&keyAlias);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksParam commonParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias },
        { .tag = HKS_TAG_ATTESTATION_BASE64, .boolParam = true },

    };
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, commonParams, sizeof(commonParams) / sizeof(commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&keyAlias, paramSet, certChain);

    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = ValidateCertChainTest(certChain, commonParams, NON_IDS_PARAM);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    FreeCertChain(&certChain, certChain->certsCount);
    certChain = NULL;

    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&keyAlias, NULL);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}
}
