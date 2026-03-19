/*
 * Copyright (C) 2026-2026 Huawei Device Co., Ltd.
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

#include "hks_type_enum.h"
#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "securec.h"
#include "hks_attest_key_test_common.h"
#include "hks_test_adapt_for_de.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "hks_mock_common.h"
#include "hks_api.h"
#include "hks_template.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_service_ipc_serialization.h"
#include "hks_type.h"

using namespace testing::ext;

namespace Unittest {
namespace AnonLocalAttestKey {

static struct ::HksBlob g_secInfo = { sizeof("hi_security_level_info"), (uint8_t *)"hi_security_level_info" };
static struct ::HksBlob g_challenge = { sizeof("hi_challenge_data"), (uint8_t *)"hi_challenge_data" };
static struct ::HksBlob g_version = { sizeof("hi_os_version_data"), (uint8_t *)"hi_os_version_data" };
static const struct ::HksBlob g_keyAlias = { sizeof("testKey"), (uint8_t *)"testKey" };

static const struct ::HksParam g_commonParams[] = {
    { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
    { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
    { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
    { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
};

class HksAnonLocalAttestKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

static uint64_t g_shellTokenId = 0;

void HksAnonLocalAttestKeyTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksAnonLocalAttestKeyTest::TearDownTestCase(void)
{
    SetSelfTokenID(g_shellTokenId);
    HksMockCommon::ResetTestEvironment();
}

void HksAnonLocalAttestKeyTest::SetUp()
{
}

void HksAnonLocalAttestKeyTest::TearDown()
{
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest001
 * @tc.desc: Verify interface availability with valid params, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest001");

    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest002
 * @tc.desc: Test with NULL keyAlias, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest002");
    
    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    ret = HksAnonAttestKeyOffline(nullptr, paramSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest003
 * @tc.desc: Test with NULL paramSet, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest003");
    
    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, nullptr, certChain);
    
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest004
 * @tc.desc: Test with NULL certChain, expect HKS_ERROR_NULL_POINTER.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest004");
    
    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *) ALIAS };
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, paramSet, nullptr);
    
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER);
    
    HksFreeParamSet(&paramSet);
    
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest005
 * @tc.desc: Test with incomplete paramSet (missing HKS_TAG_ATTESTATION_CHALLENGE), expect HKS_ERROR_INVALID_ARGUMENT.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest005");
    
    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParam incompleteParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
    };
    
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, incompleteParams, sizeof(incompleteParams) / sizeof(incompleteParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_ERROR_PARAM_NOT_EXIST);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest006
 * @tc.desc: Test with incomplete paramSet (missing HKS_TAG_ATTESTATION_ID_VERSION_INFO), expect HKS_ERROR_INVALID_ARGUMENT.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest006");
    
    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParam incompleteParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
    };
    
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, incompleteParams, sizeof(incompleteParams) / sizeof(incompleteParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest007
 * @tc.desc: Test with non-existent keyAlias, expect HKS_ERROR_READ_FILE_FAIL.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest007");
    
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const char *nonExistentAlias = "non_existent_key_test_12345";
    const struct HksBlob oh_nonExistentKeyAlias = { strlen(nonExistentAlias), (uint8_t *)nonExistentAlias };
    struct HksParamSet *newParamSet = nullptr;
    int32_t ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_nonExistentKeyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);
    HksFreeParamSet(&newParamSet);
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest008
 * @tc.desc: Test with unavaliable param, expect HKS_ERROR_INVALID_ARGUMENT.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest008");
    
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    static const struct ::HksParam unavaliableParams[] = {
    { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
    { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
    { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
    { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
    { .tag = HKS_TAG_ANONYMOUS_ATTESTATION_MODE, .uint32Param = HKS_ANONYMOUS_ATTEST_ONLNE}};
    Unittest::AttestKey::GenerateParamSet(&paramSet, unavaliableParams, sizeof(unavaliableParams) / sizeof(unavaliableParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_nonExistentKeyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_nonExistentKeyAlias, newParamSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_NEW_INVALID_ARGUMENT);
    HksFreeParamSet(&newParamSet);
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest009
 * @tc.desc: Test with HKS_TAG_ANONYMOUS_ATTESTATION_MODE, expect SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest009");
    
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;

    int32_t ret = Unittest::AttestKey::TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    static const struct ::HksParam unavaliableParams[] = {
    { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
    { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
    { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
    { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
    { .tag = HKS_TAG_ANONYMOUS_ATTESTATION_MODE, .uint32Param = HKS_ANONYMOUS_ATTEST_OFFLINE}};
    Unittest::AttestKey::GenerateParamSet(&paramSet, unavaliableParams, sizeof(unavaliableParams) / sizeof(unavaliableParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_nonExistentKeyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_nonExistentKeyAlias, newParamSet, certChain);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest010
 * @tc.desc: RSA 2048 + SHA256 + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest010");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest011
 * @tc.desc: RSA 2048 + SHA384 + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest011");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest012
 * @tc.desc: RSA 2048 + SHA512 + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest012");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest013
 * @tc.desc: RSA 2048 + SHA256 + PSS, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest013");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest014
 * @tc.desc: RSA 2048 + SHA384 + PSS, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest014");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest015
 * @tc.desc: RSA 2048 + SHA512 + PSS, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest015");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest016
 * @tc.desc: RSA 2048 + NoDigest + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest016");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest017
 * @tc.desc: RSA 3072 + SHA256 + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest017");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest018
 * @tc.desc: RSA 3072 + SHA256 + PSS, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest018");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest019
 * @tc.desc: RSA 3072 + SHA512 + PSS, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest019");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest020
 * @tc.desc: RSA 3072 + NoDigest + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest020");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest021
 * @tc.desc: RSA 4096 + SHA256 + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest021");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest022
 * @tc.desc: RSA 4096 + SHA256 + PSS, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest022");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest023
 * @tc.desc: RSA 4096 + SHA512 + PSS, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest023");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest024
 * @tc.desc: RSA 4096 + NoDigest + PKCS1_V1_5, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest024");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest025
 * @tc.desc: ECC P-256 + SHA256, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest025");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest026
 * @tc.desc: ECC P-384 + SHA384, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest026");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_384 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest027
 * @tc.desc: ECC P-521 + SHA512, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest027");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest028
 * @tc.desc: ED25519 + NoDigest, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest028");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256},
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest029
 * @tc.desc: SM2 + SM3, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest029");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256},
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAnonLocalAttestKeyTest.HksAnonLocalAttestKeyTest030
 * @tc.desc: SM2 + NoDigest, expect HKS_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAnonLocalAttestKeyTest, HksAnonLocalAttestKeyTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksAnonLocalAttestKeyTest030");
    
    struct HksParamSet *genParamSet = nullptr;
    HksInitParamSet(&genParamSet);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256},
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = (uint32_t)(HKS_AUTH_STORAGE_LEVEL_DE) },
    };
    HksAddParams(genParamSet, genParams, (uint32_t)(sizeof(genParams) / sizeof(genParams[0])));
    HksBuildParamSet(&genParamSet);
    int32_t ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    struct HksParamSet *paramSet = nullptr;
    Unittest::AttestKey::GenerateParamSet(&paramSet, g_commonParams, (uint32_t)(sizeof(g_commonParams) / sizeof(g_commonParams[0])));
    HksCertChain *certChain = nullptr;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)Unittest::AttestKey::ConstructDataToCertChain(&certChain, &certParam);
    
    const struct HksBlob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    struct HksParamSet *newParamSet = nullptr;
    ret = ConstructNewParamSet(paramSet, &newParamSet);
    ret = HksAnonAttestKeyOffline(&oh_g_keyAlias, newParamSet, certChain);
    
    ASSERT_EQ(ret, HKS_SUCCESS);
    
    Unittest::AttestKey::FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&genParamSet);
    ret = HksDeleteKeyForDe(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}
}
}