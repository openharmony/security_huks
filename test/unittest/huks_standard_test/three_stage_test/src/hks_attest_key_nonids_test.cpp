/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_attest_key_test_common.h"
#include "native_huks_api.h"
#include "native_huks_type.h"

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

static const struct HksBlob g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };

static const struct HksParam g_commonParams[] = {
    { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
    { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
    { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
    { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
};

#ifndef TEMP_ISOLATION
static const uint32_t g_keyParamsetSize = 1024;

static void ValidateCertChain(struct HksParamSet *paramSet, struct HksParamSet *paramOutSet,
    HksCertChain *certChain)
{
    struct HksParam g_getParam = {
        .tag = HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA,
        .blob = { .size = g_keyParamsetSize, .data = (uint8_t *)HksMalloc(g_keyParamsetSize) }
    };
    ASSERT_NE(g_getParam.blob.data, nullptr);
    struct HksParam *keySizeParam = nullptr;
    uint32_t rootUid = 0;
    HksInitParamSet(&paramOutSet);
    HksAddParams(paramOutSet, &g_getParam, 1);
    HksBuildParamSet(&paramOutSet);
    HKS_FREE(g_getParam.blob.data);
    int32_t ret = HksGetKeyParamSet(&g_keyAlias, nullptr, paramOutSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksGetParam(paramOutSet, HKS_TAG_KEY_SIZE, &keySizeParam);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(keySizeParam->uint32Param, HKS_RSA_KEY_SIZE_2048);
    struct HksParam *processParam = nullptr;
    ret = HksGetParam(paramOutSet, HKS_TAG_PROCESS_NAME, &processParam);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(sizeof(rootUid), processParam->blob.size);
    ASSERT_EQ(HksMemCmp(processParam->blob.data, &rootUid, processParam->blob.size), HKS_SUCCESS);

    HksFreeParamSet(&paramOutSet);

    ret = ValidateCertChainTest(certChain, g_commonParams, NON_IDS_PARAM);
    FreeCertChain(&certChain, certChain->certsCount);
    certChain = nullptr;

    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&g_keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
}
#endif

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest001
 * @tc.desc: attest with right params and validate success.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest001, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    HKS_LOG_I("enter HksAttestKeyNonIdsTest001");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&g_keyAlias, paramSet, certChain);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksAttestKey fail, ret is %" LOG_PUBLIC "d!", ret);
    }
    ASSERT_EQ(ret, HKS_ERROR_NO_PERMISSION);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest002
 * @tc.desc: attest without cert data and fail.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestKeyNonIdsTest002");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParamSet *paramSet = NULL;
    HksCertChain *certChain = NULL;
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, false, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&g_keyAlias, paramSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    FreeCertChain(&certChain, certChain->certsCount);
    certChain = NULL;

    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAnonAttestKey(&g_keyAlias, paramSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
    FreeCertChain(&certChain, certChain->certsCount);
    certChain = NULL;
    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest003
 * @tc.desc: attest without cert count and fail.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestKeyNonIdsTest003");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { true, false, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&g_keyAlias, paramSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    FreeCertChain(&certChain, certChain->certsCount);

    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAnonAttestKey(&g_keyAlias, paramSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    FreeCertChain(&certChain, certChain->certsCount);
    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest004
 * @tc.desc: attest without cert chain and fail.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestKeyNonIdsTest004");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { false, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&g_keyAlias, paramSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER);
    if (certChain != NULL) {
        FreeCertChain(&certChain, certChain->certsCount);
    }

    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAnonAttestKey(&g_keyAlias, paramSet, certChain);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER);
    if (certChain != NULL) {
        FreeCertChain(&certChain, certChain->certsCount);
    }

    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest005
 * @tc.desc: attest with base64 and validate success.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestKeyNonIdsTest005");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam g_commonParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
        { .tag = HKS_TAG_ATTESTATION_BASE64, .boolParam = true },
    };
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&g_keyAlias, paramSet, certChain);

    ASSERT_EQ(ret, HKS_ERROR_NO_PERMISSION);
    ret = ValidateCertChainTest(certChain, g_commonParams, NON_IDS_BASE64_PARAM);

    FreeCertChain(&certChain, certChain->certsCount);
    certChain = NULL;
    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest007
 * @tc.desc: attest with device id and expect HKS_ERROR_NO_PERMISSION
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestKeyNonIdsTest007");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    static struct HksBlob dId = { sizeof(DEVICE_ID), (uint8_t *)DEVICE_ID };
    struct HksParam g_commonParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
        { .tag = HKS_TAG_ATTESTATION_ID_DEVICE, .blob = dId },
        { .tag = HKS_TAG_ATTESTATION_BASE64, .boolParam = true },
    };
    struct HksParamSet *paramSet = NULL;
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    HksCertChain *certChain = NULL;
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&g_keyAlias, paramSet, certChain);

    ASSERT_EQ(ret, HKS_ERROR_NO_PERMISSION);

    FreeCertChain(&certChain, certChain->certsCount);
    certChain = NULL;
    HksFreeParamSet(&paramSet);

    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest008
 * @tc.desc: attest with right params(use pksc1_v1_5 for padding) and validate success.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest008, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    HKS_LOG_I("enter HksAttestKeyNonIdsTest008");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PKCS1_V1_5);
    ASSERT_EQ(ret, HKS_SUCCESS);
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAttestKey(&g_keyAlias, paramSet, certChain);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksAttestKey fail, ret is %" LOG_PUBLIC "d!", ret);
    }
    ASSERT_EQ(ret, HKS_ERROR_NO_PERMISSION);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest009
 * @tc.desc: attest with right params and validate success.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest009, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    HKS_LOG_I("enter HksAttestKeyNonIdsTest009");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAnonAttestKey(&g_keyAlias, paramSet, certChain);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksAnonAttestKey fail, ret is %" LOG_PUBLIC "d!", ret);
    }
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest010
 * @tc.desc: attest with right params(use pksc1_v1_5 for padding) and validate success.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest010, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    HKS_LOG_I("enter HksAttestKeyNonIdsTest010");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PKCS1_V1_5);
    ASSERT_EQ(ret, HKS_SUCCESS);
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    ret = HksAnonAttestKey(&g_keyAlias, paramSet, certChain);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksAnonAttestKey fail, ret is %" LOG_PUBLIC "d!", ret);
    }
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest011
 * @tc.desc: attest with right params.
 * @tc.type: FUNC
 * @tc.require: issueI5NY0L
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest011, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    HKS_LOG_I("enter HksAttestKeyNonIdsTest011");
    int32_t ret = TestGenerateKey(&g_keyAlias, HKS_PADDING_PSS);
    ASSERT_EQ(ret, HKS_SUCCESS);
    GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    (void)ConstructDataToCertChain(&certChain, &certParam);
    const struct OH_Huks_Blob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    ret = OH_Huks_AnonAttestKeyItem(&oh_g_keyAlias, (struct OH_Huks_ParamSet *) paramSet,
        (struct OH_Huks_CertChain *) certChain).errorCode;
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("OH_Huks_AnonAttestKeyItem fail, ret is %" LOG_PUBLIC "d!", ret);
    }
    ASSERT_EQ(ret, HKS_SUCCESS);
    for (uint32_t i = 0; i < certChain->certsCount; i++) {
        printf("Get certChain[%d]:\n %s \n", i, certChain->certs[i].data);
    }
    FreeCertChain(&certChain, certChain->certsCount);
    HksFreeParamSet(&paramSet);
    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest012
 * @tc.desc: attest ECC with right params.
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest012, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    HKS_LOG_I("enter HksAttestKeyNonIdsTest012");
    const struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    };
    int32_t ret = TestGenerateKeyCommon(&g_keyAlias, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    ret = ConstructDataToCertChain(&certChain, &certParam);
    ASSERT_EQ(ret, HKS_SUCCESS);
    const struct OH_Huks_Blob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    ret = OH_Huks_AnonAttestKeyItem(&oh_g_keyAlias, (struct OH_Huks_ParamSet *) paramSet,
        (struct OH_Huks_CertChain *) certChain).errorCode;
    HKS_LOG_I("OH_Huks_AnonAttestKeyItem, ret is %" LOG_PUBLIC "d!", ret);
    ASSERT_EQ(ret, HKS_SUCCESS);
    for (uint32_t i = 0; i < certChain->certsCount; i++) {
        printf("Get certChain[%d]:\n %s \n", i, certChain->certs[i].data);
    }
    FreeCertChain(&certChain, certChain->certsCount);
    HksFreeParamSet(&paramSet);
    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksAttestKeyNonIdsTest.HksAttestKeyNonIdsTest013
 * @tc.desc: attest with right params.
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestKeyNonIdsTest, HksAttestKeyNonIdsTest013, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    HksCertChain *certChain = nullptr;
    HKS_LOG_I("enter HksAttestKeyNonIdsTest013");
    const struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3},
    };
    int32_t ret = TestGenerateKeyCommon(&g_keyAlias, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = GenerateParamSet(&paramSet, g_commonParams, sizeof(g_commonParams) / sizeof(g_commonParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    const struct HksTestCertChain certParam = { true, true, true, g_size };
    ret = ConstructDataToCertChain(&certChain, &certParam);
    ASSERT_EQ(ret, HKS_SUCCESS);
    const struct OH_Huks_Blob oh_g_keyAlias = { sizeof(ALIAS), (uint8_t *)ALIAS };
    ret = OH_Huks_AnonAttestKeyItem(&oh_g_keyAlias, (struct OH_Huks_ParamSet *) paramSet,
        (struct OH_Huks_CertChain *) certChain).errorCode;
    HKS_LOG_I("OH_Huks_AnonAttestKeyItem, ret is %" LOG_PUBLIC "d!", ret);
    ASSERT_EQ(ret, HKS_SUCCESS);
    for (uint32_t i = 0; i < certChain->certsCount; i++) {
        printf("Get certChain[%d]:\n %s \n", i, certChain->certs[i].data);
    }
    FreeCertChain(&certChain, certChain->certsCount);
    HksFreeParamSet(&paramSet);
    ret = HksDeleteKey(&g_keyAlias, NULL);
    ASSERT_EQ(ret, HKS_SUCCESS);
}
}
