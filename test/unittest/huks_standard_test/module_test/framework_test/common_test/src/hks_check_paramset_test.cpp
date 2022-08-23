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

#include "hks_check_paramset_test.h"

#include <gtest/gtest.h>

#include "hks_check_paramset.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksFrameworkCommonCheckParamsetTest {
class HksCheckParamsetTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCheckParamsetTest::SetUpTestCase(void)
{
}

void HksCheckParamsetTest::TearDownTestCase(void)
{
}

void HksCheckParamsetTest::SetUp()
{
}

void HksCheckParamsetTest::TearDown()
{
}

struct HksCoreCheckMacParamsParam {
    struct HksBlob *key;
    struct HksParamSet *paramSet;
    struct HksBlob *srcData;
    struct HksBlob *mac;
    bool isLocalCheck;
    int32_t expectResult;
};

const static int32_t g_nonexistTag = -2;  /* for param not exist */
const static int32_t g_invalidTag = -1;  /* for param contains invalid values */
const static int32_t g_normalTag = 0;  /* for correct param */

static int32_t InsertDigestAccordingTag(int32_t paramTagDigest, struct HksParamSet *newParamSet)
{
    int32_t ret;
    if (paramTagDigest == g_invalidTag) {
        struct HksParam digest = { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE };
        ret = HksAddParams(newParamSet, &digest, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTagDigest == g_normalTag) {
        struct HksParam digest = { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 };
        ret = HksAddParams(newParamSet, &digest, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t InsertPurposeAccordingTagForCheckMac(int32_t paramTagPurpose, struct HksParamSet *newParamSet)
{
    int32_t ret;
    if (paramTagPurpose == g_invalidTag) {
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTagPurpose == g_normalTag) {
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t BuildHksCoreCheckMacParamsTestParamSet(int32_t paramTagPurpose, int32_t paramTagDigest,
    struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = HksInitParamSet(&newParamSet);
    ret = InsertPurposeAccordingTagForCheckMac(paramTagPurpose, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertPurposeAccordingTagForCheckMac failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = InsertDigestAccordingTag(paramTagDigest, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertDigestAccordingTag failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("add params failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    *outParamSet = newParamSet;
    return HKS_SUCCESS;
}

const static uint32_t g_sha256Len = 32;

static void HksCoreCheckMacParamsTest(struct HksCoreCheckMacParamsParam *param)
{
    int32_t ret = HksCoreCheckMacParams(param->key, param->paramSet, param->srcData, param->mac, true);
    EXPECT_EQ(ret, param->expectResult) << "HksGetBlobFromWrappedDataTest failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest001
 * @tc.desc: tdd HksCoreCheckMacParams, make test with nonexist purpose, expecting HKS_ERROR_CHECK_GET_PURPOSE_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest001");
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_nonexistTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param1 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_CHECK_GET_PURPOSE_FAIL};
    HksCoreCheckMacParamsTest(&param1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest002
 * @tc.desc: tdd HksCoreCheckMacParams, make test with invalid purpose, expecting HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest002");
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_invalidTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param2 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_INVALID_PURPOSE};
    HksCoreCheckMacParamsTest(&param2);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest003
 * @tc.desc: tdd HksCoreCheckMacParams, make test with nonexist digest, expecting HKS_ERROR_CHECK_GET_DIGEST_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest003");
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_nonexistTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param3 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_CHECK_GET_DIGEST_FAIL};
    HksCoreCheckMacParamsTest(&param3);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest004
 * @tc.desc: tdd HksCoreCheckMacParams, make test with invalid digest, expecting HKS_ERROR_INVALID_DIGEST
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest004");
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_invalidTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param4 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_INVALID_DIGEST};
    HksCoreCheckMacParamsTest(&param4);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest005
 * @tc.desc: tdd HksCoreCheckMacParams, make test with too small macBlob, expecting HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest005");
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    uint8_t macData[g_sha256Len - 1];
    struct HksBlob macBlob = { g_sha256Len - 1, macData };
    struct HksCoreCheckMacParamsParam param5 = { NULL, paramSet, NULL, &macBlob, true, HKS_ERROR_BUFFER_TOO_SMALL};
    HksCoreCheckMacParamsTest(&param5);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest006
 * @tc.desc: tdd HksCoreCheckMacParams, make test with too small keyBlob, expecting HKS_ERROR_INVALID_KEY_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest006");
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    uint8_t macData2[g_sha256Len];
    struct HksBlob macBlob2 = { g_sha256Len, macData2 };
    uint8_t keyData[g_sha256Len - 1];
    struct HksBlob keyBlob = { g_sha256Len - 1, keyData };
    struct HksCoreCheckMacParamsParam param6 = { &keyBlob, paramSet, NULL, &macBlob2, true, HKS_ERROR_INVALID_KEY_SIZE};
    HksCoreCheckMacParamsTest(&param6);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest006
 * @tc.desc: tdd HksCoreCheckMacParams, make test with correct params, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest007");
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    uint8_t macData2[g_sha256Len];
    struct HksBlob macBlob2 = { g_sha256Len, macData2 };
    uint8_t keyData2[g_sha256Len];
    struct HksBlob keyBlob2 = { g_sha256Len, keyData2 };
    struct HksCoreCheckMacParamsParam param7 = { &keyBlob2, paramSet, NULL, &macBlob2, true, HKS_SUCCESS};
    HksCoreCheckMacParamsTest(&param7);
    HksFreeParamSet(&paramSet);
}

static int32_t InsertIteAccordingTag(int32_t paramTagIte, struct HksParamSet *newParamSet)
{
    int32_t ret;
    if (paramTagIte == g_invalidTag) {
        struct HksParam ite = { .tag = HKS_TAG_ITERATION, .uint32Param = 0 };
        ret = HksAddParams(newParamSet, &ite, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTagIte == g_normalTag) {
        struct HksParam ite = { .tag = HKS_TAG_ITERATION, .uint32Param = 1000 };
        ret = HksAddParams(newParamSet, &ite, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t InsertSaltAccordingTag(int32_t paramTagSalt, struct HksParamSet *newParamSet, struct HksBlob *saltBlob)
{
    int32_t ret;
    if (paramTagSalt == g_invalidTag) {
        struct HksParam salt = { .tag = HKS_TAG_SALT, .blob = { 1, saltBlob->data } };
        ret = HksAddParams(newParamSet, &salt, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTagSalt == g_normalTag) {
        struct HksParam salt = { .tag = HKS_TAG_SALT, .blob = { saltBlob->size, saltBlob->data } };
        ret = HksAddParams(newParamSet, &salt, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

const static uint32_t g_pbkdf2SaltSize = 16;

struct HksCoreCheckDeriveKeyParamsTagParam {
    int32_t paramTagAlg;
    int32_t paramTagPurpose;
    int32_t paramTagDigest;
    int32_t paramTagIte;
    int32_t paramTagSalt;
};

static int32_t InsertAlgAccordingTagForCheckDeriveKey(int32_t paramTagAlg, struct HksParamSet *newParamSet)
{
    int32_t ret;
    if (paramTagAlg == g_invalidTag) {
        struct HksParam alg = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA };
        ret = HksAddParams(newParamSet, &alg, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTagAlg == g_normalTag) {
        struct HksParam alg = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_PBKDF2 };
        ret = HksAddParams(newParamSet, &alg, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t InsertPurposeAccordingTagForCheckDeriveKey(int32_t paramTagPurpose, struct HksParamSet *newParamSet)
{
    int32_t ret;
    if (paramTagPurpose == g_invalidTag) {
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTagPurpose == g_normalTag) {
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t BuildHksCoreCheckDeriveKeyParamsTestParamSet(const struct HksCoreCheckDeriveKeyParamsTagParam *param,
    struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = HksInitParamSet(&newParamSet);
    ret = InsertAlgAccordingTagForCheckDeriveKey(param->paramTagAlg, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertAlgAccordingTagForCheckDeriveKey failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = InsertPurposeAccordingTagForCheckDeriveKey(param->paramTagPurpose, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertPurposeAccordingTagForCheckDeriveKey failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = InsertIteAccordingTag(param->paramTagIte, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertIteAccordingTag failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = InsertDigestAccordingTag(param->paramTagDigest, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertDigestAccordingTag failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    uint8_t *saltData = (uint8_t *)HksMalloc(g_pbkdf2SaltSize);
    struct HksBlob saltBlob = { g_pbkdf2SaltSize, saltData};
    ret = InsertSaltAccordingTag(param->paramTagSalt, newParamSet, &saltBlob);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertSaltAccordingTag failed");
        HksFree(saltData);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksBuildParamSet failed");
        HksFree(saltData);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    HksFree(saltData);
    *outParamSet = newParamSet;
    return HKS_SUCCESS;
}

static void HksCoreCheckDeriveKeyParamsTest(struct HksCoreCheckDeriveKeyParamsTagParam *tagParam, int32_t expectResult)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckDeriveKeyParamsTestParamSet(tagParam, &paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckDeriveKeyParamsTestParamSet failed, ret = " << ret;
    ret = HksCoreCheckDeriveKeyParams(paramSet, NULL, NULL, false);
    EXPECT_EQ(ret, expectResult) << "HksCoreCheckDeriveKeyParams failed, ret = " << ret;
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest008
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with nonexist alg, expecting HKS_ERROR_CHECK_GET_ALG_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest008");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam1 = { g_nonexistTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam1, HKS_ERROR_CHECK_GET_ALG_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest009
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with invalid alg, expecting HKS_ERROR_INVALID_ALGORITHM
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest009");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam2 = { g_invalidTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam2, HKS_ERROR_INVALID_ALGORITHM);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest010
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with nonexist purpose, expecting
 *           HKS_ERROR_CHECK_GET_PURPOSE_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest010");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam3 = { g_normalTag, g_nonexistTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam3, HKS_ERROR_CHECK_GET_PURPOSE_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest011
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with invalid purpose, expecting
 *           HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest011");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam4 = { g_normalTag, g_invalidTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam4, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest012
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with nonexist digest, expecting
 *           HKS_ERROR_CHECK_GET_DIGEST_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest012");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam5 = { g_normalTag, g_normalTag, g_nonexistTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam5, HKS_ERROR_CHECK_GET_DIGEST_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest013
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with invalid digest, expecting
 *           HKS_ERROR_INVALID_DIGEST
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest013");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam6 = { g_normalTag, g_normalTag, g_invalidTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam6, HKS_ERROR_INVALID_DIGEST);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest014
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with nonexist iteration, expecting
 *           HKS_ERROR_CHECK_GET_ITERATION_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest014");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam7 = { g_normalTag, g_normalTag, g_normalTag, g_nonexistTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam7, HKS_ERROR_CHECK_GET_ITERATION_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest015
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with invalid iteration, expecting
 *           HKS_ERROR_INVALID_ITERATION
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest015");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam8 = { g_normalTag, g_normalTag, g_normalTag, g_invalidTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam8, HKS_ERROR_INVALID_ITERATION);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest016
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with nonexist salt, expecting
 *           HKS_ERROR_CHECK_GET_SALT_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest016");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam9 = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_nonexistTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam9, HKS_ERROR_CHECK_GET_SALT_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest017
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with invalid salt, expecting
 *           HKS_ERROR_INVALID_SALT
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest017");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam10 = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_invalidTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam10, HKS_ERROR_INVALID_SALT);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest018
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make test with correct params, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest018");
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam11 = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam11, HKS_SUCCESS);
}

struct HksLocalCheckCipherParamsTagParam {
    int32_t paramTagAlg;
    int32_t paramTagPadding;
    int32_t paramTagPurpose;
    int32_t paramTagMode;
    int32_t paramTagIv;
    bool isAes;
    bool isEncrypt;
};

static int32_t InsertAlgAccordingTagForLocalCheckCipher(int32_t paramTag, struct HksParamSet *newParamSet,
    bool isAes)
{
    int32_t ret;
    if (paramTag == g_invalidTag) {
        struct HksParam alg = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_PBKDF2 };
        ret = HksAddParams(newParamSet, &alg, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTag == g_normalTag) {
        uint32_t algUint = isAes ? HKS_ALG_AES : HKS_ALG_RSA;
        struct HksParam alg = { .tag = HKS_TAG_ALGORITHM, .uint32Param = algUint };
        ret = HksAddParams(newParamSet, &alg, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t InsertPaddingAccordingTagForAes(int32_t paramTag, struct HksParamSet *newParamSet)
{
    int32_t ret;
    if (paramTag == g_invalidTag) {
        struct HksParam padding = { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 };
        ret = HksAddParams(newParamSet, &padding, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTag == g_normalTag) {
        struct HksParam padding = { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE };
        ret = HksAddParams(newParamSet, &padding, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t InsertPurposeAccordingTagForLocalCheckCipher(int32_t paramTag, struct HksParamSet *newParamSet,
    bool isEncrypt)
{
    int32_t ret;
    if (paramTag == g_invalidTag) {
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTag == g_normalTag) {
        uint32_t purposeUint = isEncrypt ? HKS_KEY_PURPOSE_ENCRYPT : HKS_KEY_PURPOSE_DECRYPT;
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = purposeUint };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t InsertModeAccordingTagForAes(int32_t paramTag, struct HksParamSet *newParamSet)
{
    int32_t ret;
    if (paramTag == g_invalidTag) {
        struct HksParam mode = { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_OFB };
        ret = HksAddParams(newParamSet, &mode, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTag == g_normalTag) {
        struct HksParam mode = { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC };
        ret = HksAddParams(newParamSet, &mode, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

const static uint32_t g_ivLen = 16;

static int32_t InsertIvAccordingTagForAes(int32_t paramTag, struct HksParamSet *newParamSet, struct HksBlob *ivBlob)
{
    int32_t ret;
    if (paramTag == g_invalidTag) {
        struct HksParam iv = { .tag = HKS_TAG_IV, .blob = { 1, ivBlob->data } };
        ret = HksAddParams(newParamSet, &iv, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    } else if (paramTag == g_normalTag) {
        struct HksParam iv = { .tag = HKS_TAG_IV, .blob = { ivBlob->size, ivBlob->data } };
        ret = HksAddParams(newParamSet, &iv, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            return ret;
        }
    }
    return HKS_SUCCESS;
}

static int32_t BuildHksLocalCheckCipherParamsTestParamSet(const struct HksLocalCheckCipherParamsTagParam *param,
    struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = HksInitParamSet(&newParamSet);
    ret = InsertAlgAccordingTagForLocalCheckCipher(param->paramTagAlg, newParamSet, param->isAes);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertAlgAccordingTagForLocalCheckCipher failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = InsertPaddingAccordingTagForAes(param->paramTagPadding, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertPaddingAccordingTagForRsa failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = InsertPurposeAccordingTagForLocalCheckCipher(param->paramTagPurpose, newParamSet, param->isEncrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertPurposeAccordingTagForLocalCheckCipher failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = InsertModeAccordingTagForAes(param->paramTagMode, newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertModeAccordingTagForAes failed");
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    uint8_t *ivData = (uint8_t *)HksMalloc(g_ivLen);
    struct HksBlob ivBlob = { g_ivLen, ivData};
    ret = InsertIvAccordingTagForAes(param->paramTagIv, newParamSet, &ivBlob);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InsertIvAccordingTagForAes failed");
        HksFree(ivData);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksBuildParamSet failed");
        HksFree(ivData);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    HksFree(ivData);
    *outParamSet = newParamSet;
    return HKS_SUCCESS;
}

struct HksLocalCheckCipherParamsInputParams {
    struct HksLocalCheckCipherParamsTagParam *tagParam;
    uint32_t cmdId;
    uint32_t keySize;
    const struct HksBlob *inData;
    const struct HksBlob *outData;
};

static void HksLocalCheckCipherParamsTest(struct HksLocalCheckCipherParamsInputParams *inputParams,
    int32_t expectResult)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksLocalCheckCipherParamsTestParamSet(inputParams->tagParam, &paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckDeriveKeyParamsTestParamSet failed, ret = " << ret;

    ret = HksLocalCheckCipherParams(inputParams->cmdId, inputParams->keySize, paramSet, inputParams->inData,
        inputParams->outData);
    EXPECT_EQ(ret, expectResult) << "HksCoreCheckDeriveKeyParams failed, ret = " << ret;
    HksFreeParamSet(&paramSet);
}

#define HKS_CMD_ID_ENCRYPT 0x10E
#define HKS_CMD_ID_DECRYPT 0x112

const static uint32_t g_inValidAesInLen = 1;
const static uint32_t g_validAesInLen = 16;

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest019
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with nonexist alg, expecting
 *           HKS_ERROR_CHECK_GET_ALG_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest019");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_nonexistTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, 0, NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_CHECK_GET_ALG_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest020
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid alg, expecting
 *           HKS_ERROR_INVALID_ALGORITHM
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest020");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_invalidTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, 0, NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_ALGORITHM);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest021
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid key size for aes, expecting
 *           HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest021");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_RSA_KEY_SIZE_512,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_KEY_SIZE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest022
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid key size for rsa, expecting
 *           HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest022");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, false, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_192,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_KEY_SIZE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest023
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with nonexist padding, expecting
 *           HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest023");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_nonexistTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_CHECK_GET_PADDING_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest024
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with nonexist purpose, expecting
 *           HKS_ERROR_CHECK_GET_PURPOSE_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest024");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_nonexistTag, g_normalTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_CHECK_GET_PURPOSE_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest025
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with nonexist mode, expecting
 *           HKS_ERROR_CHECK_GET_MODE_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest025");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_nonexistTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_CHECK_GET_MODE_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest026
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with nonexist iv, expecting
 *           HKS_ERROR_CHECK_GET_IV_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest026");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_nonexistTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_CHECK_GET_IV_FAIL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest027
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid padding, expecting
 *           HKS_ERROR_INVALID_PADDING
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest027");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_invalidTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_PADDING);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest028
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid purpose, expecting
 *           HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest028");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_invalidTag, g_normalTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest029
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid mode, expecting
 *           HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest029");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_invalidTag,
        g_normalTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_MODE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest030
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid mode, expecting
 *           HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest030");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_invalidTag, true, true };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        NULL, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_IV);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest031
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid inData cause %16 != 0, expecting
 *           HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest031, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest031");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    uint8_t inUint8[g_inValidAesInLen];
    struct HksBlob inData = { g_inValidAesInLen, inUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        &inData, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest032
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid outData cause too small, expecting
 *           HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest032, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest032");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    uint8_t inUint8[g_validAesInLen];
    struct HksBlob inData = { g_validAesInLen, inUint8 };
    uint8_t outUint8[g_validAesInLen - 1];
    struct HksBlob outData = { g_validAesInLen - 1, outUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        &inData, &outData };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest033
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with correct params, expecting
 *           HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest033, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest033");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    uint8_t inUint8[g_validAesInLen];
    struct HksBlob inData = { g_validAesInLen, inUint8 };
    uint8_t outUint8[g_validAesInLen];
    struct HksBlob outData = { g_validAesInLen, outUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        &inData, &outData };
    HksLocalCheckCipherParamsTest(&params, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest034
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid inData cause %16 != 0 for HKS_CMD_ID_DECRYPT,
 *           expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest034, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest034");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, false };
    uint8_t inUint8[g_inValidAesInLen];
    struct HksBlob inData = { g_inValidAesInLen, inUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_DECRYPT, HKS_AES_KEY_SIZE_256,
        &inData, NULL };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest035
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with invalid outData cause too small for HKS_CMD_ID_DECRYPT,
 *           expecting HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest035, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest035");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, false };
    uint8_t inUint8[g_validAesInLen];
    struct HksBlob inData = { g_validAesInLen, inUint8 };
    uint8_t outUint8[g_validAesInLen - 1];
    struct HksBlob outData = { g_validAesInLen - 1, outUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_DECRYPT, HKS_AES_KEY_SIZE_256,
        &inData, &outData };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest036
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with correct params for HKS_CMD_ID_DECRYPT, expecting
 *           HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest036, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest036");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, false };
    uint8_t inUint8[g_validAesInLen];
    struct HksBlob inData = { g_validAesInLen, inUint8 };
    uint8_t outUint8[g_validAesInLen];
    struct HksBlob outData = { g_validAesInLen, outUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_DECRYPT, HKS_AES_KEY_SIZE_256,
        &inData, &outData };
    HksLocalCheckCipherParamsTest(&params, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest037
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with correct params but wrong purpose, expecting
 *           HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest037, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest037");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, false };
    uint8_t inUint8[g_validAesInLen];
    struct HksBlob inData = { g_validAesInLen, inUint8 };
    uint8_t outUint8[g_validAesInLen];
    struct HksBlob outData = { g_validAesInLen, outUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_ENCRYPT, HKS_AES_KEY_SIZE_256,
        &inData, &outData };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest038
 * @tc.desc: tdd HksLocalCheckCipherParams, make test with correct params  but wrong purpose for HKS_CMD_ID_DECRYPT,
 *           expecting HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest038, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest038");
    struct HksLocalCheckCipherParamsTagParam tagParam = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag, true, true };
    uint8_t inUint8[g_validAesInLen];
    struct HksBlob inData = { g_validAesInLen, inUint8 };
    uint8_t outUint8[g_validAesInLen];
    struct HksBlob outData = { g_validAesInLen, outUint8 };
    struct HksLocalCheckCipherParamsInputParams params = { &tagParam, HKS_CMD_ID_DECRYPT, HKS_AES_KEY_SIZE_256,
        &inData, &outData };
    HksLocalCheckCipherParamsTest(&params, HKS_ERROR_INVALID_PURPOSE);
}
}
