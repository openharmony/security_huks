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

class HksFrameworkCommonCheckParamsetTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFrameworkCommonCheckParamsetTest::SetUpTestCase(void)
{
}

void HksFrameworkCommonCheckParamsetTest::TearDownTestCase(void)
{
}

void HksFrameworkCommonCheckParamsetTest::SetUp()
{
}

void HksFrameworkCommonCheckParamsetTest::TearDown()
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
 * @tc.name: HksFrameworkCommonCheckParamsetTest.HksFrameworkCommonCheckParamsetTest001
 * @tc.desc: tdd HksCoreCheckMacParams, make tests for all branches
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkCommonCheckParamsetTest, HksFrameworkCommonCheckParamsetTest001, TestSize.Level0)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = BuildHksCoreCheckMacParamsTestParamSet(g_nonexistTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param1 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_CHECK_GET_PURPOSE_FAIL};
    HksCoreCheckMacParamsTest(&param1);

    HksFreeParamSet(&paramSet);
    ret = BuildHksCoreCheckMacParamsTestParamSet(g_invalidTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param2 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_INVALID_PURPOSE};
    HksCoreCheckMacParamsTest(&param2);

    HksFreeParamSet(&paramSet);
    ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_nonexistTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param3 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_CHECK_GET_DIGEST_FAIL};
    HksCoreCheckMacParamsTest(&param3);

    HksFreeParamSet(&paramSet);
    ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_invalidTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;
    struct HksCoreCheckMacParamsParam param4 = { NULL, paramSet, NULL, NULL, true, HKS_ERROR_INVALID_DIGEST};
    HksCoreCheckMacParamsTest(&param4);

    HksFreeParamSet(&paramSet);
    ret = BuildHksCoreCheckMacParamsTestParamSet(g_normalTag, g_normalTag, &paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildHksCoreCheckMacParamsTestParamSet failed, ret = " << ret;

    uint8_t macData[g_sha256Len - 1];
    struct HksBlob macBlob = { g_sha256Len - 1, macData };
    struct HksCoreCheckMacParamsParam param5 = { NULL, paramSet, NULL, &macBlob, true, HKS_ERROR_BUFFER_TOO_SMALL};
    HksCoreCheckMacParamsTest(&param5);

    uint8_t macData2[g_sha256Len];
    struct HksBlob macBlob2 = { g_sha256Len, macData2 };
    uint8_t keyData[g_sha256Len - 1];
    struct HksBlob keyBlob = { g_sha256Len - 1, keyData };
    struct HksCoreCheckMacParamsParam param6 = { &keyBlob, paramSet, NULL, &macBlob2, true, HKS_ERROR_INVALID_KEY_SIZE};
    HksCoreCheckMacParamsTest(&param6);

    uint8_t keyData2[g_sha256Len];
    struct HksBlob keyBlob2 = { g_sha256Len, keyData2 };
    struct HksCoreCheckMacParamsParam param7 = { &keyBlob2, paramSet, NULL, &macBlob2, true, HKS_SUCCESS};
    HksCoreCheckMacParamsTest(&param7);

    HksFreeParamSet(&paramSet);
}

struct HksCoreCheckDeriveKeyParamsParam {
    struct HksParamSet *paramSet;
    struct HksBlob *mainKey;
    struct HksBlob *derivedKey;
    int32_t expectResult;
};

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
    struct HksCoreCheckDeriveKeyParamsParam param = { paramSet, NULL, NULL, expectResult};

    ret = HksCoreCheckDeriveKeyParams(param.paramSet, param.mainKey, param.derivedKey, false);
    EXPECT_EQ(ret, param.expectResult) << "HksCoreCheckDeriveKeyParams failed, ret = " << ret;
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkCommonCheckParamsetTest.HksFrameworkCommonCheckParamsetTest002
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams, make tests for all branches
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkCommonCheckParamsetTest, HksFrameworkCommonCheckParamsetTest002, TestSize.Level0)
{
    struct HksCoreCheckDeriveKeyParamsTagParam tagParam1 = { g_nonexistTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam1, HKS_ERROR_CHECK_GET_ALG_FAIL);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam2 = { g_invalidTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam2, HKS_ERROR_INVALID_ALGORITHM);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam3 = { g_normalTag, g_nonexistTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam3, HKS_ERROR_CHECK_GET_PURPOSE_FAIL);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam4 = { g_normalTag, g_invalidTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam4, HKS_ERROR_INVALID_PURPOSE);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam5 = { g_normalTag, g_normalTag, g_nonexistTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam5, HKS_ERROR_CHECK_GET_DIGEST_FAIL);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam6 = { g_normalTag, g_normalTag, g_invalidTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam6, HKS_ERROR_INVALID_DIGEST);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam7 = { g_normalTag, g_normalTag, g_normalTag, g_nonexistTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam7, HKS_ERROR_CHECK_GET_ITERATION_FAIL);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam8 = { g_normalTag, g_normalTag, g_normalTag, g_invalidTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam8, HKS_ERROR_INVALID_ITERATION);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam9 = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_nonexistTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam9, HKS_ERROR_CHECK_GET_SALT_FAIL);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam10 = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_invalidTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam10, HKS_ERROR_INVALID_SALT);

    struct HksCoreCheckDeriveKeyParamsTagParam tagParam11 = { g_normalTag, g_normalTag, g_normalTag, g_normalTag,
        g_normalTag };
    HksCoreCheckDeriveKeyParamsTest(&tagParam11, HKS_SUCCESS);
}
}
