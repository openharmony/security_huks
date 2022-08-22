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

const static int32_t g_nonexistTag = -2;
const static int32_t g_invalidTag = -1;
const static int32_t g_normalTag = 0;

static int32_t BuildHksCoreCheckMacParamsTestParamSet(int32_t paramTagPurpose, int32_t paramTagDigest,
    struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = HksInitParamSet(&newParamSet);
    if (paramTagPurpose == g_invalidTag) {
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            HksFreeParamSet(&newParamSet);
            return ret;
        }
    } else if (paramTagPurpose == g_normalTag) {
        struct HksParam purpose = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC };
        ret = HksAddParams(newParamSet, &purpose, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            HksFreeParamSet(&newParamSet);
            return ret;
        }
    }
    if (paramTagDigest == g_invalidTag) {
        struct HksParam digest = { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE };
        ret = HksAddParams(newParamSet, &digest, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            HksFreeParamSet(&newParamSet);
            return ret;
        }
    } else if (paramTagDigest == g_normalTag) {
        struct HksParam digest = { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 };
        ret = HksAddParams(newParamSet, &digest, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add params failed");
            HksFreeParamSet(&newParamSet);
            return ret;
        }
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
 * @tc.desc: tdd HksCoreCheckMacParams
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
}
