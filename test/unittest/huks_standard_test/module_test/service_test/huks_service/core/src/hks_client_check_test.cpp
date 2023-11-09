/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_client_check_test.h"

#include <gtest/gtest.h>
#include <cstring>

#include "file_ex.h"
#include "hks_log.h"
#include "hks_type_inner.h"
#include "hks_param.h"

#include "hks_client_check.h"

using namespace testing::ext;
namespace Unittest::HksClientCheckTest {
class HksClientCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksClientCheckTest::SetUpTestCase(void)
{
}

void HksClientCheckTest::TearDownTestCase(void)
{
}

void HksClientCheckTest::SetUp()
{
}

void HksClientCheckTest::TearDown()
{
}

static int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramcount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksAddParams failed");
        HksFreeParamSet(paramSet);
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksBuildParamSet failed!");
        HksFreeParamSet(paramSet);
        return ret;
    }

    return ret;
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest001
 * @tc.desc: tdd HksCheckGetKeyParamSetParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest001");
    const char *nameData = "name";
    const char *aliasData = "alias";
    struct HksBlob processName = { .size = strlen(nameData), .data = (uint8_t *)nameData};
    struct HksBlob aliasName = { .size = strlen(aliasData), .data = (uint8_t *)aliasData};
    int32_t ret = HksCheckGetKeyParamSetParams(&processName, &aliasName, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest002
 * @tc.desc: tdd HksCheckGetKeyParamSetParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest002");
    const char *nameData = "name";
    const char *aliasData = "alias";
    struct HksBlob processName = { .size = strlen(nameData), .data = (uint8_t *)nameData};
    struct HksBlob aliasName = { .size = strlen(aliasData), .data = (uint8_t *)aliasData};
    struct HksParamSet paramSet = { 0 };
    paramSet.paramSetSize = 0;
    int32_t ret = HksCheckGetKeyParamSetParams(&processName, &aliasName, &paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest003
 * @tc.desc: tdd HksCheckGetKeyInfoListParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest003");
    const char *nameData = "name";
    struct HksBlob processName = { .size = strlen(nameData), .data = (uint8_t *)nameData};
    struct HksKeyInfo keyInfo;
    uint32_t cnt = 0;
    processName.size = HKS_MAX_PROCESS_NAME_LEN + 1;
    int32_t ret = HksCheckGetKeyInfoListParams(&processName, &keyInfo, &cnt);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest004
 * @tc.desc: tdd HksCheckGetKeyInfoListParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest004");
    const char *nameData = "name";
    struct HksBlob processName = { .size = strlen(nameData), .data = (uint8_t *)nameData};
    uint32_t cnt = 0;
    int32_t ret = HksCheckGetKeyInfoListParams(&processName, nullptr, &cnt);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest005
 * @tc.desc: tdd HksCheckGetKeyInfoListParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest005");
    const char *nameData = "name";
    struct HksBlob processName = { .size = strlen(nameData), .data = (uint8_t *)nameData};
    struct HksKeyInfo keyInfo;
    int32_t ret = HksCheckGetKeyInfoListParams(&processName, &keyInfo, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest006
 * @tc.desc: tdd HksCheckGenerateRandomParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest006");
    const char *nameData = "name";
    struct HksBlob processName = { .size = strlen(nameData), .data = (uint8_t *)nameData};
    const uint32_t ramdomSize = 16;
    uint8_t randomData[ramdomSize] = { 0 };
    struct HksBlob random = { .size = sizeof(randomData), .data = (uint8_t *)randomData};
    processName.size = HKS_MAX_PROCESS_NAME_LEN + 1;
    int32_t ret = HksCheckGenerateRandomParams(&processName, &random);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest007
 * @tc.desc: tdd HksCheckGenerateRandomParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest007");
    const char *nameData = "name";
    struct HksBlob processName = { .size = strlen(nameData), .data = (uint8_t *)nameData};
    const uint32_t ramdomSize = 16;
    uint8_t randomData[ramdomSize] = { 0 };
    struct HksBlob random = { .size = sizeof(randomData), .data = (uint8_t *)randomData};
    random.size = HKS_MAX_RANDOM_LEN + 1;
    int32_t ret = HksCheckGenerateRandomParams(&processName, &random);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest008
 * @tc.desc: tdd HksCheckAndGetUserAuthInfo, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest008");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam noAuth = { .tag = HKS_TAG_NO_AUTH_REQUIRED, .boolParam = true };
    ret = HksAddParams(paramSet, &noAuth, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckAndGetUserAuthInfo(paramSet, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest009
 * @tc.desc: tdd HksCheckAndGetUserAuthInfo, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest009");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam noAuth = { .tag = HKS_TAG_NO_AUTH_REQUIRED, .boolParam = false };
    ret = HksAddParams(paramSet, &noAuth, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckAndGetUserAuthInfo(paramSet, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest010
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, not set HKS_TAG_KEY_AUTH_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest010");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_RSA
        }
    };
    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest011
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set invalid HKS_TAG_KEY_AUTH_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest011");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_SIGN
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_RSA
        }
    };
    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}


/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest012
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set valid HKS_TAG_KEY_AUTH_PURPOSE for RSA
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest012");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_RSA
        }
    };
    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest013
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set valid HKS_TAG_KEY_AUTH_PURPOSE for AES CBC
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest013");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }, {
            .tag = HKS_TAG_BLOCK_MODE,
            .uint32Param = HKS_MODE_CBC
        }
    };

    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest014
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set valid HKS_TAG_KEY_AUTH_PURPOSE for AES GCM
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest014");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }, {
            .tag = HKS_TAG_BLOCK_MODE,
            .uint32Param = HKS_MODE_CTR
        }
    };

    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest015
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set valid HKS_TAG_KEY_AUTH_PURPOSE for AES
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest015");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }
    };

    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest016
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set valid HKS_TAG_KEY_AUTH_PURPOSE for AES
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest016");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }
    };
    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest017
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set HKS_TAG_KEY_AUTH_PURPOSE is 0
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest017");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = 0
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }
    };
    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksClientCheckTest.HksClientCheckTest018
 * @tc.desc: tdd HksCheckUserAuthKeyPurposeValidity, set HKS_TAG_PURPOSE is 0
 * @tc.type: FUNC
 */
HWTEST_F(HksClientCheckTest, HksClientCheckTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientCheckTest018");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = 0
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_AES
        }
    };
    struct HksParamSet *paramSet = nullptr;
    int ret = InitParamSet(&paramSet, parmas, sizeof(parmas) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckUserAuthKeyPurposeValidity(paramSet);
    HksFreeParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}
}