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

#include "hks_ipc_check_test.h"

#include <gtest/gtest.h>

#include "file_ex.h"
#include "hks_ipc_check.h"
#include "hks_client_ipc_serialization.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksFrameworkIpcCheckTest {
class HksFrameworkIpcCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFrameworkIpcCheckTest::SetUpTestCase(void)
{
}

void HksFrameworkIpcCheckTest::TearDownTestCase(void)
{
}

void HksFrameworkIpcCheckTest::SetUp()
{
}

void HksFrameworkIpcCheckTest::TearDown()
{
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest001
 * @tc.desc: test HksCheckIpcGenerateKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest001");
    const char *keyAlias = "HksFrameworkIpcCheckTest001";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    ret = HksCheckIpcGenerateKey(&keyAliasBlob, paramSet);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest002
 * @tc.desc: test HksCheckIpcImportKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest002");
    const char *keyAlias = "HksFrameworkIpcCheckTest002";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    const char *keyData = "HksFrameworkIpcCheckTest002";
    struct HksBlob keyBlob = { .size = strlen(keyData), .data = (uint8_t *)keyData };
    ret = HksCheckIpcImportKey(&keyAliasBlob, paramSet, &keyBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest003
 * @tc.desc: test HksCheckIpcImportKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest003");
    const char *keyAlias = "HksFrameworkIpcCheckTest003";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    const char *keyData = "HksFrameworkIpcCheckTest003";
    struct HksBlob keyBlob = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData };
    ret = HksCheckIpcImportKey(&keyAliasBlob, paramSet, &keyBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest004
 * @tc.desc: test HksCheckIpcImportWrappedKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest004");
    const char *keyAlias = "HksFrameworkIpcCheckTest004";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyAlias };
    const char *wrappedKeyAlias = "HksFrameworkIpcCheckTest004";
    struct HksBlob wrappedKeyAliasBlob = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)wrappedKeyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    const char *keyData = "HksFrameworkIpcCheckTest004";
    struct HksBlob keyBlob = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData };
    ret = HksCheckIpcImportWrappedKey(&keyAliasBlob, &wrappedKeyAliasBlob, paramSet, &keyBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest005
 * @tc.desc: test HksCheckIpcImportWrappedKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest005");
    const char *keyAlias = "HksFrameworkIpcCheckTest005";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyAlias };
    const char *wrappedKeyAlias = "HksFrameworkIpcCheckTest005";
    struct HksBlob wrappedKeyAliasBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)wrappedKeyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    const char *keyData = "HksFrameworkIpcCheckTest005";
    struct HksBlob keyBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyData };
    ret = HksCheckIpcImportWrappedKey(&keyAliasBlob, &wrappedKeyAliasBlob, paramSet, &keyBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest006
 * @tc.desc: test HksCheckIpcExportPublicKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest006");
    const char *keyAlias = "HksFrameworkIpcCheckTest006";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyAlias };
    const char *keyData = "HksFrameworkIpcCheckTest006";
    struct HksBlob keyBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyData };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckIpcExportPublicKey(&keyAliasBlob, paramSet, &keyBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest007
 * @tc.desc: test HksCheckIpcExportPublicKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest007");
    const char *keyAlias = "HksFrameworkIpcCheckTest007";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE - 1, .data = (uint8_t *)keyAlias };
    const char *keyData = "HksFrameworkIpcCheckTest007";
    struct HksBlob keyBlob = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckIpcExportPublicKey(&keyAliasBlob, paramSet, &keyBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest008
 * @tc.desc: test HksCheckIpcGetKeyParamSet with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest008");
    const char *keyAlias = "HksFrameworkIpcCheckTest008";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksParamSet *paramSetIn = nullptr;
    ret = HksInitParamSet(&paramSetIn);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSetIn);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckIpcGetKeyParamSet(&keyAliasBlob, paramSetIn, paramSet);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&paramSetIn);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest009
 * @tc.desc: test HksCheckIpcGetKeyParamSet with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest009");
    const char *keyAlias = "HksFrameworkIpcCheckTest009";
    struct HksBlob keyAliasBlob = { .size = strlen(keyAlias), .data = (uint8_t *)keyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    paramSet->paramSetSize = 0;
    struct HksParamSet *paramSetIn = nullptr;
    ret = HksInitParamSet(&paramSetIn);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSetIn);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckIpcGetKeyParamSet(&keyAliasBlob, paramSetIn, paramSet);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&paramSetIn);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest010
 * @tc.desc: test HksCheckIpcGetKeyParamSet with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest010");
    const char *keyAlias = "HksFrameworkIpcCheckTest010";
    struct HksBlob keyAliasBlob = { .size = MAX_PROCESS_SIZE - 1, .data = (uint8_t *)keyAlias };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    paramSet->paramSetSize = MAX_PROCESS_SIZE /2 +1;
    struct HksParamSet *paramSetIn = nullptr;
    ret = HksInitParamSet(&paramSetIn);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSetIn);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckIpcGetKeyParamSet(&keyAliasBlob, paramSetIn, paramSet);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&paramSetIn);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest011
 * @tc.desc: test HksCheckIpcAgreeKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest011");
    const char *keyData1 = "HksFrameworkIpcCheckTest011_1";
    struct HksBlob keyBlob1 = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyData1 };

    const char *keyData2 = "HksFrameworkIpcCheckTest011_2";
    struct HksBlob keyBlob2 = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData2 };

    const char *keyData3 = "HksFrameworkIpcCheckTest011_3";
    struct HksBlob keyBlob3 = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData3 };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    ret = HksCheckIpcAgreeKey(paramSet, &keyBlob1, &keyBlob2, &keyBlob3);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest012
 * @tc.desc: test HksCheckIpcAgreeKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest012");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *keyData1 = "HksFrameworkIpcCheckTest012_1";
    struct HksBlob keyBlob1 = { .size = MAX_PROCESS_SIZE / 2+ 1, .data = (uint8_t *)keyData1 };

    const char *keyData2 = "HksFrameworkIpcCheckTest012_2";
    struct HksBlob keyBlob2 = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData2 };

    const char *keyData3 = "HksFrameworkIpcCheckTest012_3";
    struct HksBlob keyBlob3 = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData3 };

    ret = HksCheckIpcAgreeKey(paramSet, &keyBlob1, &keyBlob2, &keyBlob3);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest013
 * @tc.desc: test HksCheckIpcDeriveKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest013");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *keyData1 = "HksFrameworkIpcCheckTest013_1";
    struct HksBlob keyBlob1 = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyData1 };

    const char *keyData2 = "HksFrameworkIpcCheckTest013_2";
    struct HksBlob keyBlob2 = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData2 };

    ret = HksCheckIpcDeriveKey(paramSet, &keyBlob1, &keyBlob2);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest014
 * @tc.desc: test HksCheckIpcDeriveKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest014");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *keyData1 = "HksFrameworkIpcCheckTest014_1";
    struct HksBlob keyBlob1 = { .size = MAX_PROCESS_SIZE - 1, .data = (uint8_t *)keyData1 };

    const char *keyData2 = "HksFrameworkIpcCheckTest014_2";
    struct HksBlob keyBlob2 = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData2 };

    ret = HksCheckIpcDeriveKey(paramSet, &keyBlob1, &keyBlob2);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest015
 * @tc.desc: test HksCheckIpcGetKeyInfoList with empty data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest015");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckIpcGetKeyInfoList(nullptr, paramSet, 0);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest016
 * @tc.desc: test HksCheckIpcDeriveKey with overload data, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest016");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *keyData1 = "HksFrameworkIpcCheckTest013_1";
    struct HksBlob keyBlob1 = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)keyData1 };

    const char *keyData2 = "HksFrameworkIpcCheckTest013_2";
    struct HksBlob keyBlob2 = { .size = MAX_PROCESS_SIZE / 2 + 1, .data = (uint8_t *)keyData2 };

    struct HksCertChain certChain = { .certs = &keyBlob2, .certsCount = 1 };

    ret = HksCheckIpcCertificateChain(&keyBlob1, paramSet, &certChain);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}
}