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

#ifdef HKS_UKEY_EXTENSION_CRYPTO
/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest017
 * @tc.desc: test HksCheckAuthStateIsValid with all valid states + invalid
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest017");
    int32_t ret = HksCheckAuthStateIsValid(HKS_EXT_CRYPTO_PIN_NO_AUTH);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckAuthStateIsValid(HKS_EXT_CRYPTO_PIN_AUTH_SUCCEEDED);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckAuthStateIsValid(HKS_EXT_CRYPTO_PIN_LOCKED);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckAuthStateIsValid(99);
    ASSERT_TRUE(ret == HKS_ERROR_EXT_RETURN_VALUE_INCRECT);
    ret = HksCheckAuthStateIsValid(-1);
    ASSERT_TRUE(ret == HKS_ERROR_EXT_RETURN_VALUE_INCRECT);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest018
 * @tc.desc: test HksCheckIpcBlobAndParamSet null and invalid inputs
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest018");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *blobData = "test018";
    struct HksBlob blob = { .size = (uint32_t)strlen(blobData), .data = (uint8_t *)blobData };

    ret = HksCheckIpcBlobAndParamSet(NULL, paramSet, 128);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcBlobAndParamSet(&blob, NULL, 128);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    struct HksBlob bigBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)blobData };
    ret = HksCheckIpcBlobAndParamSet(&bigBlob, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    uint32_t smallMax = 2;
    ret = HksCheckIpcBlobAndParamSet(&blob, paramSet, smallMax);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcBlobAndParamSet(&blob, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest019
 * @tc.desc: test HksCheckIpcBlobAndParamSet combined size overflow
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest019");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *blobData = "test019";
    struct HksBlob blob = { .size = (uint32_t)strlen(blobData), .data = (uint8_t *)blobData };

    paramSet->paramSetSize = MAX_PROCESS_SIZE;
    ret = HksCheckIpcBlobAndParamSet(&blob, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest020
 * @tc.desc: test HksCheckIpcTwoBlobsParamSet null and invalid inputs
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest020");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *d1 = "blob1_data";
    const char *d2 = "blob2_data";
    struct HksBlob blob1 = { .size = (uint32_t)strlen(d1), .data = (uint8_t *)d1 };
    struct HksBlob blob2 = { .size = (uint32_t)strlen(d2), .data = (uint8_t *)d2 };

    ret = HksCheckIpcTwoBlobsParamSet(NULL, &blob2, paramSet, 128, 128);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcTwoBlobsParamSet(&blob1, NULL, paramSet, 128, 128);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcTwoBlobsParamSet(&blob1, &blob2, NULL, 128, 128);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    ret = HksCheckIpcTwoBlobsParamSet(&blob1, &blob2, paramSet, 1, 1);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcTwoBlobsParamSet(&blob1, &blob2, paramSet, 1, 128);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcTwoBlobsParamSet(&blob1, &blob2, paramSet, 128, 1);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcTwoBlobsParamSet(&blob1, &blob2, paramSet, MAX_PROCESS_SIZE, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest021
 * @tc.desc: test HksCheckIpcBlob null and invalid inputs
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest021");
    const char *d = "test021";
    struct HksBlob blob = { .size = (uint32_t)strlen(d), .data = (uint8_t *)d };

    int32_t ret = HksCheckIpcBlob(NULL, 128);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcBlob(&blob, 1);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    struct HksBlob bigBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)d };
    ret = HksCheckIpcBlob(&bigBlob, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    ret = HksCheckIpcBlob(&blob, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest022
 * @tc.desc: test HksCheckIpcBlobAndCertInfo null and invalid certInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest022");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *blobData = "test022";
    struct HksBlob blob = { .size = (uint32_t)strlen(blobData), .data = (uint8_t *)blobData };

    ret = HksCheckIpcBlobAndCertInfo(NULL, NULL, paramSet, 128);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    ret = HksCheckIpcBlobAndCertInfo(&blob, NULL, paramSet, 128);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    const char *indexData = "idx";
    const char *certData = "certdata";
    struct HksExtCertInfo certInfo = { 0,
        { (uint32_t)strlen(indexData), (uint8_t *)indexData },
        { (uint32_t)strlen(certData), (uint8_t *)certData } };

    ret = HksCheckIpcBlobAndCertInfo(&blob, &certInfo, NULL, 128);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    struct HksExtCertInfo badCert1 = { 0, { 0, NULL }, { (uint32_t)strlen(certData), (uint8_t *)certData } };
    ret = HksCheckIpcBlobAndCertInfo(&blob, &badCert1, paramSet, 128);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    struct HksExtCertInfo badCert2 = { 0,
        { (uint32_t)strlen(indexData), (uint8_t *)indexData }, { 0, NULL } };
    ret = HksCheckIpcBlobAndCertInfo(&blob, &badCert2, paramSet, 128);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest023
 * @tc.desc: test HksCheckIpcBlobAndCertInfo blob size checks
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest023");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *blobData = "test023";
    const char *indexData = "idx";
    const char *certData = "certdata";
    struct HksBlob bigBlob = { .size = MAX_PROCESS_SIZE + 1, .data = (uint8_t *)blobData };
    struct HksExtCertInfo certInfo = { 0,
        { (uint32_t)strlen(indexData), (uint8_t *)indexData },
        { (uint32_t)strlen(certData), (uint8_t *)certData } };

    ret = HksCheckIpcBlobAndCertInfo(&bigBlob, &certInfo, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    struct HksBlob normalBlob = { .size = 200, .data = (uint8_t *)blobData };
    ret = HksCheckIpcBlobAndCertInfo(&normalBlob, &certInfo, paramSet, 100);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    struct HksBlob goodBlob = { .size = (uint32_t)strlen(blobData), .data = (uint8_t *)blobData };
    ret = HksCheckIpcBlobAndCertInfo(&goodBlob, &certInfo, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest024
 * @tc.desc: test HksCheckIpcBlobAndCertInfo ALIGN_SIZE and total overflow
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest024");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *blobData = "test024";
    const char *indexData = "idx";
    const char *certData = "certdata";
    struct HksBlob blob = { .size = (uint32_t)strlen(blobData), .data = (uint8_t *)blobData };

    struct HksExtCertInfo bigIndexCert = { 0,
        { MAX_PROCESS_SIZE + 1, (uint8_t *)indexData },
        { (uint32_t)strlen(certData), (uint8_t *)certData } };
    ret = HksCheckIpcBlobAndCertInfo(&blob, &bigIndexCert, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    struct HksExtCertInfo bigCertCert = { 0,
        { (uint32_t)strlen(indexData), (uint8_t *)indexData },
        { MAX_PROCESS_SIZE + 1, (uint8_t *)certData } };
    ret = HksCheckIpcBlobAndCertInfo(&blob, &bigCertCert, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    paramSet->paramSetSize = MAX_PROCESS_SIZE;
    struct HksExtCertInfo goodCert = { 0,
        { (uint32_t)strlen(indexData), (uint8_t *)indexData },
        { (uint32_t)strlen(certData), (uint8_t *)certData } };
    ret = HksCheckIpcBlobAndCertInfo(&blob, &goodCert, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}
#endif

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest025
 * @tc.desc: test HksCheckIpcEncapsulate with null and invalid paramSets
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest025");
    const char *alias = "alias025";
    const char *shared = "shared025";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    uint32_t outSize = 0;

    int32_t ret = HksCheckIpcEncapsulate(&keyAlias, nullptr, &sharedKeyAlias, nullptr, &outSize);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    ret = HksCheckIpcEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, nullptr, &outSize);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest026
 * @tc.desc: test HksCheckIpcEncapsulate with invalid blobs
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest026");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    uint32_t outSize = 0;
    struct HksBlob nullDataBlob = { .size = 10, .data = nullptr };
    const char *shared = "shared026";
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };

    ret = HksCheckIpcEncapsulate(&nullDataBlob, paramSet, &sharedKeyAlias, sharedParamSet, &outSize);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    const char *alias = "alias026";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob nullShared = { .size = 10, .data = nullptr };

    ret = HksCheckIpcEncapsulate(&keyAlias, paramSet, &nullShared, sharedParamSet, &outSize);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest027
 * @tc.desc: test HksCheckIpcEncapsulate keyAlias too long
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest027");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    uint32_t outSize = 0;
    char longAlias[HKS_MAX_KEY_ALIAS_LEN + 2];
    memset_s(longAlias, sizeof(longAlias), 'A', HKS_MAX_KEY_ALIAS_LEN + 1);
    longAlias[HKS_MAX_KEY_ALIAS_LEN + 1] = '\0';
    struct HksBlob keyAlias = { .size = HKS_MAX_KEY_ALIAS_LEN + 1, .data = (uint8_t *)longAlias };

    const char *shared = "shared027";
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };

    ret = HksCheckIpcEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &outSize);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest028
 * @tc.desc: test HksCheckIpcEncapsulate totalSize overflow
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest028");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *alias = "a028";
    const char *shared = "s028";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    uint32_t outSize = 0;

    sharedParamSet->paramSetSize = MAX_PROCESS_SIZE;
    ret = HksCheckIpcEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &outSize);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest029
 * @tc.desc: test HksCheckIpcEncapsulate success path
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest029");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *alias = "alias029";
    const char *shared = "shared029";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    uint32_t outSize = 0;

    ret = HksCheckIpcEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &outSize);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ASSERT_TRUE(outSize > 0);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest030
 * @tc.desc: test HksCheckIpcDecapsulateConcret with null and invalid paramSets
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest030");
    const char *alias = "alias030";
    const char *shared = "shared030";
    const char *secret = "secret030";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    struct HksBlob sharedSecret = { .size = (uint32_t)strlen(secret), .data = (uint8_t *)secret };

    int32_t ret = HksCheckIpcDecapsulateConcret(&keyAlias, nullptr, &sharedKeyAlias, nullptr, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &sharedKeyAlias, nullptr, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest031
 * @tc.desc: test HksCheckIpcDecapsulateConcret with invalid blobs
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest031, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest031");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    struct HksBlob nullBlob = { .size = 10, .data = nullptr };
    const char *alias = "alias031";
    const char *shared = "shared031";
    const char *secret = "secret031";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    struct HksBlob sharedSecret = { .size = (uint32_t)strlen(secret), .data = (uint8_t *)secret };

    ret = HksCheckIpcDecapsulateConcret(&nullBlob, paramSet, &sharedKeyAlias, sharedParamSet, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &nullBlob, sharedParamSet, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &nullBlob);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest032
 * @tc.desc: test HksCheckIpcDecapsulateConcret keyAlias too long
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest032, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest032");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    char longAlias[HKS_MAX_KEY_ALIAS_LEN + 2];
    memset_s(longAlias, sizeof(longAlias), 'B', HKS_MAX_KEY_ALIAS_LEN + 1);
    longAlias[HKS_MAX_KEY_ALIAS_LEN + 1] = '\0';
    struct HksBlob keyAlias = { .size = HKS_MAX_KEY_ALIAS_LEN + 1, .data = (uint8_t *)longAlias };

    const char *shared = "shared032";
    const char *secret = "secret032";
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    struct HksBlob sharedSecret = { .size = (uint32_t)strlen(secret), .data = (uint8_t *)secret };

    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest033
 * @tc.desc: test HksCheckIpcDecapsulateConcret sharedKeyAlias too long
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest033, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest033");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *alias = "alias033";
    char longShared[HKS_MAX_KEY_ALIAS_LEN + 2];
    memset_s(longShared, sizeof(longShared), 'C', HKS_MAX_KEY_ALIAS_LEN + 1);
    longShared[HKS_MAX_KEY_ALIAS_LEN + 1] = '\0';
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = HKS_MAX_KEY_ALIAS_LEN + 1, .data = (uint8_t *)longShared };

    const char *secret = "secret033";
    struct HksBlob sharedSecret = { .size = (uint32_t)strlen(secret), .data = (uint8_t *)secret };

    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest034
 * @tc.desc: test HksCheckIpcDecapsulateConcret totalSize overflow
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest034, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest034");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *alias = "a034";
    const char *shared = "s034";
    const char *secret = "x034";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    struct HksBlob sharedSecret = { .size = (uint32_t)strlen(secret), .data = (uint8_t *)secret };

    sharedParamSet->paramSetSize = MAX_PROCESS_SIZE;
    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest035
 * @tc.desc: test HksCheckIpcDecapsulateConcret success path
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest035, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest035");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *alias = "alias035";
    const char *shared = "shared035";
    const char *secret = "secret035";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    struct HksBlob sharedSecret = { .size = (uint32_t)strlen(secret), .data = (uint8_t *)secret };

    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &sharedKeyAlias, sharedParamSet, &sharedSecret);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest036
 * @tc.desc: test HksCheckIpcEncapsulate with invalid sharedKeyParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest036, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest036");
    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    struct HksParamSet badShared = { .paramSetSize = 1, .paramsCnt = 0 };
    const char *alias = "alias036";
    const char *shared = "s036";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    uint32_t outSize = 0;

    ret = HksCheckIpcEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, &badShared, &outSize);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest037
 * @tc.desc: test HksCheckIpcDecapsulateConcret with invalid sharedKeyParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest037, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest037");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    struct HksParamSet badShared = { .paramSetSize = 1, .paramsCnt = 0 };
    const char *alias = "alias037";
    const char *shared = "s037";
    const char *secret = "x037";
    struct HksBlob keyAlias = { .size = (uint32_t)strlen(alias), .data = (uint8_t *)alias };
    struct HksBlob sharedKeyAlias = { .size = (uint32_t)strlen(shared), .data = (uint8_t *)shared };
    struct HksBlob sharedSecret = { .size = (uint32_t)strlen(secret), .data = (uint8_t *)secret };

    ret = HksCheckIpcDecapsulateConcret(&keyAlias, paramSet, &sharedKeyAlias, &badShared, &sharedSecret);
    ASSERT_TRUE(ret == HKS_ERROR_NEW_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest038
 * @tc.desc: test HksCheckAuthStateIsValid boundary values
 * @tc.type: FUNC
 */
#ifdef HKS_UKEY_EXTENSION_CRYPTO
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest038, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest038");
    int32_t ret = HksCheckAuthStateIsValid(3);
    ASSERT_TRUE(ret == HKS_ERROR_EXT_RETURN_VALUE_INCRECT);
    ret = HksCheckAuthStateIsValid(0);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckAuthStateIsValid(2);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckAuthStateIsValid(2147483647);
    ASSERT_TRUE(ret == HKS_ERROR_EXT_RETURN_VALUE_INCRECT);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest039
 * @tc.desc: test HksCheckIpcBlob size zero edge case
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest039, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest039");
    struct HksBlob zeroBlob = { .size = 0, .data = nullptr };
    int32_t ret = HksCheckIpcBlob(&zeroBlob, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest040
 * @tc.desc: test HksCheckIpcTwoBlobsParamSet combined size overflow
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest040, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest040");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *d1 = "b1";
    const char *d2 = "b2";
    struct HksBlob blob1 = { .size = MAX_PROCESS_SIZE / 2, .data = (uint8_t *)d1 };
    struct HksBlob blob2 = { .size = MAX_PROCESS_SIZE / 2, .data = (uint8_t *)d2 };

    ret = HksCheckIpcTwoBlobsParamSet(&blob1, &blob2, paramSet, MAX_PROCESS_SIZE, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksFrameworkIpcCheckTest.HksFrameworkIpcCheckTest041
 * @tc.desc: test HksCheckIpcBlobAndCertInfo success with all valid certInfo fields
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkIpcCheckTest, HksFrameworkIpcCheckTest041, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkIpcCheckTest041");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    const char *blobData = "resourceId041";
    const char *indexData = "indexData041";
    const char *certData = "certData041_longer";
    struct HksBlob blob = { .size = (uint32_t)strlen(blobData), .data = (uint8_t *)blobData };
    struct HksExtCertInfo certInfo = { 0,
        { (uint32_t)strlen(indexData), (uint8_t *)indexData },
        { (uint32_t)strlen(certData), (uint8_t *)certData } };

    ret = HksCheckIpcBlobAndCertInfo(&blob, &certInfo, paramSet, MAX_PROCESS_SIZE);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}
#endif
}