/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <sstream>
#include <string>

#include "hks_rename_test.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_file_operator.h"
#include "hks_mock_common.h"
using namespace testing::ext;
using namespace testing::mt;
namespace {
class HksRenameKeyAliasPart3Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};
static uint64_t g_shellTokenId = 0;
void HksRenameKeyAliasPart3Test::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksRenameKeyAliasPart3Test::TearDownTestCase(void)
{
    SetSelfTokenID(g_shellTokenId);
    HksMockCommon::ResetTestEvironment();
}

void HksRenameKeyAliasPart3Test::SetUp()
{
}

void HksRenameKeyAliasPart3Test::TearDown()
{
}

static const uint32_t USER_ID_INT = 100;

static int32_t TestGenerateKey(const struct HksBlob *keyAlias, uint32_t storageLevel)
{
    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = storageLevel },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksAddParams failed");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksBuildParamSet failed");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksGenerateKey(keyAlias, paramSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksGenerateKey failed");
    }
    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t BuildParamSetWithParam(struct HksParamSet **paramSet, struct HksParam *param, uint32_t paramCnt)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("BuildParamSetWithParam HksInitParamSet failed");
        return ret;
    }
    if (param != nullptr) {
        ret = HksAddParams(*paramSet, param, paramCnt);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("BuildParamSetWithParam HksAddParams failed");
            return ret;
        }
    }
    return HksBuildParamSet(paramSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart3Test.HksRenameKeyAliasPart3Test013
 * @tc.desc: the storageLevel is CE
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart3Test, HksRenameKeyAliasPart3Test0013, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");

    const char *alias = "oldAlias013";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_CE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
        struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    };
    ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    struct HksParamSet *renameParamSet = nullptr;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true },
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newAlias013";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart3Test.HksRenameKeyAliasPart3Test014
 * @tc.desc: the storageLevel is ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart3Test, HksRenameKeyAliasPart3Test0014, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    const char *alias = "oldAlias014";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_ECE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    };
    ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    struct HksParamSet *renameParamSet = nullptr;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true },
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newAlias014";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart3Test.HksRenameKeyAliasPart3Test015
 * @tc.desc: the storageLevel is ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart3Test, HksRenameKeyAliasPart3Test0015, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");

    const char *alias = "oldAlias015";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_CE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    };
    ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    struct HksParamSet *renameParamSet = nullptr;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = false },
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newAlias015";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart3Test.HksRenameKeyAliasPart3Test016
 * @tc.desc: the storageLevel is ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart3Test, HksRenameKeyAliasPart3Test0016, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");

    const char *alias = "oldAlias016";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_ECE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    };
    ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    struct HksParamSet *renameParamSet = nullptr;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = false },
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newAlias016";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart3Test.HksRenameKeyAliasPart3Test020
 * @tc.desc: GenerateKey for HksRenameKeyAliasPart2Test020
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart3Test, HksRenameKeyAliasPart3Test020, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");

    const char *alias = "oldKeyAlias020";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey ret is " << ret;

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;;

    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
}

void MultiThreadRename()
{
    std::thread::id thisId = std::this_thread::get_id();
    std::ostringstream oss;
    oss << thisId;
    std::string thisIdStr = oss.str();

    const char *alias = "oldKeyAlias028";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    };
    int32_t ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::string rands = "newAlias028" + thisIdStr;
    const char *alias2 = rands.c_str();
    struct HksParamSet *renameParamSet = nullptr;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true },
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    if (ret == HKS_SUCCESS) {
        HKS_LOG_E("rename success!!");
    } else {
        HKS_LOG_E("rename failed!!");
    }
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart3Test.HksRenameKeyAliasPart3Test028
 * @tc.desc: GenerateKey for HksRenameKeyAliasPart2Test028
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart3Test, HksRenameKeyAliasPart3Test028, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");

    const char *alias = "oldKeyAlias028";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_ECE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey ret is " << ret;

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    };
    ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;;

    testing::mt::SET_THREAD_NUM(100);
    GTEST_RUN_TASK(MultiThreadRename);

    HksFreeParamSet(&paramSet);
}
}