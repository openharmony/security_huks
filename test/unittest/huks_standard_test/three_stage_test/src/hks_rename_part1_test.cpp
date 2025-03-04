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

#include <gtest/gtest.h>

#include "hks_rename_test.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_file_operator.h"
using namespace testing::ext;
namespace {
class HksRenameKeyAliasPart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRenameKeyAliasPart1Test::SetUpTestCase(void)
{
}

void HksRenameKeyAliasPart1Test::TearDownTestCase(void)
{
}

void HksRenameKeyAliasPart1Test::SetUp()
{
}

void HksRenameKeyAliasPart1Test::TearDown()
{
}

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
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test001
 * @tc.desc: Rename the key and keep the old one;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test001, TestSize.Level0)
{
    const char *alias = "o";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey ret is " << ret;

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;;

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newKeyAlias001";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "old key is not exit, ret is " << ret;

    ret = HksKeyExist(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "new key is not exit, ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test002
 * @tc.desc: Rename the key and remove the old one;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test002, TestSize.Level0)
{
    const char *alias = "oldAlias002";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey ret is " << ret;

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;;

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newKeyAlias002";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "old key exit, delet failed, ret is " << ret;

    ret = HksKeyExist(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "new key is not exit, ret is " << ret;

    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

static const char *STORE_PATH = "/data/service/el1/public/huks_service/maindata/0/0/key/";
/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test003
 * @tc.desc: If the main key is lost, the renaming is still successful;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test003, TestSize.Level0)
{
    const char *alias = "oldAlias003";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    ret = HksFileRemove(STORE_PATH, alias);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newKeyAlias003";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "old key exit, delet failed, ret is " << ret;
    ret = HksKeyExist(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "new key is not exit, ret is " << ret;
    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test004
 * @tc.desc: The old key is lost, the renaming is failed;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test004, TestSize.Level2)
{
    const char *alias = "oldAlias004";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey ret is " << ret;

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks delete MainFile key failed, ret is " << ret;

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newKeyAlias004";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "old key exit, delet failed, ret is " << ret;

    ret = HksKeyExist(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "new key is not exit, ret is " << ret;

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test005
 * @tc.desc: A new key with the same name exists, the renaming is faild;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test005, TestSize.Level1)
{
    const char *alias = "oldAlias005";
    const char *alias2 = "newKeyAlias005";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob keyAlias2 = { strlen(alias2), (uint8_t *)alias2 };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    ret = TestGenerateKey(&keyAlias2, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias2 ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    ret = HksKeyExist(&keyAlias2, paramSet);;
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_ALREADY_EXISTS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&keyAlias2, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test006
 * @tc.desc: The renameParamSet has incorrect parameters, the renaming is faild;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test006, TestSize.Level0)
{
    const char *alias = "oldAlias006";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newKeyAlias006";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_PARAM_NOT_EXIST) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test007
 * @tc.desc: The old and new name of the key are the same, the renaming is faild;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test007, TestSize.Level0)
{
    const char *alias = "oldAlias007";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "oldAlias007";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test008
 * @tc.desc: The keyAlias size is 128, the renaming success;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test008, TestSize.Level0)
{
    const char *alias = "oldAlias008";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newAlias128newAlias128newAlias128newAlias128newAlias128newAlias1"
                         "28newAlias128newAlias128newAlias128newAlias128newAlias128newAlia";
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
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test009
 * @tc.desc: The keyAlias size is 129, the renaming failed;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test009, TestSize.Level0)
{
    const char *alias = "oldAlias009";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "AnewAlias128newAlias128newAlias128newAlias128newAlias128newAlias1"
                         "28newAlias128newAlias128newAlias128newAlias128newAlias128newAlia";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test010
 * @tc.desc: The keyAlias is null, the renaming failed;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test0010, TestSize.Level0)
{
    const char *alias = "oldAlias010";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob newKeyAlias = { 0, NULL };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test011
 * @tc.desc: The keyAlias size is 0, the renaming failed;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test0011, TestSize.Level0)
{
    const char *alias = "oldAlias011";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test012
 * @tc.desc: The rename paramset is null, the renaming failed;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test0012, TestSize.Level0)
{
    const char *alias = "oldAlias012";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test017
 * @tc.desc: old key alias size is 129
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test017, TestSize.Level0)
{
    const char *alias = "AnewAlias128newAlias128newAlias128newAlias128newAlias128newAlias1"
                         "28newAlias128newAlias128newAlias128newAlias128newAlias128newAlia";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    int32_t ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "AnewAlias128newAlias128newAlias128newAlias128newAlias128newAlias1";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test018
 * @tc.desc: old key alias is null
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test0018, TestSize.Level0)
{
    struct HksBlob keyAlias = { 0, NULL };
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    int32_t ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "13";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test019
 * @tc.desc: no copy, old key alias size is 0
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test0019, TestSize.Level0)
{
    const char *alias = "";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    int32_t ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "19";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test021
 * @tc.desc: no copy, same old and new
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test021, TestSize.Level1)
{
    const char *alias = "oldAlias021";
    const char *alias2 = "newKeyAlias021";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob keyAlias2 = { strlen(alias2), (uint8_t *)alias2 };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    ret = TestGenerateKey(&keyAlias2, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias2 ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    ret = HksKeyExist(&keyAlias2, paramSet);;
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = false},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_ALREADY_EXISTS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

static const char *STORE_BACKUP_PATH = "/data/service/el1/public/huks_service/bakdata/0/0/key/";
/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test022
 * @tc.desc: copy, remove old main key
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test022, TestSize.Level0)
{
    const char *alias = "oldAlias022";
    const char *alias2 = "newAlias022";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob keyAlias2 = { strlen(alias2), (uint8_t *)alias2 };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    ret = TestGenerateKey(&keyAlias2, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias2 ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    ret = HksFileRemove(STORE_PATH, alias);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_ALREADY_EXISTS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "old key exit, delet failed, ret is " << ret;
    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test023
 * @tc.desc: copy, remove old backup key
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test023, TestSize.Level0)
{
    const char *alias = "oldAlias023";
    const char *alias2 = "newAlias023";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob keyAlias2 = { strlen(alias2), (uint8_t *)alias2 };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    ret = TestGenerateKey(&keyAlias2, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias2 ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    ret = HksFileRemove(STORE_BACKUP_PATH, alias);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_ALREADY_EXISTS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "old key exit, delet failed, ret is " << ret;
    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test024
 * @tc.desc: remove old backup key
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test024, TestSize.Level0)
{
    const char *alias = "oldAlias024";
    const char *alias2 = "newAlias024";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob keyAlias2 = { strlen(alias2), (uint8_t *)alias2 };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    ret = TestGenerateKey(&keyAlias2, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias2 ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    ret = HksFileRemove(STORE_BACKUP_PATH, alias);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = false},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_ALREADY_EXISTS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "old key exit, delet failed, ret is " << ret;
    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test025
 * @tc.desc: remove old main key
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test025, TestSize.Level0)
{
    const char *alias = "oldAlias025";
    const char *alias2 = "newAlias025";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob keyAlias2 = { strlen(alias2), (uint8_t *)alias2 };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    ret = TestGenerateKey(&keyAlias2, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias2 ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    ret = HksFileRemove(STORE_PATH, alias);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = false},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_ALREADY_EXISTS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "old key exit, delet failed, ret is " << ret;
    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test026
 * @tc.desc: no copy. same old and new
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test026, TestSize.Level0)
{
    const char *alias = "oldAlias026";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;
    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = false},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "oldAlias026";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRenameKeyAlias ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart1Test.HksRenameKeyAliasPart1Test027
 * @tc.desc: If the backup key is lost, the renaming is still successful;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart1Test, HksRenameKeyAliasPart1Test027, TestSize.Level0)
{
    const char *alias = "oldAlias027";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias, HKS_AUTH_STORAGE_LEVEL_DE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey ret is " << ret;
    
    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel, sizeof(storageLevel) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks get generate key failed, ret is " << ret;

    ret = HksFileRemove(STORE_BACKUP_PATH, alias);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newKeyAlias027";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "old key exit, delet failed, ret is " << ret;
    ret = HksKeyExist(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "new key is not exit, ret is " << ret;
    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksDeleteKey(&newKeyAlias, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}
}