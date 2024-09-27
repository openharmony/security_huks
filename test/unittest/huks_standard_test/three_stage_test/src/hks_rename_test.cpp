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
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "hks_file_operator.h"
using namespace testing::ext;
namespace {
class HksRenameKeyAliasTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRenameKeyAliasTest::SetUpTestCase(void)
{
}

void HksRenameKeyAliasTest::TearDownTestCase(void)
{
}

void HksRenameKeyAliasTest::SetUp()
{
}

void HksRenameKeyAliasTest::TearDown()
{
}

static const uint32_t USER_ID_INT = 0;

static int32_t TestGenerateKey(const struct HksBlob *keyAlias)
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
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
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

#ifdef HKS_INTERACT_ABILITY
static int32_t SetIdsToken()
{
    uint64_t tokenId;
    const char *acls[] = {
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    const char *perms[] = {
        "ohos.permission.PLACE_CALL", // system_basic
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .aplStr = "system_basic",
    };
    infoInstance.acls = acls;
    infoInstance.aclsNum = 1;
    infoInstance.processName = "test_movece";
    tokenId = GetAccessTokenId(&infoInstance);
    int32_t ret = SetSelfTokenID(tokenId);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("SetSelfTokenID fail, ret is %" LOG_PUBLIC "x!", ret);
    }
    return ret;
}
#endif

/**
 * @tc.name: HksRenameKeyAliasTest.HksRenameKeyAliasTest001
 * @tc.desc: Rename the key and keep the old one;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasTest, HksRenameKeyAliasTest001, TestSize.Level0)
{
#ifdef HKS_INTERACT_ABILITY
    SetIdsToken();
#endif
    const char *alias = "oldAlias001";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias);
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
        {.tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT},
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
 * @tc.name: HksRenameKeyAliasTest.HksRenameKeyAliasTest002
 * @tc.desc: Rename the key and remove the old one;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasTest, HksRenameKeyAliasTest002, TestSize.Level0)
{
#ifdef HKS_INTERACT_ABILITY
    SetIdsToken();
#endif
    const char *alias = "oldAlias002";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias);
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
        {.tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT},
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
 * @tc.name: HksRenameKeyAliasTest.HksRenameKeyAliasTest003
 * @tc.desc: If the main key is lost, the renaming is still successful;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasTest, HksRenameKeyAliasTest003, TestSize.Level0)
{
#ifdef HKS_INTERACT_ABILITY
    SetIdsToken();
#endif
    const char *alias = "oldAlias003";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias);
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
        {.tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT},
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
 * @tc.name: HksRenameKeyAliasTest.HksRenameKeyAliasTest004
 * @tc.desc: The old key is lost, the renaming is failed;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasTest, HksRenameKeyAliasTest004, TestSize.Level2)
{
#ifdef HKS_INTERACT_ABILITY
    SetIdsToken();
#endif
    const char *alias = "oldAlias004";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias);
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
        {.tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT},
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
 * @tc.name: HksRenameKeyAliasTest.HksRenameKeyAliasTest005
 * @tc.desc: A new key with the same name exists, the renaming is faild;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasTest, HksRenameKeyAliasTest005, TestSize.Level1)
{
#ifdef HKS_INTERACT_ABILITY
    SetIdsToken();
#endif
    const char *alias = "oldAlias005";
    const char *alias2 = "newKeyAlias005";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob keyAlias2 = { strlen(alias2), (uint8_t *)alias2 };
    
    int32_t ret = TestGenerateKey(&keyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestGenerateKey keyAlias ret is " << ret;
    ret = TestGenerateKey(&keyAlias2);
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
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT},
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
 * @tc.name: HksRenameKeyAliasTest.HksRenameKeyAliasTest006
 * @tc.desc: The renameParamSet has incorrect parameters, the renaming is faild;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasTest, HksRenameKeyAliasTest006, TestSize.Level0)
{
#ifdef HKS_INTERACT_ABILITY
    SetIdsToken();
#endif
    const char *alias = "oldAlias006";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias);
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
 * @tc.name: HksRenameKeyAliasTest.HksRenameKeyAliasTest007
 * @tc.desc: The old and new name of the key are the same, the renaming is faild;
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasTest, HksRenameKeyAliasTest007, TestSize.Level0)
{
#ifdef HKS_INTERACT_ABILITY
    SetIdsToken();
#endif
    const char *alias = "oldAlias007";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    
    int32_t ret = TestGenerateKey(&keyAlias);
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
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT},
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
}