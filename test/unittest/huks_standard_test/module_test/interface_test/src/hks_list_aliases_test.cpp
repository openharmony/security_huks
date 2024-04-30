/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hks_list_aliases_test.h"

#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "file_ex.h"
#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "huks_test_param_util.h"

#include "hks_type.h"
#include "hks_template.h"

#include "securec.h"

#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace Unittest::HksListAliasesTest {
class HksListAliasesTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

static const char ALIAS[] = "testAlias";
static const struct HksBlob TEST_KEY_ALIAS = { strlen(ALIAS), (uint8_t *)ALIAS };

static const char INVISABLE_ALIAS[] = "#test(";
static const struct HksBlob TEST_INVISABLE_KEY_ALIAS = { strlen(INVISABLE_ALIAS), (uint8_t *)INVISABLE_ALIAS };

static const uint32_t EXPECT_MIN_NUM = 1;

static const uint32_t INVALID_DE_SPECIFIC_USER_ID = -1;
static const uint32_t INVALID_CE_SPECIFIC_USER_ID = 99;

static const uint32_t VALID_CE_SPECIFIC_USER_ID = 100;

static const uint32_t ERROR_SIZE = 2;

static const std::vector<std::vector<HksParam>> INIT_ADD_PARAMS = {
#ifdef HKS_INTERACT_ABILITY
    {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = VALID_CE_SPECIFIC_USER_ID },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = VALID_CE_SPECIFIC_USER_ID },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    },
#endif
    {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    }
};

static const struct HksParam INIT_COMMON_PARAMS[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
};

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
    infoInstance.processName = "test_list_aliases";
    tokenId = GetAccessTokenId(&infoInstance);
    return SetSelfTokenID(tokenId);
}
#endif

void HksListAliasesTest::SetUpTestCase(void)
{
    int32_t ret = 0;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSet = nullptr;
    for (std::size_t i = 0; i < INIT_ADD_PARAMS.size(); i++) {
        ret = HuksTest::TestBuildInitParamSet(INIT_COMMON_PARAMS, INIT_ADD_PARAMS[i],
            HKS_ARRAY_SIZE(INIT_COMMON_PARAMS), &paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGenerateKey(&TEST_KEY_ALIAS, paramSet, nullptr);
        ASSERT_EQ(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSet);
    }
}

void HksListAliasesTest::TearDownTestCase(void)
{
}

void HksListAliasesTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksListAliasesTest::TearDown()
{
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest001
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet nullptr, expecting HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest001, TestSize.Level0)
{
    struct HksKeyAliasSet *outData = nullptr;
    int32_t ret = HksListAliases(nullptr, &outData);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksListAliases failed, ret = " << ret;
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest002
 * @tc.desc: tdd HksListAliasesTest, case: outData nullptr, expecting HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest002, TestSize.Level0)
{
    struct HksParamSet *queryParamSet = nullptr;
    int32_t ret = HksInitParamSet(&queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed, ret = " << ret;

    ret = HksListAliases(queryParamSet, nullptr);
    
    HksFreeParamSet(&queryParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksListAliases failed, ret = " << ret;
}


/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest003
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet only init, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest003, TestSize.Level0)
{
    struct HksParamSet *queryParamSet = nullptr;
    int32_t ret = HksInitParamSet(&queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInitParamSet failed, ret = " << ret;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    HksFreeParamSet(&queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksListAliases failed, ret = " << ret;
    EXPECT_EQ(outData->aliasesCnt >= EXPECT_MIN_NUM, true) << "HksListAliases failed, cnt = " << outData->aliasesCnt;
    HksFreeKeyAliasSet(outData);
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest004
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet add HKS_AUTH_STORAGE_LEVEL_DE, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest004, TestSize.Level0)
{
    struct HksParamSet *queryParamSet = nullptr;
    struct HksParam addParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
    };
    int32_t ret = HuksTest::TestBuildParamSet(addParams, sizeof(addParams) / sizeof(addParams[0]), &queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HuksTest::TestBuildParamSet failed, ret = " << ret;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    HksFreeParamSet(&queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksListAliases failed, ret = " << ret;
    EXPECT_EQ(outData->aliasesCnt >= EXPECT_MIN_NUM, true) << "HksListAliases failed, cnt = " << outData->aliasesCnt;
    HksFreeKeyAliasSet(outData);
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest005
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet add HKS_AUTH_STORAGE_LEVEL_CE, expecting SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest005, TestSize.Level0)
{
    int32_t ret = 0;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *queryParamSet = nullptr;
    struct HksParam addParams[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = VALID_CE_SPECIFIC_USER_ID },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE }
    };
    ret = HuksTest::TestBuildParamSet(addParams, sizeof(addParams) / sizeof(addParams[0]), &queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HuksTest::TestBuildParamSet failed, ret = " << ret;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    HksFreeParamSet(&queryParamSet);

#ifdef HKS_INTERACT_ABILITY
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksListAliases failed, ret = " << ret;
    EXPECT_EQ(outData->aliasesCnt >= EXPECT_MIN_NUM, true) << "HksListAliases failed, cnt = " << outData->aliasesCnt;
#else
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "HksListAliases failed, ret = " << ret;
#endif

    HksFreeKeyAliasSet(outData);
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest006
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet add HKS_AUTH_STORAGE_LEVEL_ECE, expecting SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest006, TestSize.Level0)
{
    int32_t ret = 0;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *queryParamSet = nullptr;
    struct HksParam addParams[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = VALID_CE_SPECIFIC_USER_ID },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE }
    };
    ret = HuksTest::TestBuildParamSet(addParams, sizeof(addParams) / sizeof(addParams[0]), &queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HuksTest::TestBuildParamSet failed, ret = " << ret;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    HksFreeParamSet(&queryParamSet);

#ifdef HKS_INTERACT_ABILITY
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksListAliases failed, ret = " << ret;
    EXPECT_EQ(outData->aliasesCnt >= EXPECT_MIN_NUM, true) << "HksListAliases failed, cnt = " << outData->aliasesCnt;
#else
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "HksListAliases failed, ret = " << ret;
#endif

    HksFreeKeyAliasSet(outData);
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest007
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet add HKS_AUTH_STORAGE_LEVEL_CE
 *    and HKS_TAG_SPECIFIC_USER_ID < 100, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest007, TestSize.Level0)
{
    int32_t ret = 0;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *queryParamSet = nullptr;
    struct HksParam addParams[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = INVALID_CE_SPECIFIC_USER_ID },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE }
    };

    ret = HuksTest::TestBuildParamSet(addParams, sizeof(addParams) / sizeof(addParams[0]), &queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HuksTest::TestBuildParamSet failed, ret = " << ret;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    HksFreeParamSet(&queryParamSet);

#ifdef HKS_INTERACT_ABILITY
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksListAliases failed, ret = " << ret;
#else
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "HksListAliases failed, ret = " << ret;
#endif

    HksFreeKeyAliasSet(outData);
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest008
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet add HKS_AUTH_STORAGE_LEVEL_DE
 *    and HKS_TAG_SPECIFIC_USER_ID < 0, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest008, TestSize.Level0)
{
    int32_t ret = 0;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *queryParamSet = nullptr;
    struct HksParam addParams[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = INVALID_DE_SPECIFIC_USER_ID },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
    };
    ret = HuksTest::TestBuildParamSet(addParams, sizeof(addParams) / sizeof(addParams[0]), &queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HuksTest::TestBuildParamSet failed, ret = " << ret;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    HksFreeParamSet(&queryParamSet);

#ifdef HKS_INTERACT_ABILITY
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksListAliases failed, ret = " << ret;
#else
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "HksListAliases failed, ret = " << ret;
#endif

    HksFreeKeyAliasSet(outData);
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest009
 * @tc.desc: tdd HksListAliasesTest, case: queryParamSet add HKS_AUTH_STORAGE_LEVEL_DE and size is error,
 *    expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest009, TestSize.Level0)
{
    struct HksParamSet *queryParamSet = nullptr;
    struct HksParam addParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
    };
    int32_t ret = HuksTest::TestBuildParamSet(addParams, sizeof(addParams) / sizeof(addParams[0]), &queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HuksTest::TestBuildParamSet failed, ret = " << ret;

    queryParamSet->paramsCnt = ERROR_SIZE;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    HksFreeParamSet(&queryParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksListAliases failed, ret = " << ret;
    HksFreeKeyAliasSet(outData);
}

static bool IsMatch(const HksKeyAliasSet *aliasSet)
{
    bool ret = false;
    if (aliasSet->aliasesCnt > 0 && aliasSet->aliases != NULL) {
        for (uint32_t i = 0; i < aliasSet->aliasesCnt; i++) {
            if (HksMemCmp(aliasSet->aliases[i].data, TEST_INVISABLE_KEY_ALIAS.data, TEST_INVISABLE_KEY_ALIAS.size)) {
                return true;
            }
        }
    }
    return ret;
}

/**
 * @tc.name: HksListAliasesTest.HksListAliasesTest010
 * @tc.desc: tdd HksListAliasesTest, case: invisable key alias, expecting true
 * @tc.type: FUNC
 */
HWTEST_F(HksListAliasesTest, HksListAliasesTest010, TestSize.Level0)
{
    // invisable key init
    struct HksParamSet *initParamSet = nullptr;

    const std::vector<HksParam> param = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    int32_t ret = HuksTest::TestBuildInitParamSet(INIT_COMMON_PARAMS, param, HKS_ARRAY_SIZE(INIT_COMMON_PARAMS),
        &initParamSet);
    ret = HksGenerateKey(&TEST_INVISABLE_KEY_ALIAS, initParamSet, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&initParamSet);

    struct HksParamSet *queryParamSet = nullptr;
    struct HksParam addParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
    };
    ret = HuksTest::TestBuildParamSet(addParams, sizeof(addParams) / sizeof(addParams[0]), &queryParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HuksTest::TestBuildParamSet failed, ret = " << ret;

    struct HksKeyAliasSet *outData = nullptr;
    ret = HksListAliases(queryParamSet, &outData);

    bool compareRes = IsMatch(outData);

    HksFreeParamSet(&queryParamSet);
    EXPECT_EQ(compareRes, true) << "HksListAliases failed, ret = " << ret;
    HksFreeKeyAliasSet(outData);
}

}
