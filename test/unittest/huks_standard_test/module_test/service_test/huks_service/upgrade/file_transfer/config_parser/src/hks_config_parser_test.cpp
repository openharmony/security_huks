/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "hks_config_parser.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

#undef HUKS_SA_UPGRADE_CONFIG
#undef HUKS_HAP_UPGRADE_CONFIG
#undef HUKS_SA_SKIP_UPGRADE_CONFIG
#undef HUKS_HAP_SKIP_UPGRADE_CONFIG

#define HUKS_SA_UPGRADE_CONFIG { { 6, false, false }, { 7, false, true }, { 8, true, false }, { 9, true, true } }
#define HUKS_HAP_UPGRADE_CONFIG { { "com.example.demo1", true, true }, \
    { "com.example.demo2", true, false }, \
    { "com.example.demo3", false, true }, \
    { "com.example.demo4", false, false } }
#define HUKS_SA_SKIP_UPGRADE_CONFIG { 0, 10, 99 }
#define HUKS_HAP_SKIP_UPGRADE_CONFIG { "com.example.skip1", "com.example.skip2" }

#include "base/security/huks/services/huks_standard/huks_service/main/upgrade/file_transfer/src/hks_config_parser.c"

enum HksAtType g_accessTokenType = HKS_TOKEN_HAP;
char *g_hapName = NULL;

int32_t HksGetAtType(uint64_t accessTokenId, enum HksAtType *atType)
{
    *atType = g_accessTokenType;
    return HKS_SUCCESS;
}

int32_t HksGetHapNameFromAccessToken(int32_t tokenId, char *hapName, int32_t hapNameSize)
{
    (void)memcpy_s(hapName, hapNameSize, g_hapName, strlen(g_hapName));
    return HKS_SUCCESS;
}

using namespace testing::ext;
namespace Unittest::HksServiceUpgradeConfigParserTest {
class HksServiceUpgradeConfigParserTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksServiceUpgradeConfigParserTest::SetUpTestCase(void)
{
}

void HksServiceUpgradeConfigParserTest::TearDownTestCase(void)
{
}

void HksServiceUpgradeConfigParserTest::SetUp()
{
}

void HksServiceUpgradeConfigParserTest::TearDown()
{
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest001
 * @tc.desc: test HksParseConfig with hap, DE and front-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest001");
    g_hapName = const_cast<char *>("com.example.demo1");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet001 = NULL;
    (void)HksInitParamSet(&paramSet001);
    uint32_t userId001 = 0;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId001),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId001
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet001, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet001);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet001),
        .size = paramSet001->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(true, info.needDe);
    EXPECT_EQ(true, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(userId001, info.uid);
    EXPECT_EQ(userId001, info.userId);

    HksFreeParamSet(&paramSet001);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest002
 * @tc.desc: test HksParseConfig with hap, DE and self-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest002");
    g_hapName = const_cast<char *>("com.example.demo2");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet002 = NULL;
    (void)HksInitParamSet(&paramSet002);
    uint32_t userId002 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId002),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId002
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet002, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet002);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet002),
        .size = paramSet002->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(true, info.needDe);
    EXPECT_EQ(false, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(userId002, info.uid);
    EXPECT_EQ(userId002, info.userId);

    HksFreeParamSet(&paramSet002);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest003
 * @tc.desc: test HksParseConfig with hap, CE and front-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest003");
    g_hapName = const_cast<char *>("com.example.demo3");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet003 = NULL;
    (void)HksInitParamSet(&paramSet003);
    uint32_t userId003 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId003),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId003
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet003, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet003);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet003),
        .size = paramSet003->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(false, info.needDe);
    EXPECT_EQ(true, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(userId003, info.uid);
    EXPECT_EQ(userId003, info.userId);

    HksFreeParamSet(&paramSet003);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest004
 * @tc.desc: test HksParseConfig with hap, CE and self-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest004");
    g_hapName = const_cast<char *>("com.example.demo4");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet004 = NULL;
    (void)HksInitParamSet(&paramSet004);
    uint32_t userId004 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId004),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId004
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet004, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet004);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet004),
        .size = paramSet004->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(false, info.needDe);
    EXPECT_EQ(false, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(userId004, info.uid);
    EXPECT_EQ(userId004, info.userId);

    HksFreeParamSet(&paramSet004);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest005
 * @tc.desc: test HksParseConfig with hap, skip upgrade
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest005");
    g_hapName = const_cast<char *>("com.example.skip1");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet005 = NULL;
    (void)HksInitParamSet(&paramSet005);
    uint32_t userId005 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId005),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId005
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet005, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet005);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet005),
        .size = paramSet005->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(true, info.skipTransfer);
    HksFreeParamSet(&paramSet005);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest006
 * @tc.desc: test HksParseConfig with sa, ce and self-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest006");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet006 = NULL;
    (void)HksInitParamSet(&paramSet006);
    uint32_t userId006 = 0;
    uint32_t uid006 = 6;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid006),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId006
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet006, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet006);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet006),
        .size = paramSet006->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(false, info.needDe);
    EXPECT_EQ(false, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(uid006, info.uid);
    EXPECT_EQ(userId006, info.userId);

    HksFreeParamSet(&paramSet006);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest007
 * @tc.desc: test HksParseConfig with sa, ce and front-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest007");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet007 = NULL;
    (void)HksInitParamSet(&paramSet007);
    uint32_t userId007 = 0;
    uint32_t uid007 = 7;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid007),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId007
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet007, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet007);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet007),
        .size = paramSet007->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(false, info.needDe);
    EXPECT_EQ(true, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(uid007, info.uid);
    EXPECT_EQ(userId007, info.userId);

    HksFreeParamSet(&paramSet007);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest008
 * @tc.desc: test HksParseConfig with sa, de and self-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest008");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet008 = NULL;
    (void)HksInitParamSet(&paramSet008);
    uint32_t userId008 = 0;
    uint32_t uid008 = 8;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid008),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId008
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet008, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet008);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet008),
        .size = paramSet008->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(true, info.needDe);
    EXPECT_EQ(false, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(uid008, info.uid);
    EXPECT_EQ(userId008, info.userId);

    HksFreeParamSet(&paramSet008);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest009
 * @tc.desc: test HksParseConfig with sa, de and front-user
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest009");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet009 = NULL;
    (void)HksInitParamSet(&paramSet009);
    uint32_t userId009 = 0;
    uint32_t uid009 = 9;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid009),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId009
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet009, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet009);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet009),
        .size = paramSet009->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(true, info.needDe);
    EXPECT_EQ(true, info.needFrontUser);
    EXPECT_EQ(false, info.skipTransfer);
    EXPECT_EQ(uid009, info.uid);
    EXPECT_EQ(userId009, info.userId);

    HksFreeParamSet(&paramSet009);
}

/**
 * @tc.name: HksServiceUpgradeConfigParserTest.HksServiceUpgradeConfigParserTest010
 * @tc.desc: test HksParseConfig with sa, skip upgrade
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeConfigParserTest, HksServiceUpgradeConfigParserTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest010");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet010 = NULL;
    (void)HksInitParamSet(&paramSet010);
    uint32_t userId010 = 0;
    uint32_t uid010 = 10;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid010),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId010
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet010, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet010);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet010),
        .size = paramSet010->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    EXPECT_EQ(HKS_SUCCESS, HksParseConfig(&fileContent, &info));
    EXPECT_EQ(true, info.skipTransfer);

    HksFreeParamSet(&paramSet010);
}
}
