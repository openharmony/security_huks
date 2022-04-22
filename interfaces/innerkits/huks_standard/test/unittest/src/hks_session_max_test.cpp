/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_log.h"
#include "hks_type.h"

using namespace testing::ext;
namespace {
static const uint32_t MAX_SESSION_NUM = 15;
class HksSessionMaxTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSessionMaxTest::SetUpTestCase(void)
{
}

void HksSessionMaxTest::TearDownTestCase(void)
{
}

void HksSessionMaxTest::SetUp()
{
}

void HksSessionMaxTest::TearDown()
{
}

static void GenerateBaseKey(const struct HksBlob *alias)
{
    HKS_TEST_LOG_I("Generate Base Key");
    struct HksParamSet *paramSet = NULL;
    ASSERT_TRUE(HksInitParamSet(&paramSet) == 0);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SHA256 },
    };

    ASSERT_TRUE(HksAddParams(paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0])) == 0);
    ASSERT_TRUE(HksBuildParamSet(&paramSet) == 0);
    ASSERT_TRUE(HksGenerateKey(alias, paramSet, NULL) == 0);

    HksFreeParamSet(&paramSet);
}

static void ConstructInitParamSet(struct HksParamSet **outParamSet)
{
    struct HksParamSet *paramSet = NULL;
    ASSERT_TRUE(HksInitParamSet(&paramSet) == 0);

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SHA256 },
    };

    ASSERT_TRUE(HksAddParams(paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0])) == 0);
    ASSERT_TRUE(HksBuildParamSet(&paramSet) == 0);

    *outParamSet = paramSet;
}

static void SessionMaxTest(const struct HksBlob *alias)
{
    uint64_t handle[MAX_SESSION_NUM];
    for (uint32_t i = 0; i < MAX_SESSION_NUM; ++i) {
        struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };
        struct HksParamSet *paramSet = NULL;
        ConstructInitParamSet(&paramSet);
        ASSERT_TRUE(HksInit(alias, paramSet, &handleBlob) == 0);
        HksFreeParamSet(&paramSet);
    }

    uint64_t handleMax;
    struct HksBlob handleMaxBlob = { sizeof(uint64_t), (uint8_t *)&handleMax };
    struct HksParamSet *paramSetMax = NULL;
    ConstructInitParamSet(&paramSetMax);
    ASSERT_TRUE(HksInit(alias, paramSetMax, &handleMaxBlob) == 0);
    ASSERT_TRUE(HksAbort(&handleMaxBlob, paramSetMax) == 0);
    HksFreeParamSet(&paramSetMax);

    for (uint32_t i = 0; i < MAX_SESSION_NUM; ++i) {
        struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };
        struct HksParamSet *paramSet = NULL;
        ConstructInitParamSet(&paramSet);
        ASSERT_TRUE(HksAbort(&handleBlob, paramSet) == 0);
        HksFreeParamSet(&paramSet);
    }
}

/**
 * @tc.name: HksSessionMaxTest.HksSessionMaxTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksSessionMaxTest, HksSessionMaxTest001, TestSize.Level0)
{
    uint8_t alias[] = "test_max_session_key_alias";
    struct HksBlob aliasBlob = { sizeof(alias), alias };
    GenerateBaseKey(&aliasBlob);

    SessionMaxTest(&aliasBlob);

    ASSERT_TRUE(HksDeleteKey(&aliasBlob, NULL) == 0);
}
}
