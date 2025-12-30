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

#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <thread>

#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_log.h"

using namespace testing::ext;
namespace {
static const uint32_t MAX_SESSION_NUM_TEST = 40;
static const uint32_t MAX_SESSION_NUM_SA = 32;
static const uint32_t HMAC_OUTPUT_SIZE = 32;
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
    std::system("find /data/service/el1/public/huks_service -user root -delete");
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
    ASSERT_TRUE(HksGenerateKeyForDe(alias, paramSet, NULL) == 0);

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
    uint64_t handle[MAX_SESSION_NUM_TEST];
    for (uint32_t i = 0; i < MAX_SESSION_NUM_TEST; ++i) {
        struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };
        struct HksParamSet *paramSet = NULL;
        ConstructInitParamSet(&paramSet);
        uint8_t tokenData[HMAC_OUTPUT_SIZE] = {0};
        struct HksBlob token = { sizeof(tokenData), tokenData };
        EXPECT_EQ(HksInitForDe(alias, paramSet, &handleBlob, &token), HKS_SUCCESS);
        HksFreeParamSet(&paramSet);
    }

    for (uint32_t i = 0; i < MAX_SESSION_NUM_TEST; ++i) {
        struct HksParamSet *paramSet = NULL;
        ConstructInitParamSet(&paramSet);

        uint8_t tmpInput[] = "testForSessionMaxTest";
        uint8_t tmpOutput[HMAC_OUTPUT_SIZE] = {0};
        struct HksBlob input = { sizeof(tmpInput), tmpInput };
        struct HksBlob output = { sizeof(tmpOutput), tmpOutput };
        struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };

        if (i < MAX_SESSION_NUM_TEST - MAX_SESSION_NUM_SA) {
            EXPECT_EQ(HksUpdateForDe(&handleBlob, paramSet, &input, &output), HKS_ERROR_NOT_EXIST);
            EXPECT_EQ(HksFinishForDe(&handleBlob, paramSet, &input, &output), HKS_ERROR_NOT_EXIST);
        } else {
            EXPECT_EQ(HksUpdateForDe(&handleBlob, paramSet, &input, &output), HKS_SUCCESS) << "i:" << i;
            EXPECT_EQ(HksFinishForDe(&handleBlob, paramSet, &input, &output), HKS_SUCCESS) << "i:" << i;
        }

        HksFreeParamSet(&paramSet);
    }

    for (uint32_t i = 0; i < MAX_SESSION_NUM_TEST; ++i) {
        struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };
        struct HksParamSet *paramSet = NULL;
        ConstructInitParamSet(&paramSet);
        EXPECT_EQ(HksAbort(&handleBlob, paramSet), HKS_SUCCESS) << "i:" << i;
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

    EXPECT_EQ(HksDeleteKeyForDe(&aliasBlob, NULL), 0);
}

/**
 * @tc.name: HksSessionMaxTest.HksSessionMaxTest002
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksSessionMaxTest, HksSessionMaxTest002, TestSize.Level0)
{
    struct HksParamSet *paramSet = NULL;
    ConstructInitParamSet(&paramSet);

    uint8_t tmpInput[] = "testForSessionMaxTest";
    uint8_t tmpOutput[HMAC_OUTPUT_SIZE] = {0};
    struct HksBlob input = { sizeof(tmpInput), tmpInput };
    struct HksBlob output = { sizeof(tmpOutput), tmpOutput };
    uint64_t temp = HMAC_OUTPUT_SIZE;
    struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&temp };

    EXPECT_EQ(HksUpdateForDe(&handleBlob, paramSet, &input, &output), HKS_ERROR_NOT_EXIST);
    EXPECT_EQ(HksFinishForDe(&handleBlob, paramSet, &input, &output), HKS_ERROR_NOT_EXIST);
    EXPECT_EQ(HksAbort(&handleBlob, paramSet), HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksSessionMaxTest.HksSessionMaxTest003
 * @tc.desc: stress init test;
 * @tc.type: FUNC
 */
HWTEST_F(HksSessionMaxTest, HksSessionMaxTest003, TestSize.Level0)
{
    static constexpr const uint32_t STRESS_SESSION_NUM_TEST = 1000;
    static constexpr const uint32_t THREAD_NUM = 10;

    std::vector<std::string> names{};
    std::vector<HksBlob> nameBlobs{};
    for (uint32_t i = 0; i < THREAD_NUM; ++i) {
        names.emplace_back(std::string("test_max_session_key_alias_") + std::to_string(i));
        nameBlobs.emplace_back(HksBlob{ names[i].size(), reinterpret_cast<uint8_t *>(names[i].data()) });
        GenerateBaseKey(&nameBlobs[i]);
    }

    struct HksParamSet *paramSet = NULL;
    ConstructInitParamSet(&paramSet);

    std::thread thrdsInit[THREAD_NUM]{};
    std::thread thrdsUpdate[THREAD_NUM]{};
    std::thread thrdsFinish[THREAD_NUM]{};
    std::thread thrdsAbort[THREAD_NUM]{};
    uint64_t handle[THREAD_NUM][STRESS_SESSION_NUM_TEST]{};
    for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
        thrdsInit[thrdNum] = std::thread([&handle, &paramSet, alias = nameBlobs[thrdNum], thrdNum]() {
            HKS_LOG_I("begin init stress");
            std::cout<<"begin init stress"<<std::endl;
            for (uint32_t i = 0; i < STRESS_SESSION_NUM_TEST; ++i) {
                struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[thrdNum][i] };
                uint8_t tokenData[HMAC_OUTPUT_SIZE] = {0};
                struct HksBlob token = { sizeof(tokenData), tokenData };
                EXPECT_EQ(HksInitForDe(&alias, paramSet, &handleBlob, &token), HKS_SUCCESS) << "i:" << i;
            }
        });
    }

    for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
        thrdsUpdate[thrdNum] = std::thread([&handle, &paramSet, alias = nameBlobs[thrdNum], thrdNum]() {
            HKS_LOG_I("begin update stress");
            std::cout<<"begin update stress"<<std::endl;
            for (uint32_t i = 0; i < STRESS_SESSION_NUM_TEST; ++i) {
                struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[thrdNum][i] };
                uint8_t inData[1] = {0};
                uint8_t outData[1] = {0};
                HksBlob inBlob = { sizeof(inData), inData };
                HksBlob outBlob = { sizeof(outData), outData };
                HksUpdateForDe(&handleBlob, paramSet, &inBlob, &outBlob);
            }
        });
    }

    for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
        thrdsFinish[thrdNum] = std::thread([&handle, &paramSet, alias = nameBlobs[thrdNum], thrdNum]() {
            HKS_LOG_I("begin finish stress");
            std::cout<<"begin finish stress"<<std::endl;
            for (uint32_t i = 0; i < STRESS_SESSION_NUM_TEST; ++i) {
                struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[thrdNum][i] };
                uint8_t inData[1] = {0};
                uint8_t outData[1] = {0};
                HksBlob inBlob = { sizeof(inData), inData };
                HksBlob outBlob = { sizeof(outData), outData };
                HksFinishForDe(&handleBlob, paramSet, &inBlob, &outBlob);
            }
        });
    }

    for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
        thrdsAbort[thrdNum] = std::thread([&handle, &paramSet, thrdNum]() {
            HKS_LOG_I("begin abort stress");
            std::cout<<"begin abort stress"<<std::endl;
            for (uint32_t i = 0; i < STRESS_SESSION_NUM_TEST; ++i) {
                struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[thrdNum][i] };
                EXPECT_EQ(HksAbort(&handleBlob, paramSet), HKS_SUCCESS) << "i:" << i;
            }
        });
    }

    for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
        thrdsInit[thrdNum].join();
        thrdsUpdate[thrdNum].join();
        thrdsFinish[thrdNum].join();
        thrdsAbort[thrdNum].join();
    }

    HksFreeParamSet(&paramSet);
    for (uint32_t i = 0; i < THREAD_NUM; ++i) {
        EXPECT_EQ(HksDeleteKeyForDe(&nameBlobs[i], NULL), 0);
    }
}

/**
 * @tc.name: HksSessionMaxTest.HksSessionMaxTest004
 * @tc.desc: stress init test;
 * @tc.type: FUNC
 */
HWTEST_F(HksSessionMaxTest, HksSessionMaxTest004, TestSize.Level0)
{
    static constexpr const uint32_t TEST_ROUND = 1000;
    static constexpr const uint32_t THREAD_NUM = 8;

    uint8_t nameBuf[] = "test_max_session_key_alias";
    HksBlob alias { sizeof(nameBuf) - 1, nameBuf };
    GenerateBaseKey(&alias);

    struct HksParamSet *paramSet = NULL;
    ConstructInitParamSet(&paramSet);

    for (uint32_t i = 0; i < TEST_ROUND; ++i) {
        std::thread thrdsUpdate[THREAD_NUM]{};
        std::thread thrdsFinish[THREAD_NUM]{};
        std::thread thrdsAbort[THREAD_NUM]{};
        uint8_t handleBuf[sizeof(uint64_t)]{};
        struct HksBlob handle = { sizeof(handleBuf), handleBuf };
        uint8_t tokenData[HMAC_OUTPUT_SIZE] = {0};
        struct HksBlob token = { sizeof(tokenData), tokenData };
        EXPECT_EQ(HksInitForDe(&alias, paramSet, &handle, &token), HKS_SUCCESS);

        for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
            thrdsUpdate[thrdNum] = std::thread([&handle, &paramSet]() {
                uint8_t inData[512] = {0};
                uint8_t outData[1] = {0};
                HksBlob inBlob = { sizeof(inData), inData };
                HksBlob outBlob = { sizeof(outData), outData };
                HksUpdateForDe(&handle, paramSet, &inBlob, &outBlob);
            });
        }

        for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
            thrdsFinish[thrdNum] = std::thread([&handle, &paramSet]() {
                uint8_t inData[1] = {0};
                uint8_t outData[1] = {0};
                HksBlob inBlob = { sizeof(inData), inData };
                HksBlob outBlob = { sizeof(outData), outData };
                HksFinishForDe(&handle, paramSet, &inBlob, &outBlob);
            });
        }

        for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
            thrdsAbort[thrdNum] = std::thread([&handle, &paramSet]() {
                EXPECT_EQ(HksAbort(&handle, paramSet), HKS_SUCCESS);
            });
        }

        for (uint32_t thrdNum = 0; thrdNum < THREAD_NUM; ++thrdNum) {
            thrdsUpdate[thrdNum].join();
            thrdsFinish[thrdNum].join();
            thrdsAbort[thrdNum].join();
        }
        if (i % 200 == 0) {
            std::cout<<"round "<<i<<std::endl;
        }
    }

    HksFreeParamSet(&paramSet);
    EXPECT_EQ(HksDeleteKeyForDe(&alias, NULL), 0);
}
}

