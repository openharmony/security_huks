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

#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>

#include "file_ex.h"
#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"

#include "securec.h"

using namespace testing::ext;
namespace Unittest::HksThreeStageMultiThreadTest {
class HksThreeStageMultiThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksThreeStageMultiThreadTest::SetUpTestCase(void)
{
}

void HksThreeStageMultiThreadTest::TearDownTestCase(void)
{
}

void HksThreeStageMultiThreadTest::SetUp()
{
}

void HksThreeStageMultiThreadTest::TearDown()
{
}

const uint32_t THREADS_NUM = 10;
static const uint32_t HKS_SM4_IV_SIZE = 16;

static uint8_t g_hksSm4TestIv[HKS_SM4_IV_SIZE] = {0};

static struct HksParam g_genParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_SM4
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = HKS_SM4_IV_SIZE,
            .data = static_cast<uint8_t *>(g_hksSm4TestIv)
        }
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_SM4_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    },
};

static int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramcount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        HKS_LOG_E("HksAddParams failed");
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        HKS_LOG_E("HksBuildParamSet failed!");
        return ret;
    }

    return ret;
}

static int32_t GenerateKeyTest(const char *tmpKeyAlias)
{
    struct HksBlob keyAlias = { strlen(tmpKeyAlias),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(tmpKeyAlias)) };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams, sizeof(g_genParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
    return ret;
}

static int32_t DeleteKeyTest(const char *tmpKeyAlias)
{
    struct HksBlob keyAlias = { strlen(tmpKeyAlias),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(tmpKeyAlias)) };
    return HksDeleteKey(&keyAlias, nullptr);
}

static struct HksParam g_encryptParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_SM4
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = HKS_SM4_IV_SIZE,
            .data = static_cast<uint8_t *>(g_hksSm4TestIv)
        }
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_SM4_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    },
};

static int32_t InitSessionTest(const char *tmpKeyAlias, struct HksBlob *handle)
{
    struct HksBlob keyAlias = { strlen(tmpKeyAlias),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(tmpKeyAlias)) };
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = InitParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = HksInit(&keyAlias, encryptParamSet, handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInit failed.";
    HksFreeParamSet(&encryptParamSet);
    return ret;
}

static int32_t UpdateSessionTest(struct HksBlob *handle)
{
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = InitParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint32_t indataSize = 8192;
    uint32_t outdataSize = 8208;
    uint8_t *indata = static_cast<uint8_t *>(HksMalloc(indataSize));
    struct HksBlob indataBlob = { indataSize, indata };
    uint8_t *outdata = static_cast<uint8_t *>(HksMalloc(outdataSize));
    struct HksBlob outdataBlob = { outdataSize, outdata };
    ret = HksUpdate(handle, encryptParamSet, &indataBlob, &outdataBlob);
    HKS_IF_NOT_SUCC_LOGE(ret, "HksUpdate failed.")
    HksFreeParamSet(&encryptParamSet);
    HKS_FREE(indata);
    HKS_FREE(outdata);
    return ret;
}

static int32_t FinishSessionTest(struct HksBlob *handle)
{
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = InitParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint32_t indataSize = 8192;
    uint8_t *indata = static_cast<uint8_t *>(HksMalloc(indataSize));
    struct HksBlob indataBlob = { indataSize, indata };
    uint32_t outdataSize = 8208;
    uint8_t *outdata = static_cast<uint8_t *>(HksMalloc(outdataSize));
    struct HksBlob outdataBlob = { outdataSize, outdata };
    ret = HksFinish(handle, encryptParamSet, &indataBlob, &outdataBlob);
    HKS_IF_NOT_SUCC_LOGE(ret, "HksFinish failed.")
    HksFreeParamSet(&encryptParamSet);
    HKS_FREE(indata);
    HKS_FREE(outdata);
    return ret;
}

static int32_t AbortSessionTest(struct HksBlob *handle)
{
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = InitParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = HksAbort(handle, encryptParamSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "HksAbort failed.")
    HksFreeParamSet(&encryptParamSet);
    return ret;
}

static void ThreeStageTest(uint32_t testIndex)
{
    char alias[20];
    (void)sprintf_s(alias, sizeof(alias), "%s%u", "test_three_stage", testIndex);
    uint8_t handleE[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handleE };
    int32_t ret = GenerateKeyTest(alias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKeyTest failed.";
    ret = InitSessionTest(alias, &handleBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitSessionTest failed.";

    std::vector<std::thread> threads;
    srand(time(nullptr));
    uint32_t finishPos = static_cast<uint32_t>(rand() / RAND_MAX) * THREADS_NUM;

    for (uint32_t i = 0; i < THREADS_NUM; i++) {
        if (finishPos == i) {
            threads.emplace_back(std::thread(AbortSessionTest, &handleBlob));
        } else {
            threads.emplace_back(std::thread(UpdateSessionTest, &handleBlob));
        }
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(ret, HKS_SUCCESS) << "InitSessionTest failed.";

    std::vector<std::thread> threads2;
    ret = InitSessionTest(alias, &handleBlob);
    threads2.emplace_back(std::thread(FinishSessionTest, &handleBlob));
    threads2.emplace_back(std::thread(AbortSessionTest, &handleBlob));

    for (auto &t : threads2) {
        t.join();
    }

    ret = DeleteKeyTest(alias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKeyTest failed.";
}

/**
 * @tc.name: HksThreeStageMultiThreadTest.HksThreeStageMultiThreadTest001
 * @tc.desc: test three stage multi thread test
 * @tc.type: FUNC
 */
HWTEST_F(HksThreeStageMultiThreadTest, HksThreeStageMultiThreadTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksThreeStageMultiThreadTest001");
    std::vector<std::thread> threads;

    for (uint32_t i = 0; i < THREADS_NUM; i++) {
        threads.emplace_back(std::thread(&ThreeStageTest, i));
    }

    for (auto &t : threads) {
        t.join();
    }
    int32_t ret = HksInitialize();
    ASSERT_TRUE(ret == HKS_SUCCESS);
}
}