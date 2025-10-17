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

#include "hks_test_adapt_for_de.h"
#include "hks_test_three_stage.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_mem.h"
#include "hks_type.h"
#include "hks_log.h"

using namespace testing::ext;
namespace {
class HksImportKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksImportKeyTest::SetUpTestCase(void)
{
}

void HksImportKeyTest::TearDownTestCase(void)
{
}

void HksImportKeyTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), HKS_SUCCESS);
}

void HksImportKeyTest::TearDown()
{
}

#ifndef _CUT_AUTHENTICATE_

struct ImportKeyCaseParams {
    std::vector<HksParam> params;
    uint32_t keySize = 0;
    HksErrorCode importKeyResult = HksErrorCode::HKS_SUCCESS;
};

static int32_t ImportTest(const struct ImportKeyCaseParams &testCaseParams)
{
    struct HksParamSet *importParamSet = nullptr;
    int32_t ret = InitParamSet(&importParamSet, testCaseParams.params.data(), testCaseParams.params.size());
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint8_t *keyData = (uint8_t *)HksMalloc(testCaseParams.keySize);
    if (keyData == nullptr) {
        HksFreeParamSet(&importParamSet);
        return HKS_ERROR_MALLOC_FAIL;
    }
    struct HksBlob key = { testCaseParams.keySize, keyData };
    (void)HksGenerateRandom(nullptr, &key);

    uint8_t alias[] = "test_import_key";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksImportKeyForDe(&keyAlias, importParamSet, &key);
    HksFreeParamSet(&importParamSet);
    HKS_FREE(key.data);
    EXPECT_EQ(ret, testCaseParams.importKeyResult);
    if (ret == HKS_SUCCESS) {
        (void)HksDeleteKeyForDe(&keyAlias, nullptr);
    }

    return (ret == testCaseParams.importKeyResult) ? HKS_SUCCESS : HKS_FAILURE;
}

struct ImportKeyCaseParams HKS_IMPORT_TEST_001_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = 2048 }
        },
    .keySize = 256,
    .importKeyResult = HKS_SUCCESS,
};

/**
 * @tc.name: HksImportKeyTest.HksImportKeyTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksImportKeyTest, HksImportKeyTest001, TestSize.Level0)
{
    std::vector<std::tuple<uint32_t, uint32_t, HksErrorCode>> testKeyLen = {
        {8, 1, HKS_SUCCESS},
        {16, 2, HKS_SUCCESS},
        {24, 3, HKS_SUCCESS},
        {256, 32, HKS_SUCCESS},
        {1008, 126, HKS_SUCCESS},
        {1024, 128, HKS_SUCCESS},
        {1040, 130, HKS_SUCCESS},
    };
    for (auto &[keyLen, keySize, ret] : testKeyLen) {
        HKS_IMPORT_TEST_001_PARAMS.params[2].uint32Param = keyLen;
        HKS_IMPORT_TEST_001_PARAMS.keySize = keySize;
        HKS_IMPORT_TEST_001_PARAMS.importKeyResult = ret;
        HKS_LOG_E("key len is %u", keyLen);
        EXPECT_EQ(ImportTest(HKS_IMPORT_TEST_001_PARAMS), HKS_SUCCESS);
    }
}
#endif /* _CUT_AUTHENTICATE_ */

}