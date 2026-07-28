/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <iostream>

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
const uint32_t HMAC_KEY_SIZE = 256;
class HksCryptoHalHmacKey : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksCryptoHalHmacKey::SetUpTestCase(void)
{
}

void HksCryptoHalHmacKey::TearDownTestCase(void)
{
}

void HksCryptoHalHmacKey::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalHmacKey::TearDown()
{
}

/**
 * @tc.number    : HksCryptoHalHmacKey_001
 * @tc.name      : HksCryptoHalHmacKey_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate HMAC-256bit key.
 */
HWTEST_F(HksCryptoHalHmacKey, HksCryptoHalHmacKey_001, Function | SmallTest | Level0)
{
    std::map<uint32_t, int32_t> testKeyLen = {
        {0, HKS_ERROR_INVALID_ARGUMENT},
        {1, HKS_ERROR_INVALID_ARGUMENT},
        {8, HKS_SUCCESS},
        {9, HKS_ERROR_INVALID_ARGUMENT},
        {10, HKS_ERROR_INVALID_ARGUMENT},
        {16, HKS_SUCCESS},
        {24, HKS_SUCCESS},
        {256, HKS_SUCCESS},
        {1008, HKS_SUCCESS},
        {1024, HKS_SUCCESS},
        {1040, HKS_SUCCESS},
    };

    HksKeySpec spec = {
        .algType = HKS_ALG_HMAC,
        .keyLen = HMAC_KEY_SIZE,
        .algParam = nullptr,
    };

    HksBlob key = { .size = 0, .data = nullptr };
    for (auto &genKey : testKeyLen) {
        spec.keyLen = genKey.first;
        ASSERT_EQ(HksCryptoHalGenerateKey(&spec, &key), genKey.second);
    }
    HKS_FREE(key.data);
}

}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS