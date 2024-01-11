/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "hks_openssl_kdf.h"
#include "hks_log.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {

}  // namespace

class HksCryptoHalSm3Kdf : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:

    void RunTestCase(const struct HksBlob *mainKey, struct HksBlob *derivedKey) const
    {
#if defined(_USE_OPENSSL_)
        struct HksKeyDerivationParam derParam = {
            .info = {
                .size = strlen("The factor1"),
                .data = (uint8_t *)"The factor1"
            },
            .digestAlg = HKS_DIGEST_SM3
        };
        struct HksKeySpec derivationSpec = { HKS_ALG_GMKDF, HKS_KEY_BYTES(HKS_SM4_KEY_SIZE_128), &derParam };
        EXPECT_EQ(HksOpensslSmKdf(mainKey, &derivationSpec, derivedKey), HKS_SUCCESS);
#endif
    }
};

void HksCryptoHalSm3Kdf::SetUpTestCase(void)
{
}

void HksCryptoHalSm3Kdf::TearDownTestCase(void)
{
}

void HksCryptoHalSm3Kdf::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalSm3Kdf::TearDown()
{
}

/**
 * @tc.number    : HksCryptoHalSm3Kdf_001
 * @tc.name      : HksCryptoHalSm3Kdf_001
 * @tc.desc      : Using HksOpensslSmKdf kdf key.
 */
HWTEST_F(HksCryptoHalSm3Kdf, HksCryptoHalSm3Kdf_001, Function | SmallTest | Level0)
{
    HKS_LOG_I("enter HksCryptoHalSm3Kdf_001");
    std::string hexData = "64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE58D225EC"
        "A784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78";
    uint32_t dataLen = hexData.size() / HKS_COUNT_OF_HALF;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint8_t hashData[19] = {0};
    struct HksBlob hash = { 19, hashData };
    RunTestCase(&message, &hash);
    HKS_FREE(message.data);
}

/**
 * @tc.number    : HksCryptoHalSm3Kdf_002
 * @tc.name      : HksCryptoHalSm3Kdf_002
 * @tc.desc      : Using HksOpensslSmKdf kdf key.
 */
HWTEST_F(HksCryptoHalSm3Kdf, HksCryptoHalSm3Kdf_002, Function | SmallTest | Level0)
{
    std::string hexData = "11223344556677881122334455667788";
    uint32_t dataLen = hexData.size() / HKS_COUNT_OF_HALF;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint8_t hashData[32] = {0};
    struct HksBlob hash = { 32, hashData };
    RunTestCase(&message, &hash);
    HKS_FREE(message.data);
}
/**
 * @tc.number    : HksCryptoHalSm3Kdf_003
 * @tc.name      : HksCryptoHalSm3Kdf_003
 * @tc.desc      : Using HksOpensslSmKdf kdf key.
 */
HWTEST_F(HksCryptoHalSm3Kdf, HksCryptoHalSm3Kdf_003, Function | SmallTest | Level0)
{
    std::string hexData = "EDF23102A566C932AE8BD613A8E865FE58D225ECA784AE300A81A2D48"
        "281A828E1CEDF11C4219099840265375077BF78";
    uint32_t dataLen = hexData.size() / HKS_COUNT_OF_HALF;

    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint8_t hashData[46] = {0};
    struct HksBlob hash = { 46, hashData };
    RunTestCase(&message, &hash);
    HKS_FREE(message.data);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS