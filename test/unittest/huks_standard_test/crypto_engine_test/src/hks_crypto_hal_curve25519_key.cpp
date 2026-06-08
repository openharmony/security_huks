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
namespace {
struct TestCaseParams {
    HksKeySpec spec = {0};

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
};

#if defined(HKS_SUPPORT_X25519_C) && defined(HKS_SUPPORT_X25519_GENERATE_KEY)
const TestCaseParams HKS_CRYPTO_HAL_CURVE25519_KEY_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_X25519,
        .keyLen = HKS_CURVE25519_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .generateKeyResult = HKS_SUCCESS,
};
#endif

#if defined(HKS_SUPPORT_ED25519_C) && defined(HKS_SUPPORT_ED25519_GENERATE_KEY)
const TestCaseParams HKS_CRYPTO_HAL_CURVE25519_KEY_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_ED25519,
        .keyLen = HKS_CURVE25519_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .generateKeyResult = HKS_SUCCESS,
};
#endif
}  // namespace

class HksCryptoHalCurve25519Key : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        HksBlob keyTest02 = { .size = 0, .data = nullptr };
        ASSERT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &keyTest02), testCaseParams.generateKeyResult);
        if (testCaseParams.generateKeyResult == HKS_SUCCESS) {
            ASSERT_NE((uint32_t)0, keyTest02.size);
            ASSERT_NE(nullptr, keyTest02.data);
            HKS_FREE(keyTest02.data);
        }
    }
};

void HksCryptoHalCurve25519Key::SetUpTestCase(void)
{
}

void HksCryptoHalCurve25519Key::TearDownTestCase(void)
{
}

void HksCryptoHalCurve25519Key::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalCurve25519Key::TearDown()
{
}

#if defined(HKS_SUPPORT_X25519_C) && defined(HKS_SUPPORT_X25519_GENERATE_KEY)
/**
 * @tc.number    : HksCryptoHalCurve25519Key_001
 * @tc.name      : HksCryptoHalCurve25519Key_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate X25519-256bit key.
 */
HWTEST_F(HksCryptoHalCurve25519Key, HksCryptoHalCurve25519Key_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_CURVE25519_KEY_001_PARAMS);
}
#endif

#if defined(HKS_SUPPORT_ED25519_C) && defined(HKS_SUPPORT_ED25519_GENERATE_KEY)
/**
 * @tc.number    : HksCryptoHalCurve25519Key_002
 * @tc.name      : HksCryptoHalCurve25519Key_002
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate Ed25519-256bit key.
 */
HWTEST_F(HksCryptoHalCurve25519Key, HksCryptoHalCurve25519Key_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_CURVE25519_KEY_002_PARAMS);
}
#endif

#if defined(HKS_SUPPORT_X25519_C) && defined(HKS_SUPPORT_X25519_GET_PUBLIC_KEY)
/**
 * @tc.number    : HksCryptoHalCurve25519Key_003
 * @tc.name      : HksCryptoHalCurve25519Key_003
 * @tc.desc      : Generate key and export public key with X25519.
 */
HWTEST_F(HksCryptoHalCurve25519Key, HksCryptoHalCurve25519Key_003, Function | SmallTest | Level0)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_X25519,
        .keyLen = HKS_CURVE25519_KEY_SIZE_256,
    };

    HksBlob key = { .size = 0, .data = NULL };

    ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_SUCCESS);

    KeyMaterial25519 *keyMaterial = (KeyMaterial25519 *)key.data;
    ASSERT_NE(keyMaterial, nullptr);

    uint32_t keyOutLen = sizeof(KeyMaterial25519) + keyMaterial->pubKeySize;
    HksBlob keyOut = { .size = keyOutLen, .data = (uint8_t *)HksMalloc(keyOutLen) };
    ASSERT_NE(keyOut.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_SUCCESS);
    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
}
#endif

#if defined(HKS_SUPPORT_ED25519_C) && defined(HKS_SUPPORT_ED2519_GET_PUBLIC_KEY)
/**
 * @tc.number    : HksCryptoHalCurve25519Key_004
 * @tc.name      : HksCryptoHalCurve25519Key_004
 * @tc.desc      : Generate key and export public key with Ed25519.
 */
HWTEST_F(HksCryptoHalCurve25519Key, HksCryptoHalCurve25519Key_004, Function | SmallTest | Level0)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_ED25519,
        .keyLen = HKS_CURVE25519_KEY_SIZE_256,
    };

    HksBlob key = { .size = 0, .data = NULL };

    ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_SUCCESS);

    KeyMaterial25519 *keyMaterial = (KeyMaterial25519 *)key.data;
    ASSERT_NE(keyMaterial, nullptr);

    uint32_t keyOutLen = sizeof(KeyMaterial25519) + keyMaterial->pubKeySize;
    HksBlob keyOut = { .size = keyOutLen, .data = (uint8_t *)HksMalloc(keyOutLen) };
    ASSERT_NE(keyOut.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_SUCCESS);
    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS