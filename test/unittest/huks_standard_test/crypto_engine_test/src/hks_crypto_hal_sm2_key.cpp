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

const TestCaseParams HKS_CRYPTO_HAL_SM2_KEY_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_SM2,
        .keyLen = HKS_SM2_KEY_SIZE_256,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
}  // namespace

class HksCryptoHalSm2Key : public HksCryptoHalCommon, public testing::Test {
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

void HksCryptoHalSm2Key::SetUpTestCase(void)
{
}

void HksCryptoHalSm2Key::TearDownTestCase(void)
{
}

void HksCryptoHalSm2Key::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalSm2Key::TearDown()
{
}

/**
 * @tc.number    : HksCryptoHalSm2Key_001
 * @tc.name      : HksCryptoHalSm2Key_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate SM2-256bit key.
 */
#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_GENERATE_KEY)
HWTEST_F(HksCryptoHalSm2Key, HksCryptoHalSm2Key_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_SM2_KEY_001_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalSm2Key_002
 * @tc.name      : HksCryptoHalSm2Key_002
 * @tc.desc      : Generate key and export public key with SM2.
 */
#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_GET_PUBLIC_KEY)
HWTEST_F(HksCryptoHalSm2Key, HksCryptoHalSm2Key_002, Function | SmallTest | Level0)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_SM2,
        .keyLen = HKS_SM2_KEY_SIZE_256,
    };

    HksBlob key = { .size = 0, .data = NULL };

    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_SUCCESS);

    KeyMaterialEcc *keyMaterial = (KeyMaterialEcc *)key.data;
    ASSERT_NE(keyMaterial, nullptr);

    uint32_t keyOutLen = sizeof(KeyMaterialEcc) + keyMaterial->xSize + keyMaterial->ySize;
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