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

#include "hks_client_service_adapter_test.h"

#include <gtest/gtest.h>
#include <string>

#include "file_ex.h"
#include "hks_client_service_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksClientServiceAdapterTest {
class HksClientServiceAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksClientServiceAdapterTest::SetUpTestCase(void)
{
}

void HksClientServiceAdapterTest::TearDownTestCase(void)
{
}

void HksClientServiceAdapterTest::SetUp()
{
}

void HksClientServiceAdapterTest::TearDown()
{
}

/**
 * @tc.name: HksClientServiceAdapterTest.HksClientServiceAdapterTest001
 * @tc.desc: tdd HksClientServiceAdapterTest001, function is TranslateFromX509PublicKey
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterTest, HksClientServiceAdapterTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterTest001");
    int32_t ret = TranslateFromX509PublicKey(HKS_ALG_RSA, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest001 failed, ret = " << ret;

    HksBlob *x509Key = reinterpret_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    x509Key->data = nullptr;
    ASSERT_EQ(x509Key == nullptr, false) << "x509Key malloc failed.";
    ret = TranslateFromX509PublicKey(HKS_ALG_RSA, x509Key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest001 failed, ret = " << ret;

    x509Key->data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob)));
    ASSERT_EQ(x509Key->data == nullptr, false) << "malloc failed.";
    x509Key->size = 0;
    ret = TranslateFromX509PublicKey(HKS_ALG_RSA, x509Key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest001 failed, ret = " << ret;

    x509Key->size = sizeof(HksBlob);
    ret = TranslateFromX509PublicKey(HKS_ALG_RSA, x509Key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest001 failed, ret = " << ret;
    HKS_FREE(x509Key->data);
    HKS_FREE(x509Key);
}

/**
 * @tc.name: HksClientServiceAdapterTest.HksClientServiceAdapterTest002
 * @tc.desc: tdd HksClientServiceAdapterTest002, function is TranslateToX509PublicKey
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterTest, HksClientServiceAdapterTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterTest002");
    int32_t ret = TranslateToX509PublicKey(nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest002 failed, ret = " << ret;

    HksBlob *pubKey = reinterpret_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    pubKey->data = nullptr;
    ASSERT_EQ(pubKey == nullptr, false) << "pubKey malloc failed.";
    ret = TranslateToX509PublicKey(pubKey, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest002 failed, ret = " << ret;

    pubKey->data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob)));
    ASSERT_EQ(pubKey->data == nullptr, false) << "malloc failed.";
    pubKey->size = 0;
    ret = TranslateToX509PublicKey(pubKey, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest002 failed, ret = " << ret;

    pubKey->size = sizeof(HksBlob);
    ret = TranslateToX509PublicKey(pubKey, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest002 failed, ret = " << ret;

    ret = TranslateToX509PublicKey(pubKey, pubKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterTest002 failed, ret = " << ret;

    HKS_FREE(pubKey->data);
    HKS_FREE(pubKey);
}
}