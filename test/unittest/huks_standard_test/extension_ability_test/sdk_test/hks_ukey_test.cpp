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

#include "hks_ukey_test.h"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_tag.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

using namespace testing::ext;
namespace {
class HksUKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static struct HksBlob *StringToHuksBlob(const char *str)
    {
        if (!str) return nullptr;
        uint32_t size = strlen(str);
        struct HksBlob *blob = new HksBlob;
        blob->data = new uint8_t[size];
        memcpy(blob->data, str, size);
        blob->size = size;
        return blob;
    }

    // 工具函数：构造 HksParamSet
    static int32_t ConstructTestParamSet(struct HksParamSet **paramSet)
    {
        HksParam params[] = {
            {
                .tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME,
                .blob = { (uint8_t *)"ability_name_value", 18 }
            },
            {
                .tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN,
                .blob = StringToHuksBlob("123789")
            }
        };

        *paramSet = (struct HksParamSet *)HksMalloc(sizeof(struct HksParamSet));
        if (*paramSet == NULL) {
            return HKS_ERROR_MALLOC_FAIL;
        }
        (*paramSet)->paramSetSize = sizeof(HksParamSet) + sizeof(HksParam) * (sizeof(params) / sizeof(params[0]));
        (*paramSet)->params = params;
        (*paramSet)->paramsCnt = sizeof(params) / sizeof(params[0]);
    }
};

void HksUKeyTest::SetUpTestCase(void)
{
}

void HksUKeyTest::TearDownTestCase(void)
{
}

void HksUKeyTest::SetUp()
{
}

void HksUKeyTest::TearDown()
{
}

/**
 * @tc.name: HksUKeyTest.HksRegisterProviderTest
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksUKeyTest, HksRegisterProviderTest, TestSize.Level0)
{
    struct HksBlob *name = StringToHuksBlob("testHap");
    EXPECT_TRUE(name != nullptr);

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksRegisterProvider(name, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("HksRegisterProviderTest, ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&name);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_RegisterProvider pass!");
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksRegisterProviderWithoutNameTest, TestSize.Level0)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksRegisterProvider(nullptr, paramSet);
    if (ret != HKS_ERROR_NULL_POINTER) {
        HKS_TEST_LOG_I("failed, HksRegisterProviderWithoutNameTest ret = %d", ret);
    }
    EXPECT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    TestFreeBlob(&name);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_RegisterProviderWithoutNameTest pass!");
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}


HWTEST_F(HksUKeyTest, HksUnregisterProvider, TestSize.Level0)
{
    struct HksBlob *name = StringToHuksBlob("testHap");
    EXPECT_TRUE(name != nullptr);

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksRegisterProvider(name, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("falied, HksUnregisterProvider, ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&name);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_UnregisterProvider pass!");
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksUnregisterProviderWithoutNameTest, TestSize.Level0)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksRegisterProvider(nullptr, paramSet);
    if (ret != HKS_ERROR_NULL_POINTER) {
        HKS_TEST_LOG_I("failed, HksRegisterProviderWithoutNameTest ret = %d", ret);
    }
    EXPECT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_UnregisterProviderWithoutNameTest pass!");
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

HWTEST_F(HksUKeyTest, HksAuthUkeyPinTest, TestSize.Level0)
{
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob *resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId != nullptr);

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    uint32_t retryCount = 0;

    ret = HksAuthUkeyPin(resourceId, paramSet, &retryCount);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksAuthUkeyPin ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_AuthUkeyPin pass!");
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksGetUkeyPinAuthStateTest, TestSize.Level0)
{
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob *resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId != nullptr);

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    int32_t status = 0;

    ret = HksGetUkeyPinAuthState(resourceId, paramSet, &status);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksGetUkeyPinAuthState ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksOpenRemoteHandleTest, TestSize.Level0)
{
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob *resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId != nullptr);

    struct HksBlob remoteHandleOut = { 0, NULL };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksOpenRemoteHandle(resourceId, paramSet, &remoteHandleOut);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksOpenRemoteHandle ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    ASSERT_TRUE(ret == 0);
}


HWTEST_F(HksUKeyTest, HksGetRemoteHandleTest, TestSize.Level0)
{
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob *resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId != nullptr);

    struct HksBlob remoteHandleOut = { 0, NULL };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksOpenRemoteHandle(resourceId, paramSet, &remoteHandleOut);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksOpenRemoteHandle ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksClearPinAuthStateTest, TestSize.Level0)
{
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob *resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId != nullptr);

    ret = HksClearPinAuthState(resourceId);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksClearPinAuthState ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksGetRemotePropertyTest, TestSize.Level0)
{
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob *resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId != nullptr);

    struct HksBlob *propertyId = StringToHuksBlob(index);
    EXPECT_TRUE(propertyId != nullptr);

    struct HksParamSet *propertySetOut = NULL;

    ret = HksGetRemoteProperty(resourceId, propertyId, &propertySetOut);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksGetRemoteProperty ret = %d", ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    TestFreeBlob(&propertyId);
    HksFreeParamSet(&propertySetOut);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    ASSERT_TRUE(ret == 0);
}
} // namespace