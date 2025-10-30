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
#include "securec.h"
#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_tag.h"
#include "hks_mem.h"
#include "hks_test_log.h"
#include "hks_api.h"
#include "hks_test_common_h.h"

using namespace testing::ext;
namespace {
class HksUKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static struct HksBlob StringToHuksBlob(const char *str)
    {
        struct HksBlob blob;
        if (!str) {
            blob.size = 0;
            blob.data = nullptr;
            return blob;
        }
        blob.size = strlen(str);
        blob.data = (uint8_t *)str; // 注意：这里没有分配新内存，只是指向原字符串
        return blob;
    }

    // 工具函数：构造 HksParamSet
    static int32_t ConstructTestParamSet(struct HksParamSet **paramSet)
    {
        HksParam params[] = {
            {
                .tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME,
                .blob = { 18, (uint8_t *)"ability_name_value" }
            },
            {
                .tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN,
                .blob = { .size = 6, .data = (uint8_t *)"123789" }
            }
        };

        uint32_t paramsCnt = sizeof(params) / sizeof(params[0]);
        uint32_t totalSize = sizeof(struct HksParamSet) + sizeof(struct HksParam) * paramsCnt;

        *paramSet = (struct HksParamSet *)HksMalloc(totalSize);
        if (*paramSet == nullptr) {
            return HKS_ERROR_MALLOC_FAIL;
        }
        (*paramSet)->paramSetSize = totalSize;
        (*paramSet)->paramsCnt = paramsCnt;

        for (uint32_t i = 0; i < paramsCnt; i++) {
            (*paramSet)->params[i] = params[i];
        }

        return 0;
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

HWTEST_F(HksUKeyTest, HksRegisterProviderTest, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksBlob name = StringToHuksBlob("testHap");
    EXPECT_TRUE(name.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksRegisterProvider(&name, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("HksRegisterProviderTest, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_RegisterProvider pass!");
    EXPECT_TRUE(ret == HKS_ERROR_EXEC_FUNC_FAIL);
}

HWTEST_F(HksUKeyTest, HksUnregisterProvider, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksBlob name = StringToHuksBlob("testHap");
    EXPECT_TRUE(name.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksUnregisterProvider(&name, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("falied, HksUnregisterProvider, ret = %d", ret);
    }
    
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_UnregisterProvider pass!");
    EXPECT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksAuthUkeyPinTest, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    uint32_t retryCount = 0;

    ret = HksAuthUkeyPin(&resourceId, paramSet, &retryCount);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksAuthUkeyPin ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_AuthUkeyPin pass!");
    EXPECT_TRUE(ret == HKS_ERROR_REMOTE_HANDLE_NOT_FOUND);
}

HWTEST_F(HksUKeyTest, HksGetUkeyPinAuthStateTest, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    int32_t status = 0;

    ret = HksGetUkeyPinAuthState(&resourceId, paramSet, &status);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksGetUkeyPinAuthState ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    EXPECT_TRUE(ret == HKS_ERROR_REMOTE_HANDLE_NOT_FOUND);
}

HWTEST_F(HksUKeyTest, HksOpenRemoteHandleTest, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksOpenRemoteHandle(&resourceId, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksOpenRemoteHandle ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    EXPECT_TRUE(ret == HKS_ERROR_REMOTE_PROXY_GET_FAILED);
}

HWTEST_F(HksUKeyTest, HksCloseRemoteHandleTest, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    ret = HksCloseRemoteHandle(&resourceId, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksCloseRemoteHandle ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    EXPECT_TRUE(ret == HKS_ERROR_REMOTE_HANDLE_NOT_FOUND);
}

HWTEST_F(HksUKeyTest, HksClearPinAuthStateTest, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId.data != nullptr);

    ret = HksClearUkeyPinAuthState(&resourceId);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksClearPinAuthState ret = %d", ret);
    }

    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    EXPECT_TRUE(ret == HKS_ERROR_REMOTE_HANDLE_NOT_FOUND);
}

HWTEST_F(HksUKeyTest, HksGetRemotePropertyTest, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId.data != nullptr);

    struct HksBlob propertyId = StringToHuksBlob(index);
    EXPECT_TRUE(propertyId.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    struct HksParamSet *propertySetOut = nullptr;

    ret = HksGetRemoteProperty(&resourceId, &propertyId, paramSet, &propertySetOut);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksGetRemoteProperty ret = %d", ret);
    }

    HksFreeParamSet(&propertySetOut);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_GetUkeyPinAuthState pass!");
    EXPECT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

HWTEST_F(HksUKeyTest, HksExportProviderCertificatesWithoutNameTest, TestSize.Level0)
{
    int32_t ret = 0;

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    HksExtCertInfoSet certSet = { 0, nullptr };

    ret = HksExportProviderCertificates(nullptr, paramSet, &certSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksExportProviderCertificates ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_HksExportProviderCertificates pass!");
    EXPECT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(HksUKeyTest, HksExportProviderCertificatesTest, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksBlob name = StringToHuksBlob("testHap");
    EXPECT_TRUE(name.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    HksExtCertInfoSet certSet = { 0, nullptr };

    ret = HksExportProviderCertificates(&name, paramSet, &certSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksExportProviderCertificates ret = %d", ret);
    }
    
    HksFreeParamSet(&paramSet);
    HksFreeExtCertSet(&certSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_HksExportProviderCertificates pass!");
    EXPECT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksExportCertificatesTest, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index =
        "{\"providerName\":\"testHap\","
        "\"abilityName\":\"com.cryptoapplication\","
        "\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_TRUE(resourceId.data != nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_TRUE(ret == 0);

    HksExtCertInfoSet certSet = { 0, nullptr };

    ret = HksExportCertificate(&resourceId, paramSet, &certSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, HksExportCertificate ret = %d", ret);
    }
    
    HksFreeParamSet(&paramSet);
    HksFreeExtCertSet(&certSet);
    HKS_TEST_LOG_I("TestHksUKey, Testcase_HksExportCertificate pass!");
    EXPECT_TRUE(ret == HKS_ERROR_REMOTE_PROXY_GET_FAILED);
}

HWTEST_F(HksUKeyTest, HksFreeExtCertSetTest, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksExtCertInfoSet certInfoSet = { 0, nullptr };
    certInfoSet.count = 2;
    certInfoSet.certs = (struct HksExtCertInfo *)HksMalloc(sizeof(struct HksExtCertInfo) * certInfoSet.count);
    EXPECT_TRUE(certInfoSet.certs != nullptr);

    for(uint32_t i = 0; i < certInfoSet.count; i++) {
        certInfoSet.certs[i].purpose = i + 1;

        const char *indexStr = (i == 0) ? "cert_index_0" : "cert_index_1";
        const char *certStr = (i == 0) ? "certificate_data_0" : "certificate_data_1";

        certInfoSet.certs[i].index.size = strlen(indexStr);
        certInfoSet.certs[i].index.data = (uint8_t *)HksMalloc(certInfoSet.certs[i].index.size);
        EXPECT_TRUE(certInfoSet.certs[i].index.data != nullptr);
        ret = memcpy_s(certInfoSet.certs[i].index.data, certInfoSet.certs[i].index.size, indexStr, certInfoSet.certs[i].index.size);
        EXPECT_TRUE(ret == 0);

        certInfoSet.certs[i].cert.size = strlen(certStr);
        certInfoSet.certs[i].cert.data = (uint8_t *)HksMalloc(certInfoSet.certs[i].cert.size);
        EXPECT_TRUE(certInfoSet.certs[i].cert.data != nullptr);
        ret = memcpy_s(certInfoSet.certs[i].cert.data, certInfoSet.certs[i].cert.size, certStr, certInfoSet.certs[i].cert.size);
        EXPECT_TRUE(ret == 0);
    }

    HksFreeExtCertSet(&certInfoSet);

    EXPECT_EQ(certInfoSet.count, 0u);

    HKS_TEST_LOG_I("HksFreeExtCertSet executed successfully.");

    HksFreeExtCertSet(&certInfoSet);
    EXPECT_EQ(certInfoSet.count, 0u);

    HKS_TEST_LOG_I("TestHksUKey, Testcase_HksFreeExtCertSet pass!");
} 
}// namespace