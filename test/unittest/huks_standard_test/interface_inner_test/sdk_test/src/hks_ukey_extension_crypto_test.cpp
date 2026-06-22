/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include <cstdint>

#include "hks_ukey_extension_crypto_test.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_mem.h"
#include "hks_test_log.h"
#include "hks_test_common.h"
#include "hks_ukey_global_errInfo.h"
#include "file_ex.h"

using namespace testing::ext;
namespace {
class HksUkeyExtensionCryptoTest : public testing::Test {
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
        blob.data = (uint8_t *)str;
        return blob;
    }

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

        return HKS_SUCCESS;
    }
};

void HksUkeyExtensionCryptoTest::SetUpTestCase(void)
{
}

void HksUkeyExtensionCryptoTest::TearDownTestCase(void)
{
}

void HksUkeyExtensionCryptoTest::SetUp()
{
}

void HksUkeyExtensionCryptoTest::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksRegisterProviderTest001, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksBlob name = StringToHuksBlob("testProvider");
    EXPECT_NE(name.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksRegisterProvider(&name, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksRegisterProviderTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksRegisterProviderTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksUnregisterProviderTest001, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksBlob name = StringToHuksBlob("testProvider");
    EXPECT_NE(name.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksUnregisterProvider(&name, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksUnregisterProviderTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksUnregisterProviderTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksQueryAbilityInfoTest001, TestSize.Level0)
{
    int32_t ret = 0;
    std::string resourceId = "{\"providerName\":\"P01\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.hmos.hukstest.ukey\",\"index\":{\"key\":\"key1\"}}";
    struct HksBlob resourceBlob = StringToHuksBlob(resourceId.data());
    EXPECT_NE(resourceBlob.data, nullptr);

    struct HksAbilityInfo abilityInfo = {};
    abilityInfo.abilityName.data = (uint8_t*)HksMalloc(128);
    abilityInfo.abilityName.size = 128;
    abilityInfo.bundleName.data = (uint8_t*)HksMalloc(128);
    abilityInfo.bundleName.size = 128;

    ret = HksQueryAbilityInfo(&resourceBlob, &abilityInfo);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksQueryAbilityInfoTest001, ret = %d", ret);
    }

    HKS_FREE_BLOB(abilityInfo.abilityName);
    HKS_FREE_BLOB(abilityInfo.bundleName);
    HKS_TEST_LOG_I("HksQueryAbilityInfoTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksExportProviderCertificatesTest001, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksBlob providerName = StringToHuksBlob("testProvider");
    EXPECT_NE(providerName.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksExtCertInfoSet certSet = { 0, nullptr };

    ret = HksExportProviderCertificates(&providerName, paramSet, &certSet);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksExportProviderCertificatesTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HksFreeExtCertSet(&certSet);
    HKS_TEST_LOG_I("HksExportProviderCertificatesTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksExportCertificateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksExtCertInfoSet certSet = { 0, nullptr };

    ret = HksExportCertificate(&resourceId, paramSet, &certSet);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksExportCertificateTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HksFreeExtCertSet(&certSet);
    HKS_TEST_LOG_I("HksExportCertificateTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksImportCertificateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;

    const char *certIndexStr = "cert_index_0";
    const char *certDataStr = "certificate_data_0";

    certInfo.index.size = strlen(certIndexStr);
    certInfo.index.data = (uint8_t *)HksMalloc(certInfo.index.size);
    EXPECT_NE(certInfo.index.data, nullptr);
    ret = memcpy_s(certInfo.index.data, certInfo.index.size, certIndexStr, certInfo.index.size);
    EXPECT_EQ(ret, EOK);

    certInfo.cert.size = strlen(certDataStr);
    certInfo.cert.data = (uint8_t *)HksMalloc(certInfo.cert.size);
    EXPECT_NE(certInfo.cert.data, nullptr);
    ret = memcpy_s(certInfo.cert.data, certInfo.cert.size, certDataStr, certInfo.cert.size);
    EXPECT_EQ(ret, EOK);

    ret = HksImportCertificate(&resourceId, &certInfo, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksImportCertificateTest001, ret = %d", ret);
    }

    HKS_FREE_BLOB(certInfo.index);
    HKS_FREE_BLOB(certInfo.cert);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksImportCertificateTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksAuthUkeyPinTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint32_t retryCount = 0;

    ret = HksAuthUkeyPin(&resourceId, paramSet, &retryCount);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksAuthUkeyPinTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksAuthUkeyPinTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksGetUkeyPinAuthStateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t status = 0;

    ret = HksGetUkeyPinAuthState(&resourceId, paramSet, &status);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksGetUkeyPinAuthStateTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksGetUkeyPinAuthStateTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksOpenRemoteHandleTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksOpenRemoteResource(&resourceId, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksOpenRemoteHandleTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksOpenRemoteHandleTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksCloseRemoteHandleTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksCloseRemoteResource(&resourceId, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksCloseRemoteHandleTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksCloseRemoteHandleTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksClearUkeyPinAuthStateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    ret = HksClearUkeyPinAuthState(&resourceId);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksClearUkeyPinAuthStateTest001, ret = %d", ret);
    }

    HKS_TEST_LOG_I("HksClearUkeyPinAuthStateTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksGetRemotePropertyTest001, TestSize.Level0)
{
    int32_t ret = 0;
    const char *index = "{\"providerName\":\"testProvider\",\"abilityName\":\"CryptoAbility\""
        ",\"bundleName\":\"com.test.app\",\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob resourceId = StringToHuksBlob(index);
    EXPECT_NE(resourceId.data, nullptr);

    const char *propertyIndex = "{\"property\":\"test_property\"}";
    struct HksBlob propertyId = StringToHuksBlob(propertyIndex);
    EXPECT_NE(propertyId.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *propertySetOut = nullptr;

    ret = HksSetOrGetRemoteProperty(HKS_EXT_PROPERTY_OPERATION_GET, &resourceId, &propertyId, paramSet, &propertySetOut);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksGetRemotePropertyTest001, ret = %d", ret);
    }

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&propertySetOut);
    HKS_TEST_LOG_I("HksGetRemotePropertyTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksGetResourceIdTest001, TestSize.Level0)
{
    int32_t ret = 0;
    struct HksBlob providerName = StringToHuksBlob("testProvider");
    EXPECT_NE(providerName.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    ret = ConstructTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob resourceId = {};
    resourceId.data = (uint8_t *)HksMalloc(256);
    resourceId.size = 256;
    EXPECT_NE(resourceId.data, nullptr);

    ret = HksGetResourceId(&providerName, paramSet, &resourceId);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("HksGetResourceIdTest001, ret = %d", ret);
    }

    HKS_FREE_BLOB(resourceId);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("HksGetResourceIdTest001 executed!");
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksUkeyExtensionCryptoTest, HksGetUkeyGlobalErrorTest001, TestSize.Level0)
{
    char testBuf[] = "this is a test err info";
    int32_t errVal = 0;
    (void)HksGetUkeyGlobalInfo(&errVal, testBuf, 0);
    (void)HksClearUkeyGlobalInfo();
}
}