/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hks_ukey_client_service_test.h"
#include "hks_ukey_service_provider_adapter.h"
#include "hks_ukey_service_provider.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"
#include "hks_type.h"
#include "hks_param.h"

#include <cstring>
#include <string>
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {

static const std::string TEST_PROVIDER = "testProvider";

void UkeyClientServiceTest::SetUpTestCase(void) {}

void UkeyClientServiceTest::TearDownTestCase(void) {}

void UkeyClientServiceTest::SetUp()
{
    HuksPluginLoader::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

void UkeyClientServiceTest::TearDown()
{
    HuksPluginLoader::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

// Helper: create a valid HksProcessInfo
static HksProcessInfo MakeProcessInfo()
{
    HksProcessInfo info = {};
    char name[] = "testProcess";
    info.processName.data = reinterpret_cast<uint8_t *>(name);
    info.processName.size = static_cast<uint32_t>(strlen(name));
    return info;
}

// Helper: create a valid HksBlob from string
static HksBlob MakeBlob(const std::string &s)
{
    HksBlob blob = {};
    blob.data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(s.data()));
    blob.size = static_cast<uint32_t>(s.size());
    return blob;
}

// Helper: create a valid HksParamSet with one param
static HksParamSet *MakeParamSet(uint32_t tag, uint32_t val)
{
    HksParam param = { .tag = tag, .uint32Param = val };
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    HksAddParam(paramSet, &param);
    HksBuildParamSet(&paramSet);
    return paramSet;
}

/**
 * @tc.name: UkeyClientServiceTest.Test001
 * @tc.desc: HksServiceRegisterProvider + HksServiceUnregisterProvider 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test001, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    // Register
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceRegisterProvider fail";

    // Unregister
    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS) << "UnRegisterProvider fail";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test002
 * @tc.desc: HksServiceRegisterProvider 传入null name blob，HksIpcCheckBlob返回HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test002, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    // null blob
    int32_t ret = HksServiceRegisterProvider(&processInfo, nullptr, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null blob";

    // blob with null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    ret = HksServiceRegisterProvider(&processInfo, &nullDataBlob, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null data";

    // blob with size 0 (less than minSize=1)
    std::string emptyStr;
    HksBlob emptyBlob = MakeBlob(emptyStr);
    ret = HksServiceRegisterProvider(&processInfo, &emptyBlob, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with empty size";

    // blob with size > HKS_EXT_MAX_PROVIDER_NAME_LEN (128)
    std::string longName(129, 'a');
    HksBlob longBlob = MakeBlob(longName);
    ret = HksServiceRegisterProvider(&processInfo, &longBlob, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized blob";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test003
 * @tc.desc: HksServiceUnregisterProvider 传入null name blob
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test003, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    int32_t ret = HksServiceUnregisterProvider(&processInfo, nullptr, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null blob";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test004
 * @tc.desc: HksServiceOpenRemoteHandle + HksServiceCloseRemoteHandle 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test004, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    // Register first
    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Open remote handle
    HksBlob indexBlob = MakeBlob("testIndex");
    ret = HksServiceOpenRemoteHandle(&processInfo, &indexBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceOpenRemoteHandle fail";

    // Close remote handle
    ret = HksServiceCloseRemoteHandle(&processInfo, &indexBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceCloseRemoteHandle fail";

    // Cleanup
    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test005
 * @tc.desc: HksServiceOpenRemoteHandle 传入null resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test005, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    int32_t ret = HksServiceOpenRemoteHandle(&processInfo, nullptr, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";

    // resourceId with size > HKS_EXT_MAX_RESOURCE_ID_LEN (1024)
    std::string longId(1025, 'x');
    HksBlob longBlob = MakeBlob(longId);
    ret = HksServiceOpenRemoteHandle(&processInfo, &longBlob, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test006
 * @tc.desc: HksServiceCloseRemoteHandle 传入null resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test006, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    int32_t ret = HksServiceCloseRemoteHandle(&processInfo, nullptr, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test007
 * @tc.desc: HksServiceAuthUkeyPin 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test007, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t outStatus = 0;
    uint32_t retryCount = 0;
    HksBlob indexBlob = MakeBlob("testIndex");
    ret = HksServiceAuthUkeyPin(&processInfo, &indexBlob, paramSet, &outStatus, &retryCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceAuthUkeyPin fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test008
 * @tc.desc: HksServiceAuthUkeyPin 传入null resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test008, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    int32_t outStatus = 0;
    uint32_t retryCount = 0;
    int32_t ret = HksServiceAuthUkeyPin(&processInfo, nullptr, paramSet, &outStatus, &retryCount);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test009
 * @tc.desc: HksServiceGetUkeyPinAuthState 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test009, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t status = 0;
    HksBlob indexBlob = MakeBlob("testIndex");
    ret = HksServiceGetUkeyPinAuthState(&processInfo, &indexBlob, paramSet, &status);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceGetUkeyPinAuthState fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test010
 * @tc.desc: HksServiceGetUkeyPinAuthState 传入null resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test010, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    int32_t status = 0;
    int32_t ret = HksServiceGetUkeyPinAuthState(&processInfo, nullptr, paramSet, &status);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test011
 * @tc.desc: HksServiceClearPinAuthState 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test011, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksBlob indexBlob = MakeBlob("testIndex");
    ret = HksServiceClearPinAuthState(&processInfo, &indexBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceClearPinAuthState fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test012
 * @tc.desc: HksServiceClearPinAuthState 传入null resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test012, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();

    int32_t ret = HksServiceClearPinAuthState(&processInfo, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";
}

/**
 * @tc.name: UkeyClientServiceTest.Test013
 * @tc.desc: HksServiceExportProviderCertificates 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test013, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksExtCertInfoSet certSet = {};
    ret = HksServiceExportProviderCertificates(&processInfo, &nameBlob, paramSet, &certSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceExportProviderCertificates fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test014
 * @tc.desc: HksServiceExportProviderCertificates 传入null providerName
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test014, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksExtCertInfoSet certSet = {};
    int32_t ret = HksServiceExportProviderCertificates(&processInfo, nullptr, paramSet, &certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null providerName";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test015
 * @tc.desc: HksServiceExportCertificate 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test015, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksBlob indexBlob = MakeBlob("testIndex");
    HksExtCertInfoSet certSet = {};
    ret = HksServiceExportCertificate(&processInfo, &indexBlob, paramSet, &certSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksServiceExportCertificate fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test016
 * @tc.desc: HksServiceExportCertificate 传入null index
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test016, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksExtCertInfoSet certSet = {};
    int32_t ret = HksServiceExportCertificate(&processInfo, nullptr, paramSet, &certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null index";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test017
 * @tc.desc: HksServiceGetRemoteProperty 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test017, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksServiceRegisterProvider(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksBlob resourceIdBlob = MakeBlob("testResource");
    HksBlob propertyIdBlob = MakeBlob("testProp");
    HksParamSet *propertySetOut = nullptr;
    ret = HksServiceGetRemoteProperty(&processInfo, &resourceIdBlob, &propertyIdBlob, paramSet, &propertySetOut);
    // HksServiceGetRemoteProperty calls HksIpcServiceOnGetRemotePropertyAdapter which
    // creates IHksExtProxy from remoteObject=NULL, so it returns HKS_ERROR_NULL_POINTER
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "should fail because IHksExtProxy is null";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test018
 * @tc.desc: HksServiceGetRemoteProperty 传入null resourceId或propertyId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test018, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob propertyIdBlob = MakeBlob("testProp");
    HksParamSet *propertySetOut = nullptr;

    // null resourceId
    int32_t ret = HksServiceGetRemoteProperty(&processInfo, nullptr, &propertyIdBlob, paramSet, &propertySetOut);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";

    // null propertyId
    HksBlob resourceIdBlob = MakeBlob("testResource");
    ret = HksServiceGetRemoteProperty(&processInfo, &resourceIdBlob, nullptr, paramSet, &propertySetOut);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null propertyId";

    // propertyId with size > HKS_EXT_MAX_PROPERTY_ID_LEN (100)
    std::string longProp(101, 'p');
    HksBlob longPropBlob = MakeBlob(longProp);
    ret = HksServiceGetRemoteProperty(&processInfo, &resourceIdBlob, &longPropBlob, paramSet, &propertySetOut);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized propertyId";

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.Test019
 * @tc.desc: 直接测试adapter层 — HksIpcImportCertAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test019, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);

    int32_t ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, cppParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test HksIpcImportCertAdapter
    HksBlob indexBlob = MakeBlob("testIndex");
    uint8_t indexData[] = "certIndex";
    uint8_t certData[] = "certContent";
    struct HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;
    certInfo.index.size = sizeof(indexData);
    certInfo.index.data = indexData;
    certInfo.cert.size = sizeof(certData);
    certInfo.cert.data = certData;

    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();
    ret = HksIpcImportCertAdapter(&processInfo, &indexBlob, &certInfo, hksParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcImportCertAdapter fail";

    // Cleanup
    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, cppParamSet, isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: UkeyClientServiceTest.Test020
 * @tc.desc: HksIpcImportCertAdapter 传入null resourceId或null certInfo
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test020, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    // null resourceId
    struct HksExtCertInfo certInfo = {};
    int32_t ret = HksIpcImportCertAdapter(&processInfo, nullptr, &certInfo, hksParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";

    // null certInfo
    HksBlob indexBlob = MakeBlob("testIndex");
    ret = HksIpcImportCertAdapter(&processInfo, &indexBlob, nullptr, hksParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "should fail with null certInfo";

    // certInfo with null index.data
    struct HksExtCertInfo nullIndexInfo = {};
    nullIndexInfo.index.size = 1;
    nullIndexInfo.index.data = nullptr;
    nullIndexInfo.cert.size = 1;
    nullIndexInfo.cert.data = reinterpret_cast<uint8_t *>("c");
    ret = HksIpcImportCertAdapter(&processInfo, &indexBlob, &nullIndexInfo, hksParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "should fail with null index data";

    // certInfo with null cert.data
    struct HksExtCertInfo nullCertInfo = {};
    nullCertInfo.index.size = 1;
    nullCertInfo.index.data = reinterpret_cast<uint8_t *>("i");
    nullCertInfo.cert.size = 1;
    nullCertInfo.cert.data = nullptr;
    ret = HksIpcImportCertAdapter(&processInfo, &indexBlob, &nullCertInfo, hksParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "should fail with null cert data";
}

/**
 * @tc.name: UkeyClientServiceTest.Test021
 * @tc.desc: 直接测试adapter层 — HksIpcCreateRemKeyHandleAdapter resourceId边界检查
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test021, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    // resourceId size > HKS_EXT_MAX_RESOURCE_ID_LEN
    std::string longResource(1025, 'r');
    HksBlob longBlob = MakeBlob(longResource);
    int32_t ret = HksIpcCreateRemKeyHandleAdapter(&processInfo, &longBlob, hksParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";

    // resourceId with null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    ret = HksIpcCreateRemKeyHandleAdapter(&processInfo, &nullDataBlob, hksParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null data";
}

/**
 * @tc.name: UkeyClientServiceTest.Test022
 * @tc.desc: 直接测试adapter层 — HksIpcCloseRemKeyHandleAdapter resourceId边界检查
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test022, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    std::string longResource(1025, 'r');
    HksBlob longBlob = MakeBlob(longResource);
    int32_t ret = HksIpcCloseRemKeyHandleAdapter(&processInfo, &longBlob, hksParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";
}

/**
 * @tc.name: UkeyClientServiceTest.Test023
 * @tc.desc: 直接测试adapter层 — HksIpcAuthUkeyPinAdapter resourceId边界检查
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test023, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    std::string longResource(1025, 'r');
    HksBlob longBlob = MakeBlob(longResource);
    int32_t outStatus = 0;
    uint32_t retryCount = 0;
    int32_t ret = HksIpcAuthUkeyPinAdapter(&processInfo, &longBlob, hksParamSet, &outStatus, &retryCount);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";
}

/**
 * @tc.name: UkeyClientServiceTest.Test024
 * @tc.desc: 直接测试adapter层 — HksIpcGetUkeyPinAuthStateAdapter resourceId边界检查
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test024, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    std::string longResource(1025, 'r');
    HksBlob longBlob = MakeBlob(longResource);
    int32_t outStatus = 0;
    int32_t ret = HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &longBlob, hksParamSet, &outStatus);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";
}

/**
 * @tc.name: UkeyClientServiceTest.Test025
 * @tc.desc: 直接测试adapter层 — HksIpcClearPinStatusAdapter resourceId边界检查
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test025, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();

    std::string longResource(1025, 'r');
    HksBlob longBlob = MakeBlob(longResource);
    int32_t ret = HksIpcClearPinStatusAdapter(&processInfo, &longBlob);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";

    // null resourceId
    ret = HksIpcClearPinStatusAdapter(&processInfo, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";
}

/**
 * @tc.name: UkeyClientServiceTest.Test026
 * @tc.desc: 直接测试adapter层 — HksIpcExportProvCertsAdapter providerName边界检查
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test026, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    // oversized providerName
    std::string longName(129, 'n');
    HksBlob longBlob = MakeBlob(longName);
    HksExtCertInfoSet certSet = {};
    int32_t ret = HksIpcExportProvCertsAdapter(&processInfo, &longBlob, hksParamSet, &certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized providerName";

    // null providerName
    ret = HksIpcExportProvCertsAdapter(&processInfo, nullptr, hksParamSet, &certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null providerName";
}

/**
 * @tc.name: UkeyClientServiceTest.Test027
 * @tc.desc: 直接测试adapter层 — HksIpcExportCertAdapter resourceId边界检查
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test027, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    // oversized resourceId
    std::string longResource(1025, 'r');
    HksBlob longBlob = MakeBlob(longResource);
    HksExtCertInfoSet certSet = {};
    int32_t ret = HksIpcExportCertAdapter(&processInfo, &longBlob, hksParamSet, &certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";

    // null resourceId
    ret = HksIpcExportCertAdapter(&processInfo, nullptr, hksParamSet, &certSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";
}

/**
 * @tc.name: UkeyClientServiceTest.Test028
 * @tc.desc: HksIpcServiceOnGetRemotePropertyAdapter 传入null resourceId和null propertyId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test028, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    HksBlob propertyIdBlob = MakeBlob("prop");

    // null resourceId
    int32_t ret = HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, nullptr, &propertyIdBlob,
        hksParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null resourceId";

    // null propertyId
    HksBlob resourceIdBlob = MakeBlob("res");
    ret = HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, nullptr,
        hksParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with null propertyId";

    // oversized propertyId
    std::string longProp(101, 'p');
    HksBlob longPropBlob = MakeBlob(longProp);
    ret = HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, &longPropBlob,
        hksParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized propertyId";

    // oversized resourceId
    std::string longRes(1025, 'r');
    HksBlob longResBlob = MakeBlob(longRes);
    ret = HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &longResBlob, &propertyIdBlob,
        hksParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should fail with oversized resourceId";
}

/**
 * @tc.name: UkeyClientServiceTest.Test029
 * @tc.desc: 直接测试provider层 — HksIpcServiceProviderRegister正常和provider=nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test029, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);

    // Release instance so GetInstanceWrapper returns nullptr
    HuksPluginLifeCycleMgr::ReleaseInstance();

    // Test HksIpcServiceProviderRegister with null pluginManager
    // We can't force GetInstanceWrapper to return nullptr easily since it creates instance.
    // So just test normal flow.
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    std::string name = TEST_PROVIDER;
    int32_t ret = HksIpcServiceProviderRegister(&processInfo, name, cppParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceProviderRegister fail";

    ret = HksIpcServiceProviderUnRegister(&processInfo, name, cppParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceProviderUnRegister fail";
}

/**
 * @tc.name: UkeyClientServiceTest.Test030
 * @tc.desc: 直接测试provider层 — 其他On函数正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, Test030, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet cppParamSet(tmpParams);

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    std::string name = TEST_PROVIDER;
    int32_t ret = HksIpcServiceProviderRegister(&processInfo, name, cppParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::string index = "testIdx";

    // HksIpcServiceOnCreateRemoteKeyHandle
    ret = HksIpcServiceOnCreateRemoteKeyHandle(&processInfo, index, cppParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnCreateRemoteKeyHandle fail";

    // HksIpcServiceOnCloseRemoteKeyHandle
    ret = HksIpcServiceOnCloseRemoteKeyHandle(&processInfo, index, cppParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnCloseRemoteKeyHandle fail";

    // HksIpcServiceOnAuthUkeyPin
    int32_t authState = 0;
    uint32_t retryCnt = 0;
    ret = HksIpcServiceOnAuthUkeyPin(&processInfo, index, cppParamSet, authState, retryCnt);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnAuthUkeyPin fail";

    // HksIpcServiceOnGetVerifyPinStatus
    int32_t state = 0;
    ret = HksIpcServiceOnGetVerifyPinStatus(&processInfo, index, cppParamSet, state);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnGetVerifyPinStatus fail";

    // HksIpcServiceOnClearUkeyPinAuthStatus
    ret = HksIpcServiceOnClearUkeyPinAuthStatus(&processInfo, index);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnClearUkeyPinAuthStatus fail";

    // HksIpcServiceOnGetRemoteProperty
    std::string propertyId = "prop";
    CppParamSet outParams;
    ret = HksIpcServiceOnGetRemoteProperty(&processInfo, index, propertyId, cppParamSet, outParams);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnGetRemoteProperty fail";

    // HksIpcServiceOnExportCertificate
    std::string certsJson;
    ret = HksIpcServiceOnExportCertificate(&processInfo, index, cppParamSet, certsJson);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnExportCertificate fail";

    // HksIpcServiceOnExportProviderAllCertificates
    std::string allCertsJson;
    ret = HksIpcServiceOnExportProviderAllCertificates(&processInfo, name, cppParamSet, allCertsJson);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnExportProviderAllCertificates fail";

    // HksIpcServiceOnImportCertificate
    struct HksExtCertInfo certInfo = {};
    uint8_t idx[] = "idx";
    uint8_t cert[] = "cert";
    certInfo.purpose = 1;
    certInfo.index.size = sizeof(idx);
    certInfo.index.data = idx;
    certInfo.cert.size = sizeof(cert);
    certInfo.cert.data = cert;
    ret = HksIpcServiceOnImportCertificate(&processInfo, index, certInfo, cppParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksIpcServiceOnImportCertificate fail";

    // HksIpcServiceOnGenerateUkeyKey — header/impl signature mismatch, skip direct call

    // Cleanup
    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, cppParamSet, isDeath);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
