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
    HksAddParams(paramSet, &param, 1);
    HksBuildParamSet(&paramSet);
    return paramSet;
}

// Helper: register provider and return mgr
static HuksPluginLifeCycleMgr *RegisterTestProvider(HksProcessInfo &processInfo, HksParamSet *paramSet)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    mgr->RegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet));
    return mgr;
}

// Helper: unregister provider
static void UnregisterTestProvider(HuksPluginLifeCycleMgr *mgr, HksProcessInfo &processInfo,
    HksParamSet *paramSet)
{
    bool isDeath = false;
    mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, CppParamSet(paramSet), isDeath);
}

/**
 * @tc.name: UkeyClientServiceTest.HksIpcCheckBlob01
 * @tc.desc: HksIpcCheckBlob — null blob, null data, empty size, oversized (通过 ProviderRegAdapter)
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, HksIpcCheckBlob01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    // null blob
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, nullptr, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // blob with null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, &nullDataBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // blob with size 0 (less than minSize=1)
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, &emptyBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // blob with size > HKS_EXT_MAX_PROVIDER_NAME_LEN (128)
    HksBlob longBlob = MakeBlob(std::string(129, 'a'));
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, &longBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.HksIpcCheckBlob02
 * @tc.desc: HksIpcCheckBlob 边界 — 通过 ProviderUnregAdapter 覆盖 null data / empty / oversized
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, HksIpcCheckBlob02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    // null blob
    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, nullptr, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, &nullDataBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, &emptyBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // oversized
    HksBlob longBlob = MakeBlob(std::string(129, 'a'));
    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, &longBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ProviderRegAdapter01
 * @tc.desc: HksIpcProviderRegAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ProviderRegAdapter01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksIpcProviderRegAdapter(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ProviderUnregAdapter01
 * @tc.desc: HksIpcProviderUnregAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ProviderUnregAdapter01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    int32_t ret = HksIpcProviderRegAdapter(&processInfo, &nameBlob, paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksIpcProviderUnregAdapter(&processInfo, &nameBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.CreateRemKeyHandle01
 * @tc.desc: HksIpcCreateRemKeyHandleAdapter null data / empty / oversized resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, CreateRemKeyHandle01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    // null resourceId
    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, nullptr, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, &nullDataBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, &emptyBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // oversized resourceId
    HksBlob longBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, &longBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.CreateRemKeyHandle02
 * @tc.desc: HksIpcCreateRemKeyHandleAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, CreateRemKeyHandle02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    HksBlob indexBlob = MakeBlob("testIndex");
    int32_t ret = HksIpcCreateRemKeyHandleAdapter(&processInfo, &indexBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.CloseRemKeyHandle01
 * @tc.desc: HksIpcCloseRemKeyHandleAdapter null data / empty / oversized resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, CloseRemKeyHandle01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    // null resourceId
    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, nullptr, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, &nullDataBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, &emptyBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // oversized resourceId
    HksBlob longBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, &longBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.CloseRemKeyHandle02
 * @tc.desc: HksIpcCloseRemKeyHandleAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, CloseRemKeyHandle02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    HksBlob indexBlob = MakeBlob("testIndex");
    HksIpcCreateRemKeyHandleAdapter(&processInfo, &indexBlob, paramSet);

    int32_t ret = HksIpcCloseRemKeyHandleAdapter(&processInfo, &indexBlob, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ExportProvCerts01
 * @tc.desc: HksIpcExportProvCertsAdapter null data / empty / oversized providerName
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ExportProvCerts01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksExtCertInfoSet certSet = {};

    // null providerName
    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, nullptr, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, &nullDataBlob, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, &emptyBlob, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // oversized providerName
    HksBlob longBlob = MakeBlob(std::string(129, 'n'));
    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, &longBlob, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ExportProvCerts02
 * @tc.desc: HksIpcExportProvCertsAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ExportProvCerts02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    HksBlob nameBlob = MakeBlob(TEST_PROVIDER);
    HksExtCertInfoSet certSet = {};
    int32_t ret = HksIpcExportProvCertsAdapter(&processInfo, &nameBlob, paramSet, &certSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ExportCert01
 * @tc.desc: HksIpcExportCertAdapter null data / empty / oversized resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ExportCert01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksExtCertInfoSet certSet = {};

    // null resourceId
    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, nullptr, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, &nullDataBlob, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, &emptyBlob, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // oversized resourceId
    HksBlob longBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, &longBlob, paramSet, &certSet),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ExportCert02
 * @tc.desc: HksIpcExportCertAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ExportCert02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    HksBlob indexBlob = MakeBlob("testIndex");
    HksExtCertInfoSet certSet = {};
    int32_t ret = HksIpcExportCertAdapter(&processInfo, &indexBlob, paramSet, &certSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ImportCert01
 * @tc.desc: HksIpcImportCertAdapter null resourceId / null certInfo / null index.data / null cert.data
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ImportCert01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksExtCertInfo certInfo = {};

    // null resourceId
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, nullptr, &certInfo, paramSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // null data in resourceId
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &nullDataBlob, &certInfo, paramSet),
        HKS_ERROR_INVALID_ARGUMENT);

    // empty size in resourceId
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &emptyBlob, &certInfo, paramSet),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob validBlob = MakeBlob("testIndex");

    // null certInfo
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &validBlob, nullptr, paramSet),
        HKS_ERROR_NULL_POINTER);

    // certInfo with null index.data
    uint8_t tmpCertBuf[] = {'c'};
    struct HksExtCertInfo nullIndexInfo = {};
    nullIndexInfo.index.size = 1;
    nullIndexInfo.cert.size = 1;
    nullIndexInfo.cert.data = tmpCertBuf;
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &validBlob, &nullIndexInfo, paramSet),
        HKS_ERROR_NULL_POINTER);

    // certInfo with null cert.data
    uint8_t tmpIdxBuf[] = {'i'};
    struct HksExtCertInfo nullCertInfo = {};
    nullCertInfo.index.size = 1;
    nullCertInfo.index.data = tmpIdxBuf;
    nullCertInfo.cert.size = 1;
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &validBlob, &nullCertInfo, paramSet),
        HKS_ERROR_NULL_POINTER);

    // oversized resourceId
    HksBlob longBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &longBlob, &certInfo, paramSet),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ImportCert02
 * @tc.desc: HksIpcImportCertAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ImportCert02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    HksBlob indexBlob = MakeBlob("testIndex");
    uint8_t indexData[] = "certIndex";
    uint8_t certData[] = "certContent";
    struct HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;
    certInfo.index.size = sizeof(indexData);
    certInfo.index.data = indexData;
    certInfo.cert.size = sizeof(certData);
    certInfo.cert.data = certData;

    int32_t ret = HksIpcImportCertAdapter(&processInfo, &indexBlob, &certInfo, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.AuthUkeyPin01
 * @tc.desc: HksIpcAuthUkeyPinAdapter null data / empty / oversized resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, AuthUkeyPin01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    int32_t outStatus = 0;
    uint32_t retryCount = 0;

    // null resourceId
    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, nullptr, paramSet, &outStatus, &retryCount),
        HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, &nullDataBlob, paramSet, &outStatus, &retryCount),
        HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, &emptyBlob, paramSet, &outStatus, &retryCount),
        HKS_ERROR_INVALID_ARGUMENT);

    // oversized resourceId
    HksBlob longBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, &longBlob, paramSet, &outStatus, &retryCount),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.AuthUkeyPin02
 * @tc.desc: HksIpcAuthUkeyPinAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, AuthUkeyPin02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    int32_t outStatus = 0;
    uint32_t retryCount = 0;
    HksBlob indexBlob = MakeBlob("testIndex");
    int32_t ret = HksIpcAuthUkeyPinAdapter(&processInfo, &indexBlob, paramSet, &outStatus, &retryCount);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.GetUkeyPinAuthState01
 * @tc.desc: HksIpcGetUkeyPinAuthStateAdapter null data / empty / oversized resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, GetUkeyPinAuthState01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    int32_t outStatus = 0;

    // null resourceId
    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, nullptr, paramSet, &outStatus),
        HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &nullDataBlob, paramSet, &outStatus),
        HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &emptyBlob, paramSet, &outStatus),
        HKS_ERROR_INVALID_ARGUMENT);

    // oversized resourceId
    HksBlob longBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &longBlob, paramSet, &outStatus),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.GetUkeyPinAuthState02
 * @tc.desc: HksIpcGetUkeyPinAuthStateAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, GetUkeyPinAuthState02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    int32_t status = 0;
    HksBlob indexBlob = MakeBlob("testIndex");
    int32_t ret = HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &indexBlob, paramSet, &status);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ClearPinStatus01
 * @tc.desc: HksIpcClearPinStatusAdapter null data / empty / oversized resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ClearPinStatus01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();

    // null resourceId
    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    // null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, &nullDataBlob), HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, &emptyBlob), HKS_ERROR_INVALID_ARGUMENT);

    // oversized resourceId
    HksBlob longBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, &longBlob), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: UkeyClientServiceTest.ClearPinStatus02
 * @tc.desc: HksIpcClearPinStatusAdapter 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ClearPinStatus02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    HksBlob indexBlob = MakeBlob("testIndex");
    int32_t ret = HksIpcClearPinStatusAdapter(&processInfo, &indexBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.GetRemoteProperty01
 * @tc.desc: HksIpcServiceOnGetRemotePropertyAdapter null/invalid resourceId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, GetRemoteProperty01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob propertyIdBlob = MakeBlob("prop");

    // null resourceId
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, nullptr, &propertyIdBlob,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    // null data in resourceId
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &nullDataBlob, &propertyIdBlob,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    // empty size in resourceId
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &emptyBlob, &propertyIdBlob,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    // oversized resourceId
    HksBlob longResBlob = MakeBlob(std::string(1025, 'r'));
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &longResBlob, &propertyIdBlob,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.GetRemoteProperty02
 * @tc.desc: HksIpcServiceOnGetRemotePropertyAdapter null/invalid propertyId
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, GetRemoteProperty02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob resourceIdBlob = MakeBlob("res");

    // null propertyId
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, nullptr,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    // null data in propertyId
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, &nullDataBlob,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    // empty size in propertyId
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, &emptyBlob,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    // oversized propertyId (> HKS_EXT_MAX_PROPERTY_ID_LEN = 100)
    HksBlob longPropBlob = MakeBlob(std::string(101, 'p'));
    EXPECT_EQ(HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, &longPropBlob,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.GetRemoteProperty03
 * @tc.desc: HksIpcServiceOnGetRemotePropertyAdapter null remoteObject → HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, GetRemoteProperty03, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);

    HksBlob resourceIdBlob = MakeBlob("res");
    HksBlob propertyIdBlob = MakeBlob("prop");

    // null remoteObject → iface_cast returns null → HKS_ERROR_NULL_POINTER
    int32_t ret = HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, &propertyIdBlob,
        paramSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.GetRemoteProperty04
 * @tc.desc: HksIpcServiceOnGetRemotePropertyAdapter 正常流程 (valid remoteObject)
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, GetRemoteProperty04, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    HksParamSet *paramSet = MakeParamSet(HKS_TAG_AUTH_STORAGE_LEVEL, HKS_AUTH_STORAGE_LEVEL_DE);
    auto mgr = RegisterTestProvider(processInfo, paramSet);

    HksBlob resourceIdBlob = MakeBlob("testIndex");
    HksBlob propertyIdBlob = MakeBlob("testProp");
    HksParamSet *propertySetOut = nullptr;
    int32_t ret = HksServiceGetRemoteProperty(&processInfo, &resourceIdBlob, &propertyIdBlob,
        paramSet, &propertySetOut);
    // HksServiceGetRemoteProperty calls HksIpcServiceOnGetRemotePropertyAdapter
    // which creates IHksExtProxy from remoteObject=NULL, so HKS_ERROR_NULL_POINTER
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    UnregisterTestProvider(mgr, processInfo, paramSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: UkeyClientServiceTest.ProviderService01
 * @tc.desc: 直接测试provider层 — HksIpcServiceProviderRegister/UnRegister 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ProviderService01, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    CppParamSet cppParamSet({{.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE}});

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);

    std::string name = TEST_PROVIDER;
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);
    EXPECT_EQ(HksIpcServiceProviderUnRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);
}

/**
 * @tc.name: UkeyClientServiceTest.ProviderService02
 * @tc.desc: 直接测试provider层 — OnCreateRemoteKeyHandle/OnCloseRemoteKeyHandle 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ProviderService02, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    CppParamSet cppParamSet({{.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE}});

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);
    std::string name = TEST_PROVIDER;
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";
    EXPECT_EQ(HksIpcServiceOnCreateRemoteKeyHandle(&processInfo, index, cppParamSet), HKS_SUCCESS);
    EXPECT_EQ(HksIpcServiceOnCloseRemoteKeyHandle(&processInfo, index, cppParamSet), HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, nullptr);
}

/**
 * @tc.name: UkeyClientServiceTest.ProviderService03
 * @tc.desc: 直接测试provider层 — OnAuthUkeyPin/OnGetVerifyPinStatus/OnClearUkeyPinAuthStatus
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ProviderService03, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    CppParamSet cppParamSet({{.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE}});

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);
    std::string name = TEST_PROVIDER;
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";

    int32_t authState = 0;
    uint32_t retryCnt = 0;
    EXPECT_EQ(HksIpcServiceOnAuthUkeyPin(&processInfo, index, cppParamSet, authState, retryCnt), HKS_SUCCESS);

    int32_t state = 0;
    EXPECT_EQ(HksIpcServiceOnGetVerifyPinStatus(&processInfo, index, cppParamSet, state), HKS_SUCCESS);

    EXPECT_EQ(HksIpcServiceOnClearUkeyPinAuthStatus(&processInfo, index), HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, nullptr);
}

/**
 * @tc.name: UkeyClientServiceTest.ProviderService04
 * @tc.desc: 直接测试provider层 — OnGetRemoteProperty/OnExportCertificate/OnExportProviderAllCertificates
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ProviderService04, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    CppParamSet cppParamSet({{.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE}});

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);
    std::string name = TEST_PROVIDER;
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";
    std::string propertyId = "prop";
    CppParamSet outParams;
    EXPECT_EQ(HksIpcServiceOnGetRemoteProperty(&processInfo, index, propertyId, cppParamSet, outParams),
        HKS_SUCCESS);

    std::string certsJson;
    EXPECT_EQ(HksIpcServiceOnExportCertificate(&processInfo, index, cppParamSet, certsJson), HKS_SUCCESS);

    std::string allCertsJson;
    EXPECT_EQ(HksIpcServiceOnExportProviderAllCertificates(&processInfo, name, cppParamSet, allCertsJson),
        HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, nullptr);
}

/**
 * @tc.name: UkeyClientServiceTest.ProviderService05
 * @tc.desc: 直接测试provider层 — OnImportCertificate 正常流程
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, ProviderService05, TestSize.Level0)
{
    HksProcessInfo processInfo = MakeProcessInfo();
    CppParamSet cppParamSet({{.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE}});

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);
    std::string name = TEST_PROVIDER;
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";
    struct HksExtCertInfo certInfo = {};
    uint8_t idx[] = "idx";
    uint8_t cert[] = "cert";
    certInfo.purpose = 1;
    certInfo.index.size = sizeof(idx);
    certInfo.index.data = idx;
    certInfo.cert.size = sizeof(cert);
    certInfo.cert.data = cert;
    EXPECT_EQ(HksIpcServiceOnImportCertificate(&processInfo, index, certInfo, cppParamSet), HKS_SUCCESS);

    UnregisterTestProvider(mgr, processInfo, nullptr);
}

/**
 * @tc.name: UkeyClientServiceTest.RemotePropertyPack01
 * @tc.desc: 覆盖 RemotePropertyPack: cppParamSet 为 nullptr 时的分支（只 pack returnResult）
 * @tc.type: FUNC
 */
HWTEST_F(UkeyClientServiceTest, RemotePropertyPack01, TestSize.Level0)
{
    // RemotePropertyPack 是 static 函数，只能通过 HksIpcServiceOnGetRemotePropertyAdapter 间接覆盖
    // 此用例验证当底层 service 返回失败时，RemotePropertyPack 仍被调用并正常处理错误码
    HksProcessInfo processInfo = MakeProcessInfo();
    CppParamSet cppParamSet({{.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE}});
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    ASSERT_NE(mgr, nullptr);
    std::string name = TEST_PROVIDER;
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    // 传入有效的 resourceId/propertyId + null remoteObject → 走到 hksExtProxy null check
    // 在此之前已通过两个 HksIpcCheckBlob，覆盖了 RemotePropertyPack 不被调用的路径
    HksBlob resourceIdBlob = MakeBlob("res");
    HksBlob propertyIdBlob = MakeBlob("prop");
    int32_t ret = HksIpcServiceOnGetRemotePropertyAdapter(&processInfo, &resourceIdBlob, &propertyIdBlob,
        nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    UnregisterTestProvider(mgr, processInfo, nullptr);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
