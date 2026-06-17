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

#include "hks_ukey_service_provider_adapter.h"
#include "hks_ukey_service_provider.h"
#include "hks_cpp_paramset.h"
#include "hks_mock_common.h"
#include "hks_ukey_common.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"
#include "hks_type.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_external_error_info.h"
#include "gtest/gtest.h"

#include <string>
#include <vector>
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {

static uint64_t g_shellTokenId = 0;

class HksUkeyClientServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksUkeyClientServiceTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksUkeyClientServiceTest::TearDownTestCase(void)
{
    HksMockCommon::ResetTestEvironment();
}

void HksUkeyClientServiceTest::SetUp() {}

void HksUkeyClientServiceTest::TearDown() {}

// ==================== Adapter parameter validation tests ====================

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest001
* @tc.desc: HksIpcProviderRegAdapter — null/empty/oversized name blob
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest001, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    // null blob
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, nullptr, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // blob with null data
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, &nullDataBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // empty size
    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, &emptyBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    // oversized name (> HKS_EXT_MAX_PROVIDER_NAME_LEN = 128)
    std::string longName(129, 'a');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longName.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longName.data())) };
    EXPECT_EQ(HksIpcProviderRegAdapter(&processInfo, &longBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest002
* @tc.desc: HksIpcProviderUnregAdapter — null/empty/oversized name blob
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest002, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, nullptr, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, &nullDataBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, &emptyBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    std::string longName(129, 'a');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longName.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longName.data())) };
    EXPECT_EQ(HksIpcProviderUnregAdapter(&processInfo, &longBlob, paramSet), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest003
* @tc.desc: HksIpcCreateRemKeyHandleAdapter — null/empty/oversized resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest003, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksExternalErrorInfo *errInfo = nullptr;

    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, nullptr, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, &nullDataBlob, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, &emptyBlob, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    std::string longId(1025, 'r');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longId.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longId.data())) };
    EXPECT_EQ(HksIpcCreateRemKeyHandleAdapter(&processInfo, &longBlob, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest004
* @tc.desc: HksIpcCloseRemKeyHandleAdapter — null/empty/oversized resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest004, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksExternalErrorInfo *errInfo = nullptr;

    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, nullptr, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, &nullDataBlob, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, &emptyBlob, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    std::string longId(1025, 'r');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longId.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longId.data())) };
    EXPECT_EQ(HksIpcCloseRemKeyHandleAdapter(&processInfo, &longBlob, paramSet, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest005
* @tc.desc: HksIpcExportProvCertsAdapter — null/empty/oversized providerName
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest005, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    HksExtCertInfoSet certSet = {};
    struct HksExternalErrorInfo *errInfo = nullptr;

    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, nullptr, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, &nullDataBlob, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, &emptyBlob, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    std::string longName(129, 'n');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longName.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longName.data())) };
    EXPECT_EQ(HksIpcExportProvCertsAdapter(&processInfo, &longBlob, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest006
* @tc.desc: HksIpcExportCertAdapter — null/empty/oversized resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest006, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    HksExtCertInfoSet certSet = {};
    struct HksExternalErrorInfo *errInfo = nullptr;

    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, nullptr, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, &nullDataBlob, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, &emptyBlob, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    std::string longId(1025, 'r');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longId.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longId.data())) };
    EXPECT_EQ(HksIpcExportCertAdapter(&processInfo, &longBlob, paramSet, &certSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest007
* @tc.desc: HksIpcImportCertAdapter — null resourceId / null certInfo / null index.data / null cert.data
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest007, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    HksExtCertInfo certInfo = {};
    struct HksExternalErrorInfo *errInfo = nullptr;

    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, nullptr, &certInfo, paramSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &nullDataBlob, &certInfo, paramSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &emptyBlob, &certInfo, paramSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    std::string validStr = "testIndex";
    HksBlob validBlob = { .size = static_cast<uint32_t>(validStr.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(validStr.data())) };

    // null certInfo
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &validBlob, nullptr, paramSet, &errInfo),
        HKS_ERROR_NULL_POINTER);

    // certInfo with null index.data
    HksExtCertInfo nullIndexInfo = {};
    nullIndexInfo.index.size = 1;
    nullIndexInfo.cert.size = 1;
    uint8_t tmpCert[] = {'c'};
    nullIndexInfo.cert.data = tmpCert;
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &validBlob, &nullIndexInfo, paramSet, &errInfo),
        HKS_ERROR_NULL_POINTER);

    // certInfo with null cert.data
    HksExtCertInfo nullCertInfo = {};
    nullCertInfo.index.size = 1;
    uint8_t tmpIdx[] = {'i'};
    nullCertInfo.index.data = tmpIdx;
    nullCertInfo.cert.size = 1;
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &validBlob, &nullCertInfo, paramSet, &errInfo),
        HKS_ERROR_NULL_POINTER);

    // oversized resourceId
    std::string longId(1025, 'r');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longId.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longId.data())) };
    EXPECT_EQ(HksIpcImportCertAdapter(&processInfo, &longBlob, &certInfo, paramSet, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest008
* @tc.desc: HksIpcAuthUkeyPinAdapter — null/empty/oversized resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest008, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    struct HksExternalErrorInfo *errInfo = nullptr;
    struct HksExtAuthPinOutParam authOutParam = {0, 0};

    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, nullptr, paramSet, &authOutParam, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, &nullDataBlob, paramSet, &authOutParam, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, &emptyBlob, paramSet, &authOutParam, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    std::string longId(1025, 'r');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longId.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longId.data())) };
    EXPECT_EQ(HksIpcAuthUkeyPinAdapter(&processInfo, &longBlob, paramSet, &authOutParam, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest009
* @tc.desc: HksIpcGetUkeyPinAuthStateAdapter — null/empty/oversized resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest009, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    int32_t outStatus = 0;
    struct HksExternalErrorInfo *errInfo = nullptr;

    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, nullptr, paramSet, &outStatus, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &nullDataBlob, paramSet, &outStatus, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &emptyBlob, paramSet, &outStatus, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    std::string longId(1025, 'r');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longId.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longId.data())) };
    EXPECT_EQ(HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &longBlob, paramSet, &outStatus, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest010
* @tc.desc: HksIpcClearPinStatusAdapter — null/empty/oversized resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest010, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    struct HksExternalErrorInfo *errInfo = nullptr;

    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, nullptr, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, &nullDataBlob, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, &emptyBlob, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    std::string longId(1025, 'r');
    HksBlob longBlob = { .size = static_cast<uint32_t>(longId.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longId.data())) };
    EXPECT_EQ(HksIpcClearPinStatusAdapter(&processInfo, &longBlob, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest011
* @tc.desc: HksIpcServiceOnSetOrGetRemotePropertyAdapter — null/invalid resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest011, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    std::string propStr = "prop";
    HksBlob propBlob = { .size = static_cast<uint32_t>(propStr.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(propStr.data())) };

    HksExtPropertyOperationInfo propertyInfoNullRes = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = nullptr, .propertyId = &propBlob };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoNullRes,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    HksExtPropertyOperationInfo propertyInfoNullData = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &nullDataBlob, .propertyId = &propBlob };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoNullData,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    HksExtPropertyOperationInfo propertyInfoEmpty = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &emptyBlob, .propertyId = &propBlob };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoEmpty,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    std::string longRes(1025, 'r');
    HksBlob longResBlob = { .size = static_cast<uint32_t>(longRes.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longRes.data())) };
    HksExtPropertyOperationInfo propertyInfoLongRes = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &longResBlob, .propertyId = &propBlob };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoLongRes,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest012
* @tc.desc: HksIpcServiceOnSetOrGetRemotePropertyAdapter — null/invalid propertyId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest012, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    std::string resStr = "res";
    HksBlob resBlob = { .size = static_cast<uint32_t>(resStr.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(resStr.data())) };

    HksExtPropertyOperationInfo propertyInfoNullProp = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &resBlob, .propertyId = nullptr };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoNullProp,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    HksExtPropertyOperationInfo propertyInfoNullDataProp = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &resBlob, .propertyId = &nullDataBlob };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoNullDataProp,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksBlob emptyBlob = {};
    HksExtPropertyOperationInfo propertyInfoEmptyProp = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &resBlob, .propertyId = &emptyBlob };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoEmptyProp,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    std::string longProp(101, 'p');
    HksBlob longPropBlob = { .size = static_cast<uint32_t>(longProp.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(longProp.data())) };
    HksExtPropertyOperationInfo propertyInfoLongProp = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &resBlob, .propertyId = &longPropBlob };
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfoLongProp,
        paramSet, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest013
* @tc.desc: HksIpcServiceOnSetOrGetRemotePropertyAdapter — null remoteObject returns NULL_POINTER
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest013, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    std::string resStr = "res";
    HksBlob resBlob = { .size = static_cast<uint32_t>(resStr.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(resStr.data())) };
    std::string propStr = "prop";
    HksBlob propBlob = { .size = static_cast<uint32_t>(propStr.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(propStr.data())) };

    HksExtPropertyOperationInfo propertyInfo = { .operation = HKS_EXT_PROPERTY_OPERATION_GET,
        .resourceId = &resBlob, .propertyId = &propBlob };
    int32_t ret = HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfo,
        paramSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

// ==================== Provider layer normal flow tests ====================

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest014
* @tc.desc: HksIpcServiceProviderRegister/UnRegister normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest014, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    CppParamSet cppParamSet({{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA}});

    std::string name = "HksUkeyClientServiceTest014";
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);
    EXPECT_EQ(HksIpcServiceProviderUnRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest015
* @tc.desc: OnCreateRemoteKeyHandle/OnCloseRemoteKeyHandle normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest015, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    CppParamSet cppParamSet({{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA}});
    struct HksExternalErrorInfo *errInfo = nullptr;

    std::string name = "HksUkeyClientServiceTest015";
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";
    EXPECT_EQ(HksIpcServiceOnCreateRemoteKeyHandle(&processInfo, index, cppParamSet, &errInfo), HKS_SUCCESS);
    EXPECT_EQ(HksIpcServiceOnCloseRemoteKeyHandle(&processInfo, index, cppParamSet, &errInfo), HKS_SUCCESS);

    EXPECT_EQ(HksIpcServiceProviderUnRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest016
* @tc.desc: OnAuthUkeyPin/OnGetVerifyPinStatus/OnClearUkeyPinAuthStatus normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest016, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    CppParamSet cppParamSet({{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA}});
    struct HksExternalErrorInfo *errInfo = nullptr;

    std::string name = "HksUkeyClientServiceTest016";
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";

    HksExtAuthPinOutParam authOutParam = {};
    EXPECT_EQ(HksIpcServiceOnAuthUkeyPin(&processInfo, index, cppParamSet, authOutParam, &errInfo), HKS_SUCCESS);

    int32_t state = 0;
    EXPECT_EQ(HksIpcServiceOnGetVerifyPinStatus(&processInfo, index, cppParamSet, state, &errInfo), HKS_SUCCESS);

    EXPECT_EQ(HksIpcServiceOnClearUkeyPinAuthStatus(&processInfo, index, &errInfo), HKS_SUCCESS);

    EXPECT_EQ(HksIpcServiceProviderUnRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest017
* @tc.desc: OnSetOrGetRemoteProperty/OnExportCertificate/OnExportProviderAllCertificates normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest017, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    CppParamSet cppParamSet({{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA}});
    struct HksExternalErrorInfo *errInfo = nullptr;

    std::string name = "HksUkeyClientServiceTest017";
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";
    std::string propertyId = "prop";
    struct HksProcessWithErrorInfo processAndError = {&processInfo, nullptr};
    EXPECT_EQ(HksIpcServiceOnSetOrGetRemoteProperty(processAndError,
        HKS_EXT_PROPERTY_OPERATION_GET, index, propertyId, cppParamSet), HKS_SUCCESS);

    std::string certsJson;
    EXPECT_EQ(HksIpcServiceOnExportCertificate(&processInfo, index, cppParamSet, certsJson, &errInfo), HKS_SUCCESS);

    std::string allCertsJson;
    EXPECT_EQ(HksIpcServiceOnExportProviderAllCertificates(&processInfo, name, cppParamSet, allCertsJson, &errInfo),
        HKS_SUCCESS);

    EXPECT_EQ(HksIpcServiceProviderUnRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest018
* @tc.desc: OnImportCertificate normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest018, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    CppParamSet cppParamSet({{.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA}});
    struct HksExternalErrorInfo *errInfo = nullptr;

    std::string name = "HksUkeyClientServiceTest018";
    EXPECT_EQ(HksIpcServiceProviderRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    std::string index = "testIdx";
    HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;
    certInfo.index = StringToBlob("idx");
    certInfo.cert = StringToBlob("cert");
    EXPECT_EQ(HksIpcServiceOnImportCertificate(&processInfo, index, certInfo, cppParamSet, &errInfo), HKS_SUCCESS);

    EXPECT_EQ(HksIpcServiceProviderUnRegister(&processInfo, name, cppParamSet), HKS_SUCCESS);

    HKS_FREE_BLOB(certInfo.index);
    HKS_FREE_BLOB(certInfo.cert);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksUkeyClientServiceTest.HksUkeyClientServiceTest019
* @tc.desc: HksIpcServiceOnGetResourceIdAdapter — ResourceId too long and normal
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyClientServiceTest, HksUkeyClientServiceTest019, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    struct HksExternalErrorInfo *errInfo = nullptr;
    std::string providerName = "TestProvider019";
    HksBlob providerBlob = { .size = static_cast<uint32_t>(providerName.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(providerName.data())) };
    HksBlob resourceIdBlob = { .size = 0, .data = nullptr };

    CppParamSet cppParamSet(paramSet);
    int32_t ret = HksIpcServiceOnGetResourceIdAdapter(&processInfo, &providerBlob, paramSet, &resourceIdBlob, &errInfo);
    EXPECT_EQ(ret, HKS_ERROR_MALLOC_FAIL);

    ret = HksIpcServiceOnGetResourceIdAdapter(&processInfo, &providerBlob, paramSet, &resourceIdBlob, &errInfo);
    EXPECT_EQ(ret, HKS_ERROR_INSUFFICIENT_DATA);

    HksFreeExternalErrorInfo(errInfo);
    HKS_FREE_BLOB(resourceIdBlob);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
