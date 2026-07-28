/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_error_code.h"
#include "hks_report_ukey_event.h"
#include "hks_cpp_paramset.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include <gtest/gtest.h>
#include <memory>
#include <new>

using namespace testing::ext;
namespace Unittest::HksReportUKeyEventTest {
class HksReportUKeyEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksReportUKeyEventTest::SetUpTestCase(void)
{
}

void HksReportUKeyEventTest::TearDownTestCase(void)
{
}

void HksReportUKeyEventTest::SetUp()
{
}

void HksReportUKeyEventTest::TearDown()
{
}

char RESOURCE[] = "testResourceId";
char PROVIDER[] = "testProviderName";
char ABILITY[] = "testAbilityName";
char EXT_BUNDLE_NAME[] = "testBundleName";
char HANDLE_ID[] = "testHandleId";
char EXTRA_DATA[] = "testExtraData";
char PROPERTY[] = "testPropertyId";

const struct HksBlob RESOURCE_BLOB = { .data = (uint8_t *)RESOURCE, .size = strlen(RESOURCE) };
const struct HksBlob PROVIDER_BLOB = { .data = (uint8_t *)PROVIDER, .size = strlen(PROVIDER) };
const struct HksBlob ABILITY_BLOB = { .data = (uint8_t *)ABILITY, .size = strlen(ABILITY) };
const struct HksBlob EXT_BUNDLE_NAME_BLOB = { .data = (uint8_t *)EXT_BUNDLE_NAME, .size = strlen(EXT_BUNDLE_NAME) };
const struct HksBlob HANDLE_ID_BLOB = { .data = (uint8_t *)HANDLE_ID, .size = strlen(HANDLE_ID) };
const struct HksBlob EXTRA_DATA_BLOB = { .data = (uint8_t *)EXTRA_DATA, .size = strlen(EXTRA_DATA) };
const struct HksBlob PROPERTY_BLOB = { .data = (uint8_t *)PROPERTY, .size = strlen(PROPERTY) };
struct UKeyInfo ukeyInfo{
    .eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER,
    .providerName = PROVIDER_BLOB,
    .resourceId = RESOURCE_BLOB,
    .propertyId = PROPERTY_BLOB
};
std::vector<HksParam> PARAMS = {
    { .tag = HKS_TAG_PARAM4_BUFFER, .blob = RESOURCE_BLOB },
    { .tag = HKS_TAG_PARAM5_BUFFER, .blob = PROVIDER_BLOB },
    { .tag = HKS_TAG_PARAM6_BUFFER, .blob = ABILITY_BLOB },
    { .tag = HKS_TAG_PARAM7_BUFFER, .blob = EXT_BUNDLE_NAME_BLOB },
    { .tag = HKS_TAG_PARAM8_BUFFER, .blob = HANDLE_ID_BLOB },
    { .tag = HKS_TAG_PARAM9_BUFFER, .blob = EXTRA_DATA_BLOB },
    { .tag = HKS_TAG_PARAM10_BUFFER, .blob = PROPERTY_BLOB },
    { .tag = HKS_TAG_PARAM0_INT32, .uint32Param = 0 }, // state && call_auth_uid
    { .tag = HKS_TAG_PARAM1_UINT32, .uint32Param = 0 }, // alg && operation
    { .tag = HKS_TAG_PARAM2_UINT32, .uint32Param = 0 },
    { .tag = HKS_TAG_PARAM3_UINT32, .uint32Param = HKS_SUCCESS },
};

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest001
 * @tc.desc: tdd
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest001, TestSize.Level0)
{
    struct HksProcessInfo processInfo{};
    struct HksParamSet paramSet{};
    struct UKeyCommonInfo ukeyCommon{};
    int32_t ret = HKS_SUCCESS;
    ret = ReportUKeyEvent(nullptr, __func__, &processInfo, &paramSet, &ukeyCommon);
    EXPECT_EQ(ret, HKS_FAILURE);
    ret = ReportUKeyEvent(&ukeyInfo, nullptr, &processInfo, &paramSet, &ukeyCommon);
    EXPECT_EQ(ret, HKS_FAILURE);
    ret = ReportUKeyEvent(&ukeyInfo, __func__, nullptr, &paramSet, &ukeyCommon);
    EXPECT_EQ(ret, HKS_FAILURE);
    ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, nullptr, &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, &paramSet, nullptr);
    EXPECT_EQ(ret, HKS_FAILURE);
    ukeyInfo.eventId = HKS_EVENT_DATA_SIZE_STATISTICS;
    ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, &paramSet, &ukeyCommon);
    EXPECT_EQ(ret, HKS_FAILURE);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest002
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_REGISTER_PROVIDER
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest002, TestSize.Level0)
{
    ukeyInfo.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    struct HksProcessInfo processInfo{};
    struct UKeyCommonInfo ukeyCommon{};

    std::vector<HksParam> params1{{ .tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = ABILITY_BLOB }};
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet1.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{{ .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 }};
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet2.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    ret = HksRegProviderParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksRegProviderNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksRegProviderNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksRegProviderEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, false); // COMPARE_NONE

    (void)HksEventInfoAddForRegProvider(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksRegProviderEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest003
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_GET_AUTH_PIN_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest003, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksGetAuthPinStateParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksGetAuthPinStateNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksGetAuthPinStateNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksGetAuthPinStateEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForGetAuthPinState(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksGetAuthPinStateEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest004
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_AUTH_PIN
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest004, TestSize.Level0)
{
    ukeyInfo.eventId = HKS_EVENT_UKEY_AUTH_PIN;
    struct HksProcessInfo processInfo{};
    struct UKeyCommonInfo ukeyCommon{};

    std::vector<HksParam> params1{{ .tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = 0 }};
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet1.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{{ .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 }};
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet2.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    ret = HksAuthPinParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksAuthPinNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksAuthPinNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksAuthPinEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForAuthPin(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksAuthPinEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest005
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest005, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksRemoteHandleParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksRemoteHandleNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksRemoteHandleNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksRemoteHandleEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForRemoteHandle(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksRemoteHandleEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest006
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest006, TestSize.Level0)
{
    ukeyInfo.eventId = HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT;
    struct HksProcessInfo processInfo{};
    struct UKeyCommonInfo ukeyCommon{};

    std::vector<HksParam> params1{{ .tag = HKS_EXT_CRYPTO_TAG_PURPOSE, .int32Param = 0 }};
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet1.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{{ .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 }};
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet2.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    ret = HksExportProviderCertParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksExportProviderCertNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksExportProviderCertNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksExportProviderCertEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForExportProviderCert(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksExportProviderCertEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest007
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_EXPORT_CERT
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest007, TestSize.Level0)
{
    ukeyInfo.eventId = HKS_EVENT_UKEY_EXPORT_CERT;
    struct HksProcessInfo processInfo{};
    struct UKeyCommonInfo ukeyCommon{};

    std::vector<HksParam> params1{{ .tag = HKS_EXT_CRYPTO_TAG_PURPOSE, .int32Param = 0 }};
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet1.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{{ .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 }};
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, cppParamSet2.GetParamSet(), &ukeyCommon);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    ret = HksExportCertParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksExportCertNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksExportCertNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksExportCertEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForExportCert(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksExportCertEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest008
 * @tc.desc: tdd, report event HKS_EVENT_UKSY_GET_REMOTE_PROPERTY
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest008, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksGetPropertyParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksGetPropertyNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksGetPropertyNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksGetPropertyEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForGetProperty(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksGetPropertyEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest009
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_IMPORT_CERT
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest009, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksImportCertParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksImportCertNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksImportCertNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksImportCertEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForImportCert(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksImportCertEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest010
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_GET_RESOURCE_ID
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest010, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksGetResourceIdParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksGetResourceIdNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksGetResourceIdNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksGetResourceIdEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForGetResourceId(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksGetResourceIdEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest011
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_CLEAR_PIN_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest011, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksClearPinStateParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksClearPinStateNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksClearPinStateNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksClearPinStateEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForClearPinState(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksClearPinStateEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest012
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_INIT_SESSION
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest012, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksInitSessionParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksInitSessionNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksInitSessionNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksInitSessionEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForInitSession(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksInitSessionEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest013
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_UPDATE_SESSION
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest013, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksUpdateSessionParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksUpdateSessionNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksUpdateSessionNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksUpdateSessionEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForUpdateSession(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksUpdateSessionEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest014
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_FINISH_SESSION
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest014, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksFinishSessionParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksFinishSessionNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksFinishSessionNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksFinishSessionEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForFinishSession(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksFinishSessionEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest015
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_ABORT_SESSION
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest015, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksAbortSessionParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksAbortSessionNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksAbortSessionNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksAbortSessionEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForAbortSession(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksAbortSessionEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest016
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_GENERATE_KEY
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest016, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksGenerateKeyParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksGenerateKeyNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksGenerateKeyNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksGenerateKeyEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForGenerateKey(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksGenerateKeyEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest017
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest017, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksExportPublicKeyParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksExportPublicKeyNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksExportPublicKeyNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksExportPublicKeyEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForExportPublicKey(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksExportPublicKeyEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest018
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest018, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksImportWrappedKeyParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksImportWrappedKeyNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksImportWrappedKeyNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksImportWrappedKeyEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForImportWrappedKey(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksImportWrappedKeyEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest019
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_SET_REMOTE_PROPERTY
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest019, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    CppParamSet cppParamSet(PARAMS);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksSetPropertyParamSetToEventInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    bool needReport = HksSetPropertyNeedReport(nullptr);
    EXPECT_EQ(needReport, false);

    needReport = HksSetPropertyNeedReport(&eventInfo);
    EXPECT_EQ(needReport, false);

    bool equal = HksSetPropertyEventInfoEqual(&eventInfo, &eventInfo);
    EXPECT_EQ(equal, true);

    (void)HksEventInfoAddForSetProperty(&eventInfo, &eventInfo);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksSetPropertyEventInfoToMap(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

}