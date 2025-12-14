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

char PROVIDER[] = "testProviderName";
char ABILITY[] = "testAbilityName";
char RESOURCE[] = "testResourceId";
char PROPERTY[] = "testPropertyId";
const struct HksBlob PROVIDER_BLOB = { .data = (uint8_t *)PROVIDER, .size = strlen(PROVIDER) };
const struct HksBlob ABILITY_BLOB = { .data = (uint8_t *)ABILITY, .size = strlen(ABILITY) };
const struct HksBlob RESOURCE_BLOB = { .data = (uint8_t *)RESOURCE, .size = strlen(RESOURCE) };
const struct HksBlob PROPERTY_BLOB = { .data = (uint8_t *)PROPERTY, .size = strlen(PROPERTY) };
struct UKeyInfo ukeyInfo{
    .eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER,
    .providerName = PROVIDER_BLOB,
    .resourceId = RESOURCE_BLOB,
    .propertyId = PROPERTY_BLOB
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
    EXPECT_EQ(ret, HKS_FAILURE);
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
    std::vector<HksParam> params3{
        { .tag = HKS_TAG_PARAM4_BUFFER, .blob = PROVIDER_BLOB },
        { .tag = HKS_TAG_PARAM5_BUFFER, .blob = ABILITY_BLOB }
    };
    CppParamSet cppParamSet3(params3);
    EXPECT_NE(cppParamSet3.GetParamSet(), nullptr);
    ret = HksRegProviderParamSetToEventInfo(cppParamSet3.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksRegProviderParamSetToEventInfo(cppParamSet2.GetParamSet(), &eventInfo);
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
    std::vector<HksParam> params1{
        { .tag = HKS_TAG_PARAM4_BUFFER, .blob = PROVIDER_BLOB },
        { .tag = HKS_TAG_PARAM0_INT32, .int32Param = 0 }
    };
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = HksGetAuthPinStateParamSetToEventInfo(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{{ .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 }};
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = HksGetAuthPinStateParamSetToEventInfo(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo dstEventInfo{
        .common.eventId = HKS_EVENT_UKEY_GET_AUTH_PIN_STATE,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    struct HksEventInfo srcEventInfo{
        .common.eventId = HKS_EVENT_UKEY_GET_AUTH_PIN_STATE,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    HksEventInfoAddForGetAuthPinState(&dstEventInfo, &srcEventInfo);

    srcEventInfo.common.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    HksEventInfoAddForGetAuthPinState(&dstEventInfo, &srcEventInfo);
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
    std::vector<HksParam> params3{
        { .tag = HKS_TAG_PARAM4_BUFFER, .blob = RESOURCE_BLOB },
        { .tag = HKS_TAG_PARAM0_INT32, .int32Param = 0 }
    };
    CppParamSet cppParamSet3(params3);
    EXPECT_NE(cppParamSet3.GetParamSet(), nullptr);
    ret = HksRegProviderParamSetToEventInfo(cppParamSet3.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksRegProviderParamSetToEventInfo(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo dstEventInfo{
        .common.eventId = HKS_EVENT_UKEY_AUTH_PIN,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    struct HksEventInfo srcEventInfo{
        .common.eventId = HKS_EVENT_UKEY_AUTH_PIN,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    HksEventInfoAddForAuthPin(&dstEventInfo, &srcEventInfo);

    srcEventInfo.common.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    HksEventInfoAddForAuthPin(&dstEventInfo, &srcEventInfo);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest005
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest005, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};

    std::vector<HksParam> params1{{ .tag = HKS_TAG_PARAM4_BUFFER, .blob = PROVIDER_BLOB }};
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = HksRemoteHandleParamSetToEventInfo(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{{ .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 }};
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = HksRemoteHandleParamSetToEventInfo(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo dstEventInfo{
        .common.eventId = HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    struct HksEventInfo srcEventInfo{
        .common.eventId = HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    HksEventInfoAddForRemoteHandle(&dstEventInfo, &srcEventInfo);

    srcEventInfo.common.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    HksEventInfoAddForRemoteHandle(&dstEventInfo, &srcEventInfo);
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
    std::vector<HksParam> params3{{ .tag = HKS_TAG_PARAM4_BUFFER, .blob = RESOURCE_BLOB }};
    CppParamSet cppParamSet3(params3);
    EXPECT_NE(cppParamSet3.GetParamSet(), nullptr);
    ret = HksExportProviderCertParamSetToEventInfo(cppParamSet3.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksExportProviderCertParamSetToEventInfo(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo dstEventInfo{
        .common.eventId = HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT,
        .ukeyInfo = { .providerName = PROVIDER }
    };
    struct HksEventInfo srcEventInfo{
        .common.eventId = HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT,
        .ukeyInfo = { .providerName = PROVIDER }
    };
    HksEventInfoAddForExportProviderCert(&dstEventInfo, &srcEventInfo);

    srcEventInfo.common.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    HksEventInfoAddForExportProviderCert(&dstEventInfo, &srcEventInfo);
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
    std::vector<HksParam> params3{{ .tag = HKS_TAG_PARAM4_BUFFER, .blob = RESOURCE_BLOB }};
    CppParamSet cppParamSet3(params3);
    EXPECT_NE(cppParamSet3.GetParamSet(), nullptr);
    ret = HksExportCertParamSetToEventInfo(cppParamSet3.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksExportCertParamSetToEventInfo(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo dstEventInfo{
        .common.eventId = HKS_EVENT_UKEY_EXPORT_CERT,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    struct HksEventInfo srcEventInfo{
        .common.eventId = HKS_EVENT_UKEY_EXPORT_CERT,
        .ukeyInfo = { .resourceId = RESOURCE }
    };
    HksEventInfoAddForExportCert(&dstEventInfo, &srcEventInfo);

    srcEventInfo.common.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    HksEventInfoAddForExportCert(&dstEventInfo, &srcEventInfo);
}

/**
 * @tc.name: HksReportUKeyEventTest.HksReportUKeyEventTest008
 * @tc.desc: tdd, report event HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE
 * @tc.type: FUNC
 */
HWTEST_F(HksReportUKeyEventTest, HksReportUKeyEventTest008, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};

    std::vector<HksParam> params1{
        { .tag = HKS_TAG_PARAM4_BUFFER, .blob = PROVIDER_BLOB },
        { .tag = HKS_TAG_PARAM5_BUFFER, .blob = PROVIDER_BLOB }
    };
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = HksGetPropertyParamSetToEventInfo(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{{ .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 }};
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = HksGetPropertyParamSetToEventInfo(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo dstEventInfo{
        .common.eventId = HKS_EVENT_UKSY_GET_REMOTE_PROPERTY,
        .ukeyInfo = { .resourceId = RESOURCE, .propertyId = PROPERTY }
    };
    struct HksEventInfo srcEventInfo{
        .common.eventId = HKS_EVENT_UKSY_GET_REMOTE_PROPERTY,
        .ukeyInfo = { .resourceId = RESOURCE, .propertyId = PROPERTY }
    };
    HksEventInfoAddForGetProperty(&dstEventInfo, &srcEventInfo);

    srcEventInfo.common.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    HksEventInfoAddForGetProperty(&dstEventInfo, &srcEventInfo);
}

}