/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "hks_ha_plugin.h"

using namespace testing::ext;
namespace Unittest::HksHaPluginTest {
class HksHaPluginTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHaPluginTest::SetUpTestCase(void)
{
}

void HksHaPluginTest::TearDownTestCase(void)
{
}

void HksHaPluginTest::SetUp()
{
}

void HksHaPluginTest::TearDown()
{
}

int32_t HksParamSetToEventInfo([[maybe_unused]] const struct HksParamSet *paramSet,
    [[maybe_unused]] struct HksEventInfo *eventInfo)
{
    return HKS_SUCCESS;
}

bool HksEventInfoNeedReport([[maybe_unused]] const struct HksEventInfo *eventInfo)
{
    return true;
}

bool HksEventInfoIsEqual([[maybe_unused]] const struct HksEventInfo *info1,
    [[maybe_unused]] const struct HksEventInfo *info2)
{
    return true;
}

void HksEventInfoAdd([[maybe_unused]] struct HksEventInfo *dst, [[maybe_unused]] const struct HksEventInfo *src)
{}

int32_t HksEventInfoToMap([[maybe_unused]] const struct HksEventInfo *eventInfo,
    [[maybe_unused]] std::unordered_map<std::string, std::string> &eventMap)
{
    return HKS_SUCCESS;
}

static struct HksEventProcMap singleEvent {
    .eventId = 1000,
    .eventInfoCreate = HksParamSetToEventInfo,
    .needReport = HksEventInfoNeedReport,
    .eventInfoEqual = HksEventInfoIsEqual,
    .eventInfoAdd = HksEventInfoAdd,
    .eventInfoToMap = HksEventInfoToMap
};

static const struct HksEventProcMap PROC_MAPS[] = {
    {
        .eventId = 1001,
        .eventInfoCreate = HksParamSetToEventInfo,
        .needReport = HksEventInfoNeedReport,
        .eventInfoEqual = HksEventInfoIsEqual,
        .eventInfoAdd = HksEventInfoAdd,
        .eventInfoToMap = HksEventInfoToMap
    },
    {
        .eventId = 1002,
        .eventInfoCreate = HksParamSetToEventInfo,
        .needReport = HksEventInfoNeedReport,
        .eventInfoEqual = HksEventInfoIsEqual,
        .eventInfoAdd = HksEventInfoAdd,
        .eventInfoToMap = HksEventInfoToMap
    },
    {
        .eventId = 1003,
        .eventInfoCreate = HksParamSetToEventInfo,
        .needReport = HksEventInfoNeedReport,
        .eventInfoEqual = HksEventInfoIsEqual,
        .eventInfoAdd = HksEventInfoAdd,
        .eventInfoToMap = HksEventInfoToMap
    }
};

/**
 * @tc.name: HksHaPluginTest.HksHaPluginTest001
 * @tc.desc: test register single event
 * @tc.type: FUNC
 */
HWTEST_F(HksHaPluginTest, HksHaPluginTest001, TestSize.Level0)
{
    int32_t ret = HksRegisterEventProcWrapper(&singleEvent);
    EXPECT_EQ(ret, HKS_SUCCESS) << "register single event failed";

    singleEvent.eventInfoCreate = nullptr;
    ret = HksRegisterEventProcWrapper(&singleEvent);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "eventInfoCreate should be nullptr";

    singleEvent.eventInfoCreate = HksParamSetToEventInfo;
    singleEvent.needReport = nullptr;
    ret = HksRegisterEventProcWrapper(&singleEvent);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "needReport should be nullptr";

    singleEvent.needReport = HksEventInfoNeedReport;
    singleEvent.eventInfoEqual = nullptr;
    ret = HksRegisterEventProcWrapper(&singleEvent);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "eventInfoEqual should be nullptr";

    singleEvent.eventInfoEqual = HksEventInfoIsEqual;
    singleEvent.eventInfoAdd = nullptr;
    ret = HksRegisterEventProcWrapper(&singleEvent);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "eventInfoAdd should be nullptr";

    singleEvent.eventInfoAdd = HksEventInfoAdd;
    singleEvent.eventInfoToMap = nullptr;
    ret = HksRegisterEventProcWrapper(&singleEvent);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "eventInfoToMap should be nullptr";
}

/**
 * @tc.name: HksHaPluginTest.HksHaPluginTest002
 * @tc.desc: test register batch events
 * @tc.type: FUNC
 */
HWTEST_F(HksHaPluginTest, HksHaPluginTest002, TestSize.Level0)
{
    int32_t ret = HksRegisterEventProcs(nullptr, 1);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "procMaps should be nullptr";

    ret = HksRegisterEventProcs(PROC_MAPS, 0);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "count should be 0";

    ret = HksRegisterEventProcs(PROC_MAPS, 3);
    EXPECT_EQ(ret, HKS_SUCCESS) << "register batch events failed";

    ret = HksRegisterEventProcs(&singleEvent, 1);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "register events should be failed";
}

}