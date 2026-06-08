/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "message_parcel.h"

#include "hks_log.h"
#include "hks_sa.h"
#include "hks_param.h"
#include "hks_mem.h"
#include "huks_service_ipc_interface_code.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::Hks;
namespace Unittest::HksSaTest {

class HksSaTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSaTest::SetUpTestCase(void)
{
}

void HksSaTest::TearDownTestCase(void)
{
}

void HksSaTest::SetUp()
{
}

void HksSaTest::TearDown()
{
}

const std::u16string SA_KEYSTORE_SERVICE_DESCRIPTOR_TEST = u"ohos.security.hks.service";
const uint32_t IN_TEST_SIZE = 1024;
const uint32_t OUT_TEST_SIZE = 100 * 1024;

static int32_t WriteCommonRequestData(MessageParcel &data, const struct HksBlob *inBlob, const struct HksBlob *outBlob)
{
    if (!data.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR_TEST)) {
        return HKS_ERROR_BAD_STATE;
    }
    if (outBlob == nullptr) {
        if (!data.WriteUint32(0)) {
            return HKS_ERROR_BAD_STATE;
        }
    } else {
        if (!data.WriteUint32(outBlob->size)) {
            return HKS_ERROR_BAD_STATE;
        }
    }
    if (!data.WriteUint32(inBlob->size)) {
        return HKS_ERROR_BAD_STATE;
    }
    if (!data.WriteBuffer(inBlob->data, static_cast<size_t>(inBlob->size))) {
        return HKS_ERROR_BAD_STATE;
    }
    return HKS_SUCCESS;
}

static int32_t TestRemoteRequest(uint32_t code, bool hasOutData = false)
{
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    struct HksBlob inBlob = { 0, nullptr };
    struct HksBlob outBlob = { 0, nullptr };
    inBlob.size = IN_TEST_SIZE;
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    EXPECT_NE(inBlob.data, nullptr);
    outBlob.size = OUT_TEST_SIZE;
    outBlob.data = (uint8_t *)HksMalloc(outBlob.size);
    EXPECT_NE(outBlob.data, nullptr);

    int32_t ret = HKS_FAILURE;
    if (hasOutData) {
        ret = WriteCommonRequestData(data, &inBlob, &outBlob);
    } else {
        ret = WriteCommonRequestData(data, &inBlob, nullptr);
    }
    EXPECT_EQ(ret, HKS_SUCCESS);

    hksService.OnRemoteRequest(code, data, reply, option);
    HKS_FREE_BLOB(inBlob);
    HKS_FREE_BLOB(outBlob);

    return HKS_SUCCESS;
}

/**
 * @tc.name: HksSaTest.HksSaTest001
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_GEN_KEY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest001");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_GEN_KEY), HKS_SUCCESS);
}

/**
 * @tc.name: HksSaTest.HksSaTest002
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_ATTEST_KEY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest002");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_ATTEST_KEY), HKS_SUCCESS);
}

/**
 * @tc.name: HksSaTest.HksSaTest003
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest003");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest004 - HKS_MSG_INIT");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_INIT), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest005 - invalid code");
    EXPECT_EQ(TestRemoteRequest(999), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest006 - HKS_MSG_GET_KEY_INFO_LIST");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_GET_KEY_INFO_LIST), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest007 - HKS_MSG_EXPORT_PUBLIC_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_EXPORT_PUBLIC_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest008 - HKS_MSG_DELETE_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_DELETE_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest009 - HKS_MSG_GET_KEY_PARAMSET");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_GET_KEY_PARAMSET), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest010 - HKS_MSG_KEY_EXIST");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_KEY_EXIST), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest011 - HKS_MSG_SIGN");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_SIGN), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest012 - HKS_MSG_VERIFY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_VERIFY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest013 - HKS_MSG_ENCRYPT");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_ENCRYPT), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest014 - HKS_MSG_DECRYPT");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_DECRYPT), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest015 - HKS_MSG_AGREE_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_AGREE_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest016 - HKS_MSG_DERIVE_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_DERIVE_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest017 - HKS_MSG_MAC");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_MAC), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest018 - HKS_MSG_IMPORT_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_IMPORT_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest019 - HKS_MSG_GENERATE_RANDOM");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_GENERATE_RANDOM), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest020 - HKS_MSG_IMPORT_WRAPPED_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_IMPORT_WRAPPED_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest021 - HKS_MSG_UPDATE");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_UPDATE), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest022 - HKS_MSG_FINISH");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_FINISH), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest023 - HKS_MSG_ABORT");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_ABORT), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest024 - HKS_MSG_LIST_ALIASES");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_LIST_ALIASES), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest025 - HksService GetInstance");
    auto instance = HksService::GetInstance();
    EXPECT_NE(instance, nullptr);
}

HWTEST_F(HksSaTest, HksSaTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest026 - HksDeathRecipient OnRemoteDied");
    HksDeathRecipient deathRecipient(1000, 100);
    wptr<IRemoteObject> remoteObj = nullptr;
    
    deathRecipient.OnRemoteDied(remoteObj);
}

HWTEST_F(HksSaTest, HksSaTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest027 - HksService multiple instances");
    HksService hksService1(0, true);
    HksService hksService2(1, false);
    
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService1.OnRemoteRequest(HKS_MSG_GEN_KEY, data, reply, option);
    hksService2.OnRemoteRequest(HKS_MSG_GEN_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest028 - HKS_MSG_CHANGE_STORAGE_LEVEL");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_CHANGE_STORAGE_LEVEL), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest029 - HKS_MSG_RENAME_KEY_ALIAS");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_RENAME_KEY_ALIAS), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest030 - HKS_MSG_WRAP_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_WRAP_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest031, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest031 - HKS_MSG_UNWRAP_KEY");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_UNWRAP_KEY), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest032, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest032 - HKS_MSG_GET_CERTIFICATE_CHAIN");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_GET_CERTIFICATE_CHAIN), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest033, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest033 - wrong interface token");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"wrong.token");

    hksService.OnRemoteRequest(HKS_MSG_GEN_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest034, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest034 - code out of range");
    EXPECT_EQ(TestRemoteRequest(HKS_MSG_MAX + 1), HKS_SUCCESS);
}

HWTEST_F(HksSaTest, HksSaTest035, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest035 - code out of range");
    EXPECT_EQ(TestRemoteRequest(-1), HKS_SUCCESS);
}

}