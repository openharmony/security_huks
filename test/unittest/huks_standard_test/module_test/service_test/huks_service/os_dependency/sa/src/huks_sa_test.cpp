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

/**
 * @tc.name: HksSaTest.HksSaTest001
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_GEN_KEY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest001");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    struct HksParamSet *tmpParamSetOut = NULL;
    EXPECT_EQ(HKS_SUCCESS, HksInitParamSet(&tmpParamSetOut));
    hksService.OnRemoteRequest(HKS_MSG_GEN_KEY, data, reply, option);
    HksFreeParamSet(&tmpParamSetOut);
}

/**
 * @tc.name: HksSaTest.HksSaTest002
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_ATTEST_KEY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest002");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    struct HksParamSet *tmpParamSetOut = NULL;
    EXPECT_EQ(HKS_SUCCESS, HksInitParamSet(&tmpParamSetOut));
    hksService.OnRemoteRequest(HKS_MSG_ATTEST_KEY, data, reply, option);
    HksFreeParamSet(&tmpParamSetOut);
}

/**
 * @tc.name: HksSaTest.HksSaTest003
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest003");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    struct HksParamSet *tmpParamSetOut = NULL;
    EXPECT_EQ(HKS_SUCCESS, HksInitParamSet(&tmpParamSetOut));
    hksService.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HksFreeParamSet(&tmpParamSetOut);
}

HWTEST_F(HksSaTest, HksSaTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest004 - HKS_MSG_INIT");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_INIT, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest005 - invalid code");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(999, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest006 - HKS_MSG_GET_KEY_INFO_LIST");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_GET_KEY_INFO_LIST, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest007 - HKS_MSG_EXPORT_PUBLIC_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_EXPORT_PUBLIC_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest008 - HKS_MSG_DELETE_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_DELETE_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest009 - HKS_MSG_GET_KEY_PARAMSET");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_GET_KEY_PARAMSET, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest010 - HKS_MSG_KEY_EXIST");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_KEY_EXIST, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest011 - HKS_MSG_SIGN");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_SIGN, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest012 - HKS_MSG_VERIFY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_VERIFY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest013 - HKS_MSG_ENCRYPT");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_ENCRYPT, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest014 - HKS_MSG_DECRYPT");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_DECRYPT, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest015 - HKS_MSG_AGREE_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_AGREE_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest016 - HKS_MSG_DERIVE_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_DERIVE_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest017 - HKS_MSG_MAC");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_MAC, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest018 - HKS_MSG_IMPORT_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_IMPORT_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest019 - HKS_MSG_GENERATE_RANDOM");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_GENERATE_RANDOM, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest020 - HKS_MSG_IMPORT_WRAPPED_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_IMPORT_WRAPPED_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest021 - HKS_MSG_UPDATE");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_UPDATE, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest022 - HKS_MSG_FINISH");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_FINISH, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest023 - HKS_MSG_ABORT");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_ABORT, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest024 - HKS_MSG_LIST_ALIASES");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_LIST_ALIASES, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest025 - HksService GetInstance");
    auto instance = HksService::GetInstance();
    if (instance != nullptr) {
        HKS_LOG_I("HksService instance obtained");
    }
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
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_CHANGE_STORAGE_LEVEL, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest029 - HKS_MSG_RENAME_KEY_ALIAS");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_RENAME_KEY_ALIAS, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest030 - HKS_MSG_WRAP_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_WRAP_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest031, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest031 - HKS_MSG_UNWRAP_KEY");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_UNWRAP_KEY, data, reply, option);
}

HWTEST_F(HksSaTest, HksSaTest032, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest032 - HKS_MSG_GET_CERTIFICATE_CHAIN");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_GET_CERTIFICATE_CHAIN, data, reply, option);
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
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    hksService.OnRemoteRequest(HKS_MSG_MAX + 1, data, reply, option);
}

}