/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <memory>

#include "hks_sa_interface.h"
#include "hks_dcm_callback_handler.h"
#include "hks_log.h"
#include "hks_type.h"
#include "message_parcel.h"
#include "message_option.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::Hks;

namespace Unittest::HksSaInterfaceTest {

class HksSaInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksSaInterfaceTest::SetUpTestCase(void)
{
}

void HksSaInterfaceTest::TearDownTestCase(void)
{
}

void HksSaInterfaceTest::SetUp()
{
}

void HksSaInterfaceTest::TearDown()
{
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest001 - HksStub SendAsyncReply basic");
    HksStub hksStub;
    
    uint32_t errCode = 0;
    std::unique_ptr<uint8_t[]> certChain = std::make_unique<uint8_t[]>(100);
    uint32_t sz = 100;
    
    hksStub.SendAsyncReply(errCode, certChain, sz);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest002 - HksStub SendAsyncReply with error");
    HksStub hksStub;
    
    uint32_t errCode = 1;
    std::unique_ptr<uint8_t[]> certChain = nullptr;
    uint32_t sz = 0;
    
    hksStub.SendAsyncReply(errCode, certChain, sz);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest003 - HksStub WaitForAsyncReply basic");
    HksStub hksStub;
    
    auto result = hksStub.WaitForAsyncReply(1);
    uint32_t errCode = std::get<0>(result);
    uint32_t retSize = std::get<2>(result);
    
    HKS_LOG_I("WaitForAsyncReply returned errCode: %u, size: %u", errCode, retSize);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest004 - HksStub WaitForAsyncReply after SendAsyncReply");
    HksStub hksStub;
    
    uint32_t errCode = 0;
    std::unique_ptr<uint8_t[]> certChain = std::make_unique<uint8_t[]>(50);
    uint32_t sz = 50;
    
    hksStub.SendAsyncReply(errCode, certChain, sz);
    
    auto result = hksStub.WaitForAsyncReply(1);
    uint32_t retErrCode = std::get<0>(result);
    uint32_t retSize = std::get<2>(result);
    
    HKS_LOG_I("errCode: %u, size: %u", retErrCode, retSize);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest005 - HksStub OnRemoteRequest invalid code");
    HksStub hksStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    
    int ret = hksStub.OnRemoteRequest(999, data, reply, option);
    HKS_LOG_I("OnRemoteRequest returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest006 - HksStub OnRemoteRequest wrong token");
    HksStub hksStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"wrong.token");
    
    int ret = hksStub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_LOG_I("OnRemoteRequest with wrong token returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest007 - HksStub OnRemoteRequest with success code");
    HksStub hksStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_SUCCESS);
    data.WriteUint32(10);
    uint8_t testData[10] = {0};
    data.WriteBuffer(testData, 10);
    
    int ret = hksStub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_LOG_I("OnRemoteRequest with success code returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest008 - HksStub OnRemoteRequest with error code");
    HksStub hksStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(1);
    
    int ret = hksStub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_LOG_I("OnRemoteRequest with error code returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest009 - HksStub OnRemoteRequest invalid size");
    HksStub hksStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_SUCCESS);
    data.WriteUint32(0);
    
    int ret = hksStub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_LOG_I("OnRemoteRequest with invalid size returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest010 - HksStub OnRemoteRequest large size");
    HksStub hksStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_SUCCESS);
    data.WriteUint32(MAX_OUT_BLOB_SIZE + 1);
    
    int ret = hksStub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_LOG_I("OnRemoteRequest with large size returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest011 - HksExtStub SendAsyncReply basic");
    HksExtStub hksExtStub;
    
    uint32_t errCode = HKS_SUCCESS;
    std::unique_ptr<uint8_t[]> sendData = std::make_unique<uint8_t[]>(100);
    uint32_t sendSize = 100;
    uint32_t msgCode = HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY;
    
    hksExtStub.SendAsyncReply(errCode, sendData, sendSize, msgCode, nullptr);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest012 - HksExtStub SendAsyncReply with error");
    HksExtStub hksExtStub;
    
    uint32_t errCode = HKS_ERROR_BAD_STATE;
    std::unique_ptr<uint8_t[]> sendData = nullptr;
    uint32_t sendSize = 0;
    uint32_t msgCode = HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY;
    
    hksExtStub.SendAsyncReply(errCode, sendData, sendSize, msgCode, nullptr);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest013 - HksExtStub WaitForAsyncReply basic");
    HksExtStub hksExtStub;
    
    auto result = hksExtStub.WaitForAsyncReply(1);
    uint32_t errCode = std::get<0>(result);
    uint32_t retSize = std::get<2>(result);
    uint32_t retMsgCode = std::get<3>(result);
    
    HKS_LOG_I("HksExtStub WaitForAsyncReply returned errCode: %u, size: %u, msgCode: %u", errCode, retSize, retMsgCode);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest014 - HksExtStub WaitForAsyncReply after SendAsyncReply");
    HksExtStub hksExtStub;
    
    uint32_t errCode = HKS_SUCCESS;
    std::unique_ptr<uint8_t[]> sendData = std::make_unique<uint8_t[]>(50);
    uint32_t sendSize = 50;
    uint32_t msgCode = HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY;
    
    hksExtStub.SendAsyncReply(errCode, sendData, sendSize, msgCode, nullptr);
    
    auto result = hksExtStub.WaitForAsyncReply(1);
    uint32_t retErrCode = std::get<0>(result);
    uint32_t retSize = std::get<2>(result);
    uint32_t retMsgCode = std::get<3>(result);
    
    HKS_LOG_I("errCode: %u, size: %u, msgCode: %u", retErrCode, retSize, retMsgCode);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest015 - HksExtStub OnRemoteRequest invalid code");
    HksExtStub hksExtStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hksext.service");
    
    int ret = hksExtStub.OnRemoteRequest(999, data, reply, option);
    HKS_LOG_I("HksExtStub OnRemoteRequest returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest016 - HksExtStub OnRemoteRequest wrong token");
    HksExtStub hksExtStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"wrong.token");
    
    int ret = hksExtStub.OnRemoteRequest(HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY, data, reply, option);
    HKS_LOG_I("HksExtStub OnRemoteRequest with wrong token returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest017 - HksExtStub OnRemoteRequest with success code");
    HksExtStub hksExtStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hksext.service");
    data.WriteUint32(HKS_SUCCESS);
    data.WriteUint32(10);
    uint8_t testData[10] = {0};
    data.WriteBuffer(testData, 10);
    
    int ret = hksExtStub.OnRemoteRequest(HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY, data, reply, option);
    HKS_LOG_I("HksExtStub OnRemoteRequest with success code returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest018 - HksExtStub OnRemoteRequest with error code");
    HksExtStub hksExtStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hksext.service");
    data.WriteUint32(HKS_ERROR_BAD_STATE);
    
    int ret = hksExtStub.OnRemoteRequest(HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY, data, reply, option);
    HKS_LOG_I("HksExtStub OnRemoteRequest with error code returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest019 - HksExtStub OnRemoteRequest invalid size");
    HksExtStub hksExtStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hksext.service");
    data.WriteUint32(HKS_SUCCESS);
    data.WriteUint32(0);
    
    int ret = hksExtStub.OnRemoteRequest(HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY, data, reply, option);
    HKS_LOG_I("HksExtStub OnRemoteRequest with invalid size returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest020 - HksExtStub OnRemoteRequest large size");
    HksExtStub hksExtStub;
    
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    
    data.WriteInterfaceToken(u"ohos.security.hksext.service");
    data.WriteUint32(HKS_SUCCESS);
    data.WriteUint32(MAX_OUT_BLOB_SIZE + 1);
    
    int ret = hksExtStub.OnRemoteRequest(HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY, data, reply, option);
    HKS_LOG_I("HksExtStub OnRemoteRequest with large size returned: %d", ret);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest021 - HksStub multiple SendAsyncReply");
    HksStub hksStub;
    
    for (int i = 0; i < 5; i++) {
        uint32_t errCode = i;
        std::unique_ptr<uint8_t[]> certChain = std::make_unique<uint8_t[]>(i * 10);
        uint32_t sz = i * 10;
        
        hksStub.SendAsyncReply(errCode, certChain, sz);
        
        auto result = hksStub.WaitForAsyncReply(1);
        HKS_LOG_I("iteration %d: errCode %u, size %u", i, std::get<0>(result), std::get<2>(result));
    }
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest022 - HksExtStub multiple SendAsyncReply");
    HksExtStub hksExtStub;
    
    for (int i = 0; i < 5; i++) {
        uint32_t errCode = i == 0 ? HKS_SUCCESS : HKS_ERROR_BAD_STATE;
        std::unique_ptr<uint8_t[]> sendData = i == 0 ? std::make_unique<uint8_t[]>(50) : nullptr;
        uint32_t sendSize = i == 0 ? 50 : 0;
        uint32_t msgCode = HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY;
        
        hksExtStub.SendAsyncReply(errCode, sendData, sendSize, msgCode, nullptr);
        
        auto result = hksExtStub.WaitForAsyncReply(1);
        HKS_LOG_I("iteration %d: errCode %u, size %u", i, std::get<0>(result), std::get<2>(result));
    }
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest023 - HksStub WaitForAsyncReply timeout");
    HksStub hksStub;
    
    auto result = hksStub.WaitForAsyncReply(5);
    uint32_t errCode = std::get<0>(result);
    
    HKS_LOG_I("WaitForAsyncReply timeout returned errCode: %u", errCode);
}

HWTEST_F(HksSaInterfaceTest, HksSaInterfaceTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaInterfaceTest024 - HksExtStub WaitForAsyncReply timeout");
    HksExtStub hksExtStub;
    
    auto result = hksExtStub.WaitForAsyncReply(5);
    uint32_t errCode = std::get<0>(result);
    
    HKS_LOG_I("HksExtStub WaitForAsyncReply timeout returned errCode: %u", errCode);
}

}