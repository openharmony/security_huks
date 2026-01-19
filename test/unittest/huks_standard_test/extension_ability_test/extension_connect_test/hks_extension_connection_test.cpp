/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "hks_extension_connection_test.h"
#include "hks_mock_common.h"
#include <thread>

using namespace testing::ext;
using ::testing::_;
using ::testing::Return;

namespace OHOS {
namespace Security {
namespace Huks {
void ExtensionConnectionTest::SetUpTestCase(void) {
}

void ExtensionConnectionTest::TearDownTestCase(void) {
}

void ExtensionConnectionTest::SetUp() {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    connection_ = new ExtensionConnection(processInfo);
    want_.SetElementName("com.hmos.hukstest.ukey", "TestCryptoAbility");
    userId_ = 100;
}

void ExtensionConnectionTest::TearDown() {
    connection_ = nullptr;
}

constexpr int WAIT_TIME = 10;
void SimulateAbilityConnectResponse() {
    std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<long long>(WAIT_TIME)));
    sptr<MockIRemoteObject> mockIRemoteObject = new MockIRemoteObject();
    EXPECT_CALL(*mockRemoteObject, SendRequest(_, _, _, _)).WillRepeatedly(Return(0));
    AppExecFwk::ElementName element;
    connection_->OnAbilityConnectDone(element, mockIRemoteObject, 0);
}

void SimulateAbilityDisconnectResponse() {
    std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<long long>(WAIT_TIME)));
    AppExecFwk::ElementName element;
    connection_->OnAbilityDisconnectDone(element, 0);
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest001
 * @tc.desc: connect success and disconnect time out.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest001, TestSize.Level0) {
    std::thread connectThread(&ExtensionConnectionTest::SimulateAbilityConnectResponse, this);
    int32_t result = connection_->OnConnection(want_, connection_, userId_);
    if (connectThread.joinable()) {
        connectThread.join();
    }
    EXPECT_EQ(result, HKS_SUCCESS);
    EXPECT_TRUE(connection_->IsConnected());

    std::thread disConnectThread(&ExtensionConnectionTest::SimulateAbilityDisconnectResponse, this);
    connection_->DisConnect(connection_);
    if (disConnectThread.joinable()) {
        disConnectThread.join();
    }
    EXPECT_FALSE(connection_->IsConnected());
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest002
 * @tc.desc: connect time out.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest002, TestSize.Level0) {
    int32_t result = connection_->OnConnection(want_, connection_, userId_);
    EXPECT_EQ(ret, HKS_ERROR_REMOTE_OPERATION_FAILED) << "ret is not HKS_ERROR_REMOTE_OPERATION_FAILED.";
    EXPECT_FALSE(connection_->IsConnected());
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest003
 * @tc.desc: OnRemotedDied.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest003, TestSize.Level0) {
    std::thread connectThread(&ExtensionConnectionTest::SimulateAbilityConnectResponse, this);
    int32_t result = connection_->OnConnection(want_, connection_, userId_);
    if (connectThread.joinable()) {
        connectThread.join();
    }
    EXPECT_EQ(result, HKS_SUCCESS);
    EXPECT_TRUE(connection_->IsConnected());

    std::function<void(HksProcessInfo)> callBackPlugin = [](HksProcessInfo info) {};
    connection_->callBackFromPlugin(callBackPlugin);
    wptr<MockIRemoteObject> mockIRemoteObject = new MockIRemoteObject();
    connection_->OnRemoteDied(mockIRemoteObject);
    EXPECT_FALSE(connection_->IsConnected());
}

}
}
}

