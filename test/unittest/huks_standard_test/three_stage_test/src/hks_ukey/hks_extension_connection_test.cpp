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

#include "hks_extension_connection_test.h"
#include "gtest/gtest.h"
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {
void ExtensionConnectionTest::SetUpTestCase(void) {
}

void ExtensionConnectionTest::TearDownTestCase(void) {
}

void ExtensionConnectionTest::SetUp() {
    extensionConn = std::make_shared<ExtensionConnection>();
    ASSERT_NE(extensionConn, nullptr);
}

void ExtensionConnectionTest::TearDown() {
    extensionConn = nullptr;
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest001
 * @tc.desc: connect success.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest001, TestSize.Level10) {
    EXPECT_CALL(*mockProxy, AsObject()).WillRepeatedly(Return(mockRemoteObject));
    EXPECT_CALL(*mockRemoteObject, AddDeathRecipient(_, _)).Times(1);

    AppExecFwk::ElementName element;
    int resultCode = 0;
    extensionConn->OnAbilityConnectDone(element, mockRemoteObject, resultCode);

    EXPECT_EQ(extensionConn->IsConnected(), true) << "IsConnected is false";
    EXPECT_NE(extensionConn->GetExtConnectProxy(), nullptr) << "extConnectProxy is nullptr";
    EXPECT_EQ(extensionConn->GetExtConnectProxy(), mockProxy) << "proxy is not mockProxy";
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest002
 * @tc.desc: connect fail.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest002, TestSize.Level10) {
    AppExecFwk::ElementName element;
    int resultCode = 0;
    extensionConn->OnAbilityConnectDone(element, nullptr, resultCode);

    EXPECT_EQ(extensionConn->IsConnected(), true) << "IsConnected is true";
    EXPECT_EQ(extensionConn->GetExtConnectProxy(), nullptr) << "extConnectProxy is not nullptr";
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest003
 * @tc.desc: connect time out.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest003, TestSize.Level10) {
    Want want;
    int32_t ret = extensionConn->OnConnection(want);

    EXPECT_EQ(ret, HKS_ERROR_CONNECT_TIME_OUT) << "ret is not time out";
    EXPECT_EQ(extensionConn->IsConnected(), false) << "IsConnected is true";
    EXPECT_EQ(extensionConn->GetExtConnectProxy(), nullptr) << "extConnectProxy is not nullptr";
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest004
 * @tc.desc: connect and disconnect.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest004, TestSize.Level10) {
    EXPECT_CALL(*mockProxy, AsObject()).WillRepeatedly(Return(mockRemoteObject)) << "mockProxy is nullptr";
    EXPECT_CALL(*mockRemoteObject, AddDeathRecipient(_, _)).Times(1) << "AddDeathRecipient fail";

    AppExecFwk::ElementName element;
    extensionConn->OnAbilityConnectDone(element, mockRemoteObject, 0);

    EXPECT_EQ(extensionConn->IsConnected(), true) << "connection fail";

    AppExecFwk::ElementName disconnectElement;
    int disconnectResultCode = 0;
    extensionConn->OnAbilityDisconnectDone(disconnectElement, disconnectResultCode);

    EXPECT_EQ(extensionConn->IsConnected(), false) << "disconnect fail";
    EXPECT_EQ(extensionConn->GetExtConnectProxy(), nullptr) << "extConnectProxy is not nullptr";
}

/**
 * @tc.name: ExtensionConnectionTest.ExtensionConnectionTest005
 * @tc.desc: death recipient callback.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionConnectionTest, ExtensionConnectionTest005, TestSize.Level10) {
    EXPECT_CALL(*mockProxy, AsObject()).WillRepeatedly(Return(mockRemoteObject));
    EXPECT_CALL(*mockRemoteObject, AddDeathRecipient(_, _)).Times(1);

    AppExecFwk::ElementName element;
    extensionConn->OnAbilityConnectDone(element, mockProxy, 0);
    EXPECT_EQ(extensionConn->IsConnected(), true) << "IsConnected is false";

    wptr<IRemoteObject> remote(mockRemoteObject);
    extensionConn->OnRemoteDied(remote);

    EXPECT_EQ(extensionConn->IsConnected(), false) << "IsConnected is true";
    EXPECT_EQ(extensionConn->GetExtConnectProxy(), nullptr) << "extConnectProxy is not nullptr";
}

}
}
}

