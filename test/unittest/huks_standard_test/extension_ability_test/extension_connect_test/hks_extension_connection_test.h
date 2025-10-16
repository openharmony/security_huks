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

#ifndef HKS_EXTENSION_CONNECTION_TEST_H
#define HKS_EXTENSION_CONNECTION_TEST_H
#include "iremote_broker.h"
#include "hks_extension_connection.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace OHOS {
namespace Security {
namespace Huks {
class ExtensionConnectionTest : public testing::Test {
protected:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp() override;

    void TearDown() override;
    
    std::shared_ptr<ExtensionConnection> extensionConn;
    sptr<MockIRemoteObject> mockRemoteObject = new MockIRemoteObject();
    sptr<MockDesignAccessExtBase> mockProxy = new MockDesignAccessExtBase();
};

class MockIRemoteObject : public IRemoteObject {
public:
    MOCK_METHOD2(AddDeathRecipient, void(sptr<DeathRecipient>&, int));
    MOCK_METHOD2(RemoveDeathRecipient, void(sptr<DeathRecipient>&, int));

};

class MockDesignAccessExtBase : public DesignAccessExtBase {
public:
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
};

}
}
}

#endif