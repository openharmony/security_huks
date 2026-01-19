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
#include "ihuks_access_ext_base.h"
#include "hks_plugin_def.h"

namespace OHOS {
namespace Security {
namespace Huks {
    
class MockIHuksAccessExtBase : public IHuksAccessExtBase {
public:
    MOCK_METHOD(ErrCode, OpenRemoteHandle,
        (const std::string &index, const CppParamSet &params, std::string &handle, int &errcode), (override));

    MOCK_METHOD(ErrCode, CloseRemoteHandle,
        (const std::string &handle, const CppParamSet &params, int &errcode), (override));

    MOCK_METHOD(ErrCode, AuthUkeyPin,
        (const std::string &handle, const CppParamSet &params, int &errcode, int &authState, unsigned int &retryCnt), (override));

    MOCK_METHOD(ErrCode, GetUkeyPinAuthState,
        (const std::string &handle, const CppParamSet &params, int &state, int &errcode), (override));

    MOCK_METHOD(ErrCode, Sign,
        (const std::string &handle, const CppParamSet &params, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, int &errcode), (override));

    MOCK_METHOD(ErrCode, Verify,
        (const std::string &handle, const CppParamSet &params, const std::vector<uint8_t> &plainText, const std::vector<uint8_t> &signature, int &errcode), (override));

    MOCK_METHOD(ErrCode, ExportCertificate,
        (const std::string &index, const CppParamSet &params, std::string &certJsonArr, int &errcode), (override));

    MOCK_METHOD(ErrCode, ExportProviderCertificates,
        (const CppParamSet &params, std::string &certJsonArr, int &errcode), (override));

    MOCK_METHOD(ErrCode, InitSession,
        (const std::string &index, const CppParamSet &params, std::string &handle, int &errcode), (override));

    MOCK_METHOD(ErrCode, UpdateSession,
        (const std::string &handle, const CppParamSet &params, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, int &errcode), (override));

    MOCK_METHOD(ErrCode, FinishSession,
        (const std::string &handle, const CppParamSet &params, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, int &errcode), (override));

    MOCK_METHOD(ErrCode, GetProperty,
        (const std::string &handle, const std::string &propertyId, const CppParamSet &params, CppParamSet &outParams, int &errcode), (override));

    MOCK_METHOD(ErrCode, GetResourceId,
        (const CppParamSet &params, std::string &resourceId, int &errcode), (override));

    MOCK_METHOD(ErrCode, ClearUkeyPinAuthState,
        (const std::string &handle, const CppParamSet &params, int &errcode), (override));

    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class MockIRemoteObject : public IRemoteObject {
public:
    MOCK_METHOD(int32_t, GetObjectRefCount, (), (override));
    MOCK_METHOD(int, SendRequest, (uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option),
        (override));
    MOCK_METHOD(bool, IsProxyObject, (), (const, override));
    MOCK_METHOD(bool, AddDeathRecipient, (const sptr<DeathRecipient> &recipient), (override));
    MOCK_METHOD(bool, RemoveDeathRecipient, (const sptr<DeathRecipient> &recipient), (override));
    MOCK_METHOD(int, Dump, (int fd, const std::vector<std::u16string> &args), (override));
    MockIRemoteObject() : IRemoteObject(u"mock_IRemoteObject") {}
};

class ExtensionConnectionTest : public testing::Test {
public:
    void SimulateAbilityConnectResponse();

    void SimulateAbilityDisconnectResponse();

protected:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp() override;

    void TearDown() override;
    
    sptr<ExtensionConnection> connection_;
    AAFwk::Want want_;
    int32_t userId_;
};

}
}
}

#endif