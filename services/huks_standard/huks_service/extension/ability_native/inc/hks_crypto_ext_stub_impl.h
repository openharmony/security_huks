/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FILE_ACCESS_EXT_STUB_IMPL_H
#define FILE_ACCESS_EXT_STUB_IMPL_H

#include <memory>
#include <vector>
#include "hks_cpp_paramset.h"
#include "huks_access_ext_base_stub.h"
#include "hks_crypto_ext_ability.h"
#include "hks_ext_cert_info.h"
#include "hks_ext_error_info.h"

namespace OHOS {
namespace Security {
namespace Huks {
class HksCryptoExtStubImpl : public HuksAccessExtBaseStub {
public:
    explicit HksCryptoExtStubImpl(const std::shared_ptr<HksCryptoExtAbility>& extension)
        : extension_(extension) {}

    virtual ~HksCryptoExtStubImpl() {}

    ErrCode OpenRemoteHandle(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        HksExternalErrorInfoIdl& errorInfo) override;

    ErrCode CloseRemoteHandle(
        const std::string& handle,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo) override;

    ErrCode AuthUkeyPin(
        const std::string& handle,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo,
        int32_t& authState,
        uint32_t& retryCnt) override;

    ErrCode GetUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& state,
        HksExternalErrorInfoIdl& errorInfo) override;

    ErrCode ExportCertificate(
        const std::string& index,
        const CppParamSet& params,
        std::string& certJsonArr,
        HksExternalErrorInfoIdl& errorInfo) override;

    ErrCode ExportProviderCertificates(
        const CppParamSet& params,
        std::string& certJsonArr,
        HksExternalErrorInfoIdl& errorInfo) override;

    ErrCode ImportCertificate(
        const std::string& index,
        const HksExtCertInfoIdl& certInfo,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo) override;

    ErrCode InitSession(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        int32_t& errcode) override;

    ErrCode GenerateKey(
        const std::string& index,
        const CppParamSet& params,
        int32_t& errcode) override;

    ErrCode UpdateSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) override;

    ErrCode FinishSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) override;

    ErrCode SetOrGetProperty(
        uint32_t operation,
        const std::string& handle,
        const std::string& propertyId,
        CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo) override;
    
    ErrCode ClearUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo) override;

    ErrCode ImportWrappedKey(
        const std::string& index,
        const std::string& wrappingKeyIndex,
        const CppParamSet& params,
        const std::vector<uint8_t>& wrappedData,
        int32_t& errcode) override;

    ErrCode ExportPublicKey(
        const std::string& index,
        const CppParamSet& params,
        std::vector<uint8_t>& outData,
        int32_t& errcode) override;

    ErrCode GetResourceId(
        const CppParamSet &params,
        std::string &resourceId,
        HksExternalErrorInfoIdl& errorInfo) override;
private:
    std::shared_ptr<HksCryptoExtAbility> extension_;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // FILE_ACCESS_EXT_STUB_IMPL_H
