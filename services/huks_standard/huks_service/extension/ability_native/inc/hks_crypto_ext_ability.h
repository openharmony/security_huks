/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HUKS_CRYPTO_EXT_ABILITY_H
#define HUKS_CRYPTO_EXT_ABILITY_H

#include "extension_base.h"
#include "want.h"
#include "hks_cpp_paramset.h"
#include "hks_ext_cert_info.h"

namespace OHOS {
namespace AbilityRuntime {
class Runtime;
}
namespace Security {
namespace Huks {
class HksCryptoExtAbility;
using CreatorFunc = std::function<HksCryptoExtAbility *(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)>;
class HksCryptoExtAbility : public AbilityRuntime::ExtensionBase<> {
public:
    HksCryptoExtAbility() = default;
    virtual ~HksCryptoExtAbility() = default;

    virtual void Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
        const std::shared_ptr<AbilityRuntime::OHOSApplication> &application,
        std::shared_ptr<AbilityRuntime::AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    static HksCryptoExtAbility *Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);
    static void SetCreator(const CreatorFunc &creator);

    virtual int OpenRemoteHandle(const std::string &index, const CppParamSet &params, std::string &handle,
        int32_t &errcode);
    virtual int CloseRemoteHandle(const std::string &handle, const CppParamSet &params, int32_t &errcode);
    virtual int AuthUkeyPin(const std::string &handle, const CppParamSet &params, int32_t &errcode, int32_t &authState,
        uint32_t &retryCnt);
    virtual int GetUkeyPinAuthState(const std::string &handle, const CppParamSet &params, int32_t &authState,
        int32_t &errcode);
    virtual int ExportCertificate(const std::string &index, const CppParamSet &params, std::string &certJsonArr,
        int32_t &errcode);
    virtual int ExportProviderCertificates(const CppParamSet &params, std::string &certJsonArr, int32_t &errcode);
    virtual int ImportCertificate(const std::string &index, const HksExtCertInfoIdl& certInfo,
        const CppParamSet &params, int32_t &errcode);
    virtual int InitSession(const std::string &index, const CppParamSet &params, std::string &handle, int32_t &errcode);
    virtual int UpdateSession(const std::string &handle, const CppParamSet &params, const std::vector<uint8_t> &inData,
        std::vector<uint8_t> &outData, int32_t &errcode);
    virtual int FinishSession(const std::string &handle, const CppParamSet &params, const std::vector<uint8_t> &inData,
        std::vector<uint8_t> &outData, int32_t &errcode);
    virtual int GetProperty(const std::string& handle, const std::string& propertyId, const CppParamSet& params,
        CppParamSet& outParams, int32_t& errcode);
    virtual int ClearUkeyPinAuthState(const std::string& handle, const CppParamSet& params, int32_t& errcode);
    virtual int ImportWrappedKey(const std::string& index, const std::string& wrappingKeyIndex,
        const CppParamSet& params, const std::vector<uint8_t>& wrappedData, int32_t& errcode);
    virtual int ExportPublicKey(const std::string& index, const CppParamSet& params,
        std::vector<uint8_t>& outData, int32_t& errcode);
    virtual int GenerateKey(const std::string &handle, const CppParamSet &params, int32_t &errcode);
    virtual int GetResourceId(const CppParamSet &params, std::string &resourceId, int32_t &errcode);
private:
    static CreatorFunc creator_;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // HUKS_CRYPTO_EXT_ABILITY_H