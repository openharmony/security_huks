/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_crypto_ext_ability.h"
#include "extension_context.h"
#include "if_system_ability_manager.h"
#include "js_hks_crypto_ext_ability.h"
#include "runtime.h"
#include "refbase.h"
#include "log_utils.h"
#include "hks_error_code.h"

namespace OHOS {
namespace Security {
namespace Huks {

CreatorFunc HksCryptoExtAbility::creator_ = nullptr;
void HksCryptoExtAbility::SetCreator(const CreatorFunc &creator)
{
    creator_ = creator;
}

HksCryptoExtAbility* HksCryptoExtAbility::Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    if (runtime == nullptr) {
        return new (std::nothrow) HksCryptoExtAbility();
    }

    if (creator_) {
        return creator_(runtime);
    }

    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            return JsHksCryptoExtAbility::Create(runtime);
        default:
            return new (std::nothrow) HksCryptoExtAbility();
    }
}

void HksCryptoExtAbility::Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
    const std::shared_ptr<AbilityRuntime::OHOSApplication> &application,
    std::shared_ptr<AbilityRuntime::AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    ExtensionBase<>::Init(record, application, handler, token);
}

int32_t HksCryptoExtAbility::OpenRemoteHandle(const std::string &index, const CppParamSet &params, std::string &handle,
    int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::OpenRemoteHandle Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::CloseRemoteHandle(const std::string &handle, const CppParamSet &params, int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::CloseRemoteHandle Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::AuthUkeyPin(const std::string &handle, const CppParamSet &params, int32_t &errcode,
    int32_t &authState, uint32_t &retryCnt)
{
    LOGE("HksCryptoExtAbility::AuthUkeyPin Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::GetUkeyPinAuthState(const std::string &handle, const CppParamSet &params,
    int32_t &authState, int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::GetUkeyPinAuthState Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::ExportCertificate(const std::string &index, const CppParamSet &params,
    std::string &certJsonArr, int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::ExportCertificate Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::ExportProviderCertificates(const CppParamSet &params, std::string &certJsonArr,
    int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::ExportProviderCertificates Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::InitSession(const std::string &index, const CppParamSet &params, std::string &handle,
    int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::InitSession Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::UpdateSession(const std::string &handle, const CppParamSet &params,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::UpdateSession Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::FinishSession(const std::string &handle, const CppParamSet &params,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::FinishSession Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::GetProperty(const std::string &handle, const std::string &propertyId,
    const CppParamSet &params, CppParamSet &outParams, int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::GetProperty Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

int32_t HksCryptoExtAbility::ClearUkeyPinAuthState(const std::string &handle,
    const CppParamSet &params, int32_t &errcode)
{
    LOGE("HksCryptoExtAbility::ClearUkeyPinAuthState Undefined operation");
    return HKS_ERROR_EXT_UNDEFINED_OPERATION;
}

} // namespace HUKS
} // namespace Security
} // namespace OHOS