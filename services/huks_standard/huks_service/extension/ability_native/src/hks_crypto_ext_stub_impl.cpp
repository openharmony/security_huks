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

#include "hks_crypto_ext_stub_impl.h"
#include "hks_cpp_paramset.h"
#include "log_utils.h"
namespace OHOS {
namespace Security {
namespace Huks {
ErrCode HksCryptoExtStubImpl::OpenRemoteHandle(
    const std::string& index,
    const CppParamSet& params,
    std::string& handle,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->OpenRemoteHandle(index, params, handle, errcode);
}

ErrCode HksCryptoExtStubImpl::CloseRemoteHandle(
    const std::string& handle,
    const CppParamSet& params,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->CloseRemoteHandle(handle, params, errcode);
}

ErrCode HksCryptoExtStubImpl::AuthUkeyPin(
    const std::string& handle,
    const CppParamSet& params,
    int32_t& errcode,
    int32_t& authState,
    uint32_t& retryCnt)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->AuthUkeyPin(handle, params, errcode, authState, retryCnt);
}

ErrCode HksCryptoExtStubImpl::GetUkeyPinAuthState(
    const std::string& handle,
    const CppParamSet& params,
    int32_t& state,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    state = 0; // 设置默认状态
    int32_t authState = 0;
    extension_->GetUkeyPinAuthState(handle, params, authState, errcode);
    return state = static_cast<uint32_t>(authState);
}

ErrCode HksCryptoExtStubImpl::Sign(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    // 实现签名逻辑
    // outData = ...; // 设置签名结果
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::Verify(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& plainText,
    const std::vector<uint8_t>& signature,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    // 实现验证逻辑
    // 设置errcode为验证结果
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::ExportCertificate(
    const std::string& index,
    const CppParamSet& params,
    std::string& certJsonArr,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->ExportCertificate(index, params, certJsonArr, errcode);
}

ErrCode HksCryptoExtStubImpl::ExportProviderCertificates(
    const CppParamSet& params,
    std::string& certJsonArr,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->ExportProviderCertificates(params, certJsonArr, errcode);
}

ErrCode HksCryptoExtStubImpl::InitSession(
    const std::string& index,
    const CppParamSet& params,
    std::string& handle,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->InitSession(index, params, handle, errcode);
}

ErrCode HksCryptoExtStubImpl::UpdateSession(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->UpdateSession(handle, params, inData, outData, errcode);
}

ErrCode HksCryptoExtStubImpl::FinishSession(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    int32_t& errcode)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        return ERR_OK;
    }
    return extension_->FinishSession(handle, params, inData, outData, errcode);
}

ErrCode HksCryptoExtStubImpl::GetProperty(
    const std::string& handle,
    const std::string& propertyId,
    const CppParamSet& params,
    CppParamSet& outParams,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO GetProperty");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    return extension_->GetProperty(handle, propertyId, params, outParams, errcode);
}

ErrCode HksCryptoExtStubImpl::GetResourceId(
    const CppParamSet& params,
    std::string& resourceId,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO GetResourceId");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    // TODO 实现具体的获取资源ID逻辑
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::ClearUkeyPinAuthState(
    const std::string& handle,
    const CppParamSet& params,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO ClearUkeyPinAuthState");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    return extension_->ClearUkeyPinAuthState(handle, params, errcode);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS