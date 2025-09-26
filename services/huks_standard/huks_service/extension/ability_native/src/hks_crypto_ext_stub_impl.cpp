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
// #include "hks_log.h"
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
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl test");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    extension_->OpenRemoteHandle(index, params, handle, errcode);
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::CloseRemoteHandle(
    const std::string& handle,
    const CppParamSet& params,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl CloseRemoteHandle");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    // 实现具体的关闭远程句柄逻辑
    extension_->CloseRemoteHandle(handle, params, errcode);
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::AuthUkeyPin(
    const std::string& handle,
    const CppParamSet& params,
    int32_t& errcode,
    int32_t& authState,
    uint32_t& retryCnt)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl AuthUkeyPin");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    // 实现具体的Ukey PIN认证逻辑
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::GetUkeyPinAuthState(
    const std::string& handle,
    const CppParamSet& params,
    uint32_t& state,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl GetUkeyPinAuthState");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    // 实现获取Ukey PIN认证状态的逻辑
    state = 0; // 设置默认状态
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::Sign(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl Sign");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
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
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl Verify");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
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
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO ExportCertificate");
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::ExportProviderCertificates(
    const CppParamSet& params,
    std::string& certJsonArr,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO ExportProviderCertificates");
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::InitSession(
    const std::string& index,
    const CppParamSet& params,
    std::string& handle,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO InitSession");
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::UpdataSession(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO UpdataSession");
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::FinishSession(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO FinishSession");
    return ERR_OK;
}

} // namespace Huks
} // namespace Security
} // namespace OHOS