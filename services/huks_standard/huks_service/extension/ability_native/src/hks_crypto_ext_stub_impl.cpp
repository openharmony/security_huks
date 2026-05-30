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

#include "hks_crypto_ext_stub_impl.h"
#include "hks_cpp_paramset.h"
#include "hks_external_error_info.h"
#include "log_utils.h"

namespace OHOS {
namespace Security {
namespace Huks {

static void SetErrorInfoFromC(struct HksExternalErrorInfo *errInfoC, int32_t ret, HksExternalErrorInfoIdl &errorInfo)
{
    if (errInfoC != nullptr) {
        errorInfo.errVal = errInfoC->errVal;
        errorInfo.errorDesc = errInfoC->errorDesc != nullptr ? errInfoC->errorDesc : "";
        HksFreeExternalErrorInfo(errInfoC);
        return;
    }
    errorInfo.errVal = ret;
    errorInfo.errorDesc.assign("");
}

int32_t HksCryptoExtStubImpl::HksExtStubCheckExtension(HksExternalErrorInfoIdl &errorInfo)
{
    if (extension_ == nullptr) {
        LOGE("extension is nullptr");
        errorInfo.errVal = HKS_ERROR_EXT_NULLPTR;
        errorInfo.errorDesc.assign("");
        return HKS_ERROR_EXT_NULLPTR;
    }
    return HKS_SUCCESS;
}

void HksCryptoExtStubImpl::HksExtStubInitErrorInfo(struct HksExternalErrorInfo **errInfoC)
{
    *errInfoC = HksCreateExternalErrorInfo(HKS_ERROR_EXT_JS_METHOD_ERROR, "");
    if (*errInfoC == nullptr) {
        LOGE("errInfoC: Default value not set.");
    }
}

ErrCode HksCryptoExtStubImpl::OpenRemoteHandle(
    const std::string& index,
    const CppParamSet& params,
    std::string& handle,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);

    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->OpenRemoteHandle(index, params, handle, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::CloseRemoteHandle(
    const std::string& handle,
    const CppParamSet& params,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->CloseRemoteHandle(handle, params, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::AuthUkeyPin(
    const std::string& handle,
    const CppParamSet& params,
    HksExternalErrorInfoIdl& errorInfo,
    int32_t& authState,
    uint32_t& retryCnt)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->AuthUkeyPin(handle, params, &errInfoC, authState, retryCnt);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::GetUkeyPinAuthState(
    const std::string& handle,
    const CppParamSet& params,
    int32_t& state,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    state = 0;
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->GetUkeyPinAuthState(handle, params, state, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::ExportCertificate(
    const std::string& index,
    const CppParamSet& params,
    std::string& certJsonArr,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->ExportCertificate(index, params, certJsonArr, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::ExportProviderCertificates(
    const CppParamSet& params,
    std::string& certJsonArr,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->ExportProviderCertificates(params, certJsonArr, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::ImportCertificate(
    const std::string& index,
    const HksExtCertInfoIdl& certInfo,
    const CppParamSet& params,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->ImportCertificate(index, certInfo, params, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::InitSession(
    const std::string& index,
    const CppParamSet& params,
    std::string& handle,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->InitSession(index, params, handle, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::GenerateKey(
    const std::string& index,
    const CppParamSet& params,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->GenerateKey(index, params, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::UpdateSession(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->UpdateSession(handle, params, inData, outData, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::FinishSession(
    const std::string& handle,
    const CppParamSet& params,
    const std::vector<uint8_t>& inData,
    std::vector<uint8_t>& outData,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->FinishSession(handle, params, inData, outData, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::SetOrGetProperty(
    uint32_t operation,
    const std::string& handle,
    const std::string& propertyId,
    CppParamSet& params,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->SetOrGetProperty(operation, handle, propertyId, params, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::ClearUkeyPinAuthState(
    const std::string& handle,
    const CppParamSet& params,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->ClearUkeyPinAuthState(handle, params, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::ImportWrappedKey(
    const std::string& index,
    const std::string& wrappingKeyIndex,
    const CppParamSet& params,
    const std::vector<uint8_t>& wrappedData,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->ImportWrappedKey(index, wrappingKeyIndex, params, wrappedData, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::ExportPublicKey(
    const std::string& index,
    const CppParamSet& params,
    std::vector<uint8_t>& outData,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->ExportPublicKey(index, params, outData, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

ErrCode HksCryptoExtStubImpl::GetResourceId(
    const CppParamSet &params,
    std::string &resourceId,
    HksExternalErrorInfoIdl& errorInfo)
{
    int32_t ret = HksExtStubCheckExtension(errorInfo);
    HKS_EXT_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret);
    struct HksExternalErrorInfo *errInfoC = nullptr;
    HksExtStubInitErrorInfo(&errInfoC);
    ret = extension_->GetResourceId(params, resourceId, &errInfoC);
    SetErrorInfoFromC(errInfoC, ret, errorInfo);
    return ret;
}

} // namespace Huks
} // namespace Security
} // namespace OHOS