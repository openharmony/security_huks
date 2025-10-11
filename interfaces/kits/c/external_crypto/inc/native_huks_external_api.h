/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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


#ifndef NATIVE_HUKS_EXTERNAL_API_H
#define NATIVE_HUKS_EXTERNAL_API_H

#include "native_huks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Obtains the current HUKS SDK version.
 *
 * @param sdkVersion Indicates the pointer to the SDK version (in string format) obtained.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 401 - If sdkVersion or
 *             sdkVersion->data is null, or if sdkVersion->size is too small.
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GetSdkVersion(struct OH_Huks_Blob *sdkVersion);

// 注册&注销
struct OH_Huks_Result OH_Huks_RegisterProvider(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ExternalCryptoParamSet *paramSet);
struct OH_Huks_Result OH_Huks_UnregisterProvider(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ExternalCryptoParamSet *paramSet);

// 证书导出
struct OH_Huks_Result OH_Huks_ExportProviderCertificates(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, struct OH_Huks_ExtCertInfoSet *certSet);
struct OH_Huks_Result OH_Huks_ExportCertificate(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, struct OH_Huks_ExtCertInfoSet *certSet);


// 句柄管理
struct OH_Huks_Result OH_Huks_OpenRemoteHandle(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet, struct OH_Huks_Blob *remoteHandleOut);
struct OH_Huks_Result OH_Huks_GetRemoteHandle(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet, struct OH_Huks_Blob *remoteHandleOut);
struct OH_Huks_Result OH_Huks_CloseRemoteHandle(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet);

// PIN码认证
struct OH_Huks_Result OH_Huks_AuthUkeyPin(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, uint32_t *retryCount);
struct OH_Huks_Result OH_Huks_GetUkeyPinAuthState(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, bool *stateOut);
struct OH_Huks_Result OH_Huks_ClearPinAuthState(const struct OH_Huks_Blob *resourceId);

// 签名验签
struct OH_Huks_Result OH_Huks_Sign(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet,
    const struct OH_Huks_Blob *srcData, struct OH_Huks_Blob *signatureOut);
struct OH_Huks_Result OH_Huks_Verify(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet,
    const struct OH_Huks_Blob *srcData, struct OH_Huks_Blob *signatureOut);
#ifdef __cplusplus
}
#endif

/** @} */
#endif /* NATIVE_HUKS_EXTERNAL_API_H */
