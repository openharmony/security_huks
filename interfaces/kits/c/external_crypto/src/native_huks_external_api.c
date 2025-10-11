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

#include "native_huks_external_api.h"

#include "hks_api.h"
#include "hks_errcode_adapter.h"
#include "hks_error_code.h"
#include "stdlib.h"

static struct OH_Huks_Result ConvertApiResult(int32_t ret)
{
    struct HksResult result = HksConvertErrCode(ret);
    return *((struct OH_Huks_Result *)(&result));
}

struct OH_Huks_Result OH_Huks_GetSdkVersion(struct OH_Huks_Blob *sdkVersion)
{
    int32_t result = HksGetSdkVersion((struct HksBlob *) sdkVersion);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_RegisterProvider(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t result = HksRegisterProvider((const struct HksBlob *) providerName, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_UnregisterProvider(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t result = HksUnregisterProvider((const struct HksBlob *) providerName, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_ExportCertificate(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, struct OH_Huks_ExtCertInfoSet *certSet)
{
    int32_t result = HksExportCertificate((const struct HksBlob *) resourceId, (const struct HksParamSet *) paramSetIn, (struct HksExtCertInfoSet *) certSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_ExportProviderCertificates(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, struct OH_Huks_ExtCertInfoSet *certSet)
{
    int32_t result = HksExportProviderCertificates((const struct HksBlob *) providerName, (const struct HksParamSet *) paramSetIn, (struct HksExtCertInfoSet *) certSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_OpenRemoteHandle(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet, struct OH_Huks_Blob *remoteHandleOut)
{
    int32_t ret = HksOpenRemoteHandle((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet, (struct HksBlob *) remoteHandleOut);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GetRemoteHandle(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet, struct OH_Huks_Blob *remoteHandleOut)
{
    int32_t ret = HksGetRemoteHandle((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet, (struct HksBlob *) remoteHandleOut);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_CloseRemoteHandle(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t ret = HksCloseRemoteHandle((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_AuthUkeyPin(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, uint32_t *retryCount)
{
    int32_t ret = HksAuthUkeyPin((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSetIn, retryCount);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GetUkeyPinAuthState(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, int32_t *stateOut)
{
    int32_t ret = HksGetUkeyPinAuthState((const struct HksBlob *) resourceId, (const struct HksParamSet *) paramSetIn, stateOut);
    return ConvertApiResult(ret);
}
struct OH_Huks_Result OH_Huks_ClearPinAuthState(const struct OH_Huks_Blob *resourceId)
{
    int32_t ret = HksClearPinAuthState((const struct HksBlob *) resourceId);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_Sign(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet,
    const struct OH_Huks_Blob *srcData, struct OH_Huks_Blob *signatureOut)
{
    int32_t ret = HksUkeySign((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet, (const struct HksBlob *) srcData, (struct HksBlob *) signatureOut);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_Verify(const struct OH_Huks_Blob *resourceId, const struct OH_Huks_ExternalCryptoParamSet *paramSet,
    const struct OH_Huks_Blob *srcData, struct OH_Huks_Blob *signatureOut)
{
    int32_t ret = HksUkeyVerify((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet, (const struct HksBlob *) srcData, (struct HksBlob *) signatureOut);
    return ConvertApiResult(ret);
}
