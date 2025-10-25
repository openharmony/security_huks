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

#include "native_huks_external_crypto_api.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_errcode_adapter.h"
#include "hks_error_code.h"
#include "stdlib.h"

static struct OH_Huks_Result ConvertApiResult(int32_t ret)
{
    struct HksResult result = HksConvertErrCode(ret);
    return *((struct OH_Huks_Result *)(&result));
}

struct OH_Huks_Result OH_Huks_RegisterProvider(const struct OH_Huks_Blob *providerName,
    const OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t result = HksRegisterProvider((const struct HksBlob *) providerName, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_UnregisterProvider(const struct OH_Huks_Blob *providerName,
    const OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t result = HksUnregisterProvider((const struct HksBlob *) providerName,
        (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_OpenResource(const struct OH_Huks_Blob *resourceId,
    const OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t ret = HksOpenRemoteHandle((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GetResource(const struct OH_Huks_Blob *resourceId,
    const struct OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t ret = HksGetRemoteHandle((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_CloseResource(const struct OH_Huks_Blob *resourceId,
    const OH_Huks_ExternalCryptoParamSet *paramSet)
{
    int32_t ret = HksCloseRemoteHandle((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSet);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_AuthUkeyPin(const struct OH_Huks_Blob *resourceId,
    const struct OH_Huks_ExternalCryptoParamSet *paramSetIn, uint32_t *retryCount)
{
    int32_t ret = HksAuthUkeyPin((const struct HksBlob *) resourceId,
        (const struct HksParamSet *) paramSetIn, retryCount);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GetUkeyPinAuthState(const struct OH_Huks_Blob *resourceId,
    const OH_Huks_ExternalCryptoParamSet *paramSetIn, bool *authState)
{
    if (authState == NULL) {
        return ConvertApiResult(HKS_ERROR_NULL_POINTER);
    }
    *authState = false;
    int32_t state = 0;
    int32_t ret = HksGetUkeyPinAuthState((const struct HksBlob *)resourceId,
        (const struct HksParamSet *)paramSetIn, &state);
    if (ret == 0) {
        *authState = (state == 0);
    }
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GetProperty(const struct OH_Huks_Blob *resourceId,
    const struct OH_Huks_Blob *propertyId, const OH_Huks_ExternalCryptoParamSet *paramSetIn,
    OH_Huks_ExternalCryptoParamSet **paramSetOut)
{
    if (paramSetOut == NULL) {
        return ConvertApiResult(HKS_ERROR_NULL_POINTER);
    }
    struct HksParamSet *innerOut = NULL;
    int32_t ret = HksGetRemoteProperty(
        (const struct HksBlob *)resourceId, (const struct HksBlob *)propertyId,
        (const struct HksParamSet *)paramSetIn, &innerOut);
    if (ret == HKS_SUCCESS) {
        *paramSetOut = (struct OH_Huks_ExternalCryptoParamSet *)innerOut;
    }
    return ConvertApiResult(ret);
}

static struct OH_Huks_Result ConvertExtParamResult(int32_t ret)
{
    struct HksResult result = HksConvertErrCode(ret);
    return *((struct OH_Huks_Result *)(&result));
}

struct OH_Huks_Result OH_Huks_InitExternalCryptoParamSet(OH_Huks_ExternalCryptoParamSet **paramSet)
{
    int32_t result = HksInitParamSet((struct HksParamSet **) paramSet);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_AddExternalCryptoParams(OH_Huks_ExternalCryptoParamSet *paramSet,
    const OH_Huks_ExternalCryptoParam *params, uint32_t paramCnt)
{
    int32_t result = HksAddParams((struct HksParamSet *) paramSet,
        (const struct HksParam *) params, paramCnt);
    return ConvertExtParamResult(result);
}

struct OH_Huks_Result OH_Huks_BuildExternalCryptoParamSet(OH_Huks_ExternalCryptoParamSet **paramSet)
{
    int32_t result = HksBuildParamSet((struct HksParamSet **) paramSet);
    return ConvertExtParamResult(result);
}

void OH_Huks_FreeExternalCryptoParamSet(OH_Huks_ExternalCryptoParamSet **paramSet)
{
    HksFreeParamSet((struct HksParamSet **) paramSet);
}

struct OH_Huks_Result OH_Huks_GetExternalCryptoParam(struct OH_Huks_ExternalCryptoParamSet *paramSet,
    uint32_t tag, struct OH_Huks_ExternalCryptoParam **param)
{
    int32_t result = HksGetParam((const struct HksParamSet *) paramSet, tag, (struct HksParam **) param);
    return ConvertExtParamResult(result);
}
