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

#include "native_huks_api.h"

#include "hks_api.h"
#include "hks_errcode_adapter.h"
#include "hks_error_code.h"
#include "native_huks_api_adapter.h"
#include "stdlib.h"

static struct OH_Huks_Result ConvertApiResult(int32_t ret)
{
    struct HksResult result = HksConvertErrCode(ret);
    return *((struct OH_Huks_Result *)(&result));
}

static struct OH_Huks_Result NewConvertApiResult(int32_t ret)
{
    struct HksResult result = HksConvertErrCode(ret);
    if (result.errorCode == HUKS_ERR_CODE_ILLEGAL_ARGUMENT) {
        result.errorCode = HUKS_ERR_CODE_INVALID_ARGUMENT;
    }
    return *((struct OH_Huks_Result *)(&result));
}

struct OH_Huks_Result OH_Huks_GetSdkVersion(struct OH_Huks_Blob *sdkVersion)
{
    int32_t result = HksGetSdkVersion((struct HksBlob *) sdkVersion);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_RegisterProvider(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ParamSet *paramSet)
{
    int32_t result = HksRegisterProvider((const struct HksBlob *) providerName, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_UnregisterProvider(const struct OH_Huks_Blob *providerName, const struct OH_Huks_ParamSet *paramSet)
{
    int32_t result = HksUnregisterProvider((const struct HksBlob *) providerName, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_OpenRemoteHandle(const struct OH_Huks_Blob *index, const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *remoteHandleOut)
{
    int32_t ret = HksOpenRemoteHandle((const struct HksBlob *) index,
        (const struct HksParamSet *) paramSet, (struct HksBlob *) remoteHandleOut);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GetRemoteHandle(const struct OH_Huks_Blob *index, const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *remoteHandleOut)
{
    int32_t ret = HksGetRemoteHandle((const struct HksBlob *) index,
        (const struct HksParamSet *) paramSet, (struct HksBlob *) remoteHandleOut);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_CloseRemoteHandle(const struct OH_Huks_Blob *index, const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *remoteHandleOut)
{
    int32_t ret = HksCloseRemoteHandle((const struct HksBlob *) index,
        (const struct HksParamSet *) paramSet, (struct HksBlob *) remoteHandleOut);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_AuthUkeyPin(const struct OH_Huks_Blob *index, const struct OH_Huks_ParamSet *paramSetIn, uint32_t *retryCount)
{
    int32_t ret = HksAuthUkeyPinWithRetry((const struct HksBlob *) index,
        (const struct HksParamSet *) paramSetIn, retryCount);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GetPinAuthState(const struct OH_Huks_Blob *index, uint32_t *stateOut)
{
    int32_t ret = HksGetPinAuthState((const struct HksBlob *) index, stateOut);
    return ConvertApiResult(ret);
}
struct OH_Huks_Result OH_Huks_ClearPinAuthState(const struct OH_Huks_Blob *index)
{
    int32_t ret = HksClearPinAuthState((const struct HksBlob *) index);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_Sign(const struct OH_Huks_Blob *index, const struct OH_Huks_ParamSet *paramSet,
    const struct OH_Huks_Blob *srcData, struct OH_Huks_Blob *signatureOut)
{
    int32_t ret = HksUkeySign((const struct HksBlob *) index,
        (const struct HksParamSet *) paramSet, (const struct HksBlob *) srcData, (struct HksBlob *) signatureOut);
    return ConvertApiResult(ret);
}

struct OH_Huks_Result OH_Huks_GenerateKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSetIn, struct OH_Huks_ParamSet *paramSetOut)
{
    int32_t result = HksGenerateKey((const struct HksBlob *) keyAlias,
        (const struct HksParamSet *) paramSetIn, (struct HksParamSet *) paramSetOut);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_ImportKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *key)
{
    int32_t result = HksImportKey((const struct HksBlob *) keyAlias,
        (const struct HksParamSet *) paramSet, (const struct HksBlob *) key);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_ImportWrappedKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_Blob *wrappingKeyAlias, const struct OH_Huks_ParamSet *paramSet,
    const struct OH_Huks_Blob *wrappedKeyData)
{
    int32_t result = HksImportWrappedKey((const struct HksBlob *) keyAlias,
        (const struct HksBlob *) wrappingKeyAlias, (const struct HksParamSet *) paramSet,
        (const struct HksBlob *) wrappedKeyData);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_ExportPublicKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *key)
{
    int32_t result = HksExportPublicKey((const struct HksBlob *) keyAlias,
        (const struct HksParamSet *) paramSet, (struct HksBlob *) key);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_DeleteKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet)
{
    int32_t result = HksDeleteKey((const struct HksBlob *) keyAlias, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_GetKeyItemParamSet(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSetIn, struct OH_Huks_ParamSet *paramSetOut)
{
    int32_t result = HksGetKeyParamSet((const struct HksBlob *) keyAlias,
        (const struct HksParamSet *) paramSetIn, (struct HksParamSet *) paramSetOut);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_IsKeyItemExist(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet)
{
    int32_t result = HksKeyExist((const struct HksBlob *) keyAlias, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_AttestKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_CertChain *certChain)
{
    int32_t result = HuksAttestAdapter(keyAlias, paramSet, certChain, false);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_AnonAttestKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_CertChain *certChain)
{
    int32_t result = HuksAttestAdapter(keyAlias, paramSet, certChain, true);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_InitSession(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *handle, struct OH_Huks_Blob *token)
{
    int32_t result = HksInit((const struct HksBlob *) keyAlias,
        (const struct HksParamSet *) paramSet, (struct HksBlob *) handle, (struct HksBlob *) token);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_UpdateSession(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *outData)
{
    int32_t result = HksUpdate((const struct HksBlob *) handle,
        (const struct HksParamSet *) paramSet, (const struct HksBlob *) inData, (struct HksBlob *) outData);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_FinishSession(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *outData)
{
    int32_t result = HksFinish((const struct HksBlob *) handle,
        (const struct HksParamSet *) paramSet, (const struct HksBlob *) inData, (struct HksBlob *) outData);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_AbortSession(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet)
{
    int32_t result = HksAbort((const struct HksBlob *) handle, (const struct HksParamSet *) paramSet);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_ListAliases(const struct OH_Huks_ParamSet *paramSet,
    struct OH_Huks_KeyAliasSet **outData)
{
    int32_t result = HksListAliases((const struct HksParamSet *) paramSet, (struct HksKeyAliasSet **) outData);
    return ConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_WrapKey(const struct OH_Huks_Blob *keyAlias, const struct OH_Huks_ParamSet *paramSet,
    struct OH_Huks_Blob *wrappedKey)
{
    int32_t result = HksWrapKey((const struct HksBlob *) keyAlias, NULL, (const struct HksParamSet *) paramSet,
        (struct HksBlob *) wrappedKey);
    return NewConvertApiResult(result);
}

struct OH_Huks_Result OH_Huks_UnwrapKey(const struct OH_Huks_Blob *keyAlias, const struct OH_Huks_ParamSet *paramSet,
    const struct OH_Huks_Blob *wrappedKey)
{
    int32_t result = HksUnwrapKey((const struct HksBlob *) keyAlias, NULL, (struct HksBlob *) wrappedKey,
        (const struct HksParamSet *) paramSet);
    return NewConvertApiResult(result);
}
