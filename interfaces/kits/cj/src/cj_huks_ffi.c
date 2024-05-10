/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <string.h>

#include "hks_api.h"
#include "hks_errcode_adapter.h"

#include "cj_huks_ffi.h"

int32_t FfiOHOSGetSdkVersion(struct HksBlob *sdkVersion)
{
    return HksGetSdkVersion(sdkVersion);
}

int32_t FfiOHOSInitSession(const char *keyAlias, const struct HksParamSet *paramSet,
                           struct HksBlob *handle, struct HksBlob *token)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksInit(&keyAliasBlob, paramSet, handle, token);
}

int32_t FfiOHOSUpdateSession(const struct HksBlob *handle, const struct HksParamSet *paramSet,
                             const struct HksBlob *inData, struct HksBlob *outData)
{
    return HksUpdate(handle, paramSet, inData, outData);
}

int32_t FfiOHOSFinishSession(const struct HksBlob *handle, const struct HksParamSet *paramSet,
                             const struct HksBlob *inData, struct HksBlob *outData)
{
    return HksFinish(handle, paramSet, inData, outData);
}

int32_t FfiOHOSAbortSession(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    return HksAbort(handle, paramSet);
}

int32_t FfiOHOSIsKeyExist(const char *keyAlias, const struct HksParamSet *paramSet)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksKeyExist(&keyAliasBlob, paramSet);
}

int32_t FfiOHOSGetKeyItemProperties(const char *keyAlias,
                                    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksGetKeyParamSet(&keyAliasBlob, paramSetIn, paramSetOut);
}

int32_t FfiOHOSHAttestKey(const char *keyAlias, const struct HksParamSet *paramSet,
                          struct HksCertChain *certChain)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksAttestKey(&keyAliasBlob, paramSet, certChain);
}

int32_t FfiOHOSHAnonAttestKey(const char *keyAlias, const struct HksParamSet *paramSet,
                              struct HksCertChain *certChain)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksAnonAttestKey(&keyAliasBlob, paramSet, certChain);
}

int32_t FfiOHOSExportKey(const char *keyAlias, const struct HksParamSet *paramSet,
                         struct HksBlob *key)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksExportPublicKey(&keyAliasBlob, paramSet, key);
}

int32_t FfiOHOSImportWrappedKey(const char *keyAlias, const char *wrappingKeyAlias,
                                const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    struct HksBlob wrappingKeyAliasBlob = {strlen(wrappingKeyAlias), (uint8_t *)wrappingKeyAlias};
    return HksImportWrappedKey(&keyAliasBlob, &wrappingKeyAliasBlob, paramSet, wrappedKeyData);
}

int32_t FfiOHOSGenerateKey(const char *keyAlias, const struct HksParamSet *paramSetIn,
                           struct HksParamSet *paramSetOut)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksGenerateKey(&keyAliasBlob, paramSetIn, paramSetOut);
}

int32_t FfiOHOSDeleteKey(const char *keyAlias, const struct HksParamSet *paramSet)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksDeleteKey(&keyAliasBlob, paramSet);
}

int32_t FfiOHOSImportKey(const char *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *key)
{
    struct HksBlob keyAliasBlob = {strlen(keyAlias), (uint8_t *)keyAlias};
    return HksImportKey(&keyAliasBlob, paramSet, key);
}

void FfiOHOSConvertErrCode(int32_t hksCode, struct HksResult *ret)
{
    *ret = HksConvertErrCode(hksCode);
}
