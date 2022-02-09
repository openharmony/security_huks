/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HKS_SERVICE_CORE_HAL_H
#define HKS_SERVICE_CORE_HAL_H

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksHalModuleInit(void);
int32_t HksHalRefresh(void);
int32_t HksHalGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut);
int32_t HksHalImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut);
int32_t HksHalImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut);
int32_t HksHalExportPublicKey(const struct HksBlob *key,  const struct HksParamSet *paramSet, struct HksBlob *keyOut);
int32_t HksHalInit(const struct  HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *handle);
int32_t HksHalUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);
int32_t HksHalFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);
int32_t HksHalAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet);
int32_t HksHalGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key);
int32_t HksHalAttestKey(const struct HksBlob *key, const  struct HksParamSet *paramSet,
    struct HksBlob *certChain);
int32_t HksHalGetAbility(int funcType);
int32_t HksHalGetHardwareInfo(); // -1失败，0：REE，1：TEE,2:SE

#ifdef __cplusplus
}
#endif
#endif