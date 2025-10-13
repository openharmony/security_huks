/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_IPC_SERVICE_H
#define HKS_IPC_SERVICE_H

#include "hks_type_inner.h"
#include "hks_ipc_service_provider_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

void HksIpcServiceRegisterProvider(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceUnregisterProvider(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceAuthUkeyPin(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceGetUkeyPinAuthState(const struct HksBlob *srcData, const uint8_t *context); 

void HksIpcServiceOpenRemoteHandle(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceGetRemoteHandle(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceCloseRemoteHandle(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceUkeySign(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceUkeyVerify(const struct HksBlob *srcData, const uint8_t *context);


void HksIpcServiceGenerateKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceImportKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceExportPublicKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceImportWrappedKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceDeleteKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceGetKeyParamSet(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceKeyExist(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceGenerateRandom(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceSign(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceVerify(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceEncrypt(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceDecrypt(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceAgreeKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceDeriveKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceMac(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceGetKeyInfoList(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceAttestKey(const struct HksBlob *srcData, const uint8_t *context, const uint8_t *remoteObject);

void HksIpcServiceInit(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context);

void HksIpcServiceUpdate(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context);

void HksIpcServiceFinish(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context);

void HksIpcServiceAbort(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context);

void HksIpcServiceListAliases(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceRenameKeyAlias(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcChangeStorageLevel(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcWrapKey(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcUnwrapKey(const struct HksBlob *srcData, const uint8_t *context);

#ifdef __cplusplus
}
#endif

#endif
