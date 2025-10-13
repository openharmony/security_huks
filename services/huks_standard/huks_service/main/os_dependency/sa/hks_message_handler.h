/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_MESSAGE_HANDLER_H
#define HKS_MESSAGE_HANDLER_H

#include "huks_service_ipc_interface_code.h"

#include "hks_ipc_service.h"
#include "hks_type.h"

typedef void (*HksIpcHandlerFuncProc)(const struct HksBlob *msg, const uint8_t *context);

struct HksIpcEntryPoint {
    enum HksIpcInterfaceCode msgId;
    HksIpcHandlerFuncProc handler;
};

const struct HksIpcEntryPoint HKS_IPC_MESSAGE_HANDLER[] = {
    { HKS_MSG_GEN_KEY, HksIpcServiceGenerateKey },
    { HKS_MSG_IMPORT_KEY, HksIpcServiceImportKey },
    { HKS_MSG_EXPORT_PUBLIC_KEY, HksIpcServiceExportPublicKey },
    { HKS_MSG_IMPORT_WRAPPED_KEY, HksIpcServiceImportWrappedKey },
    { HKS_MSG_DELETE_KEY, HksIpcServiceDeleteKey },
    { HKS_MSG_GET_KEY_PARAMSET, HksIpcServiceGetKeyParamSet },
    { HKS_MSG_KEY_EXIST, HksIpcServiceKeyExist },
    { HKS_MSG_GENERATE_RANDOM, HksIpcServiceGenerateRandom },
    { HKS_MSG_SIGN, HksIpcServiceSign },
    { HKS_MSG_VERIFY, HksIpcServiceVerify },
    { HKS_MSG_ENCRYPT, HksIpcServiceEncrypt },
    { HKS_MSG_DECRYPT, HksIpcServiceDecrypt },
    { HKS_MSG_AGREE_KEY, HksIpcServiceAgreeKey },
    { HKS_MSG_DERIVE_KEY, HksIpcServiceDeriveKey },
    { HKS_MSG_MAC, HksIpcServiceMac },
    { HKS_MSG_GET_KEY_INFO_LIST, HksIpcServiceGetKeyInfoList },
    { HKS_MSG_LIST_ALIASES, HksIpcServiceListAliases },
    { HKS_MSG_RENAME_KEY_ALIAS, HksIpcServiceRenameKeyAlias },
    { HKS_MSG_CHANGE_STORAGE_LEVEL, HksIpcChangeStorageLevel },
    { HKS_MSG_WRAP_KEY, HksIpcWrapKey },
    { HKS_MSG_UNWRAP_KEY, HksIpcUnwrapKey },

    { HKS_MSG_EXT_REGISTER, HksIpcServiceRegisterProvider },
    { HKS_MSG_EXT_UNREGISTER, HksIpcServiceUnregisterProvider },
    { HKS_MSG_EXT_AUTH_UKEY_PIN, HksIpcServiceAuthUkeyPin },
    { HKS_MSG_EXT_GET_UKEY_PIN_AUTH_STATE, HksIpcServiceGetUkeyPinAuthState },
    { HKS_MSG_EXT_CLEAR_PIN_AUTH_STATE, HksIpcServiceClearPinAuthState },
    { HKS_MSG_EXT_OPEN_REMOTE_HANDLE, HksIpcServiceOpenRemoteHandle },
    { HKS_MSG_EXT_GET_REMOTE_HANDLE, HksIpcServiceGetRemoteHandle },
    { HKS_MSG_EXT_CLOSE_REMOTE_HANDLE, HksIpcServiceCloseRemoteHandle },
    { HKS_MSG_EXT_UKEY_SIGN, HksIpcServiceUkeySign },
    { HKS_MSG_EXT_UKEY_VERIFY, HksIpcServiceUkeyVerify },

};

typedef void (*HksIpcThreeStageHandlerFuncProc)(const struct HksBlob *msg, struct HksBlob *outData,
    const uint8_t *context);

struct HksIpcThreeStagePoint {
    enum HksIpcInterfaceCode msgId;
    HksIpcThreeStageHandlerFuncProc handler;
};

const struct HksIpcThreeStagePoint HKS_IPC_THREE_STAGE_HANDLER[] = {
    { HKS_MSG_INIT, HksIpcServiceInit },
    { HKS_MSG_UPDATE, HksIpcServiceUpdate },
    { HKS_MSG_FINISH, HksIpcServiceFinish },
    { HKS_MSG_ABORT, HksIpcServiceAbort },
};

void HksIpcErrorResponse(const uint8_t *context);

#endif