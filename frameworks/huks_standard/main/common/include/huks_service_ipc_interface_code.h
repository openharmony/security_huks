/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HUKS_SERVICE_IPC_INTERFACE_CODE_H
#define HUKS_SERVICE_IPC_INTERFACE_CODE_H

/* SAID: 3510 */
enum HksIpcInterfaceCode {
    HKS_MSG_BASE = 0,

    HKS_MSG_GEN_KEY = HKS_MSG_BASE,
    HKS_MSG_IMPORT_KEY,
    HKS_MSG_EXPORT_PUBLIC_KEY,
    HKS_MSG_IMPORT_WRAPPED_KEY,
    HKS_MSG_DELETE_KEY,
    HKS_MSG_GET_KEY_PARAMSET,
    HKS_MSG_KEY_EXIST,
    HKS_MSG_GENERATE_RANDOM,
    HKS_MSG_SIGN,
    HKS_MSG_VERIFY,
    HKS_MSG_ENCRYPT,
    HKS_MSG_DECRYPT,
    HKS_MSG_AGREE_KEY,
    HKS_MSG_DERIVE_KEY,
    HKS_MSG_MAC,
    HKS_MSG_GET_KEY_INFO_LIST,
    HKS_MSG_ATTEST_KEY,
    HKS_MSG_GET_CERTIFICATE_CHAIN,
    HKS_MSG_INIT,
    HKS_MSG_UPDATE,
    HKS_MSG_FINISH,
    HKS_MSG_ABORT,
    HKS_MSG_CHIPSET_PLATFORM_DECRYPT,
    HKS_MSG_ATTEST_KEY_ASYNC_REPLY,
    HKS_MSG_LIST_ALIASES,

    /* new cmd type must be added before HKS_MSG_MAX */
    HKS_MSG_MAX,
};

#endif /* HUKS_SERVICE_IPC_INTERFACE_CODE_H */
