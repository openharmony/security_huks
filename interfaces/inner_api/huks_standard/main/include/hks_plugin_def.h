/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

/**
 * @file hks_plugin_def.h
 *
 * @brief Declares huks plugin struct and enum.
 *
 * @since 12
 */

#ifndef HKS_PLUGIN_DEF_H
#define HKS_PLUGIN_DEF_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief hks process info
 */
struct HksProcessInfo {
    struct HksBlob userId;
    struct HksBlob processName;
    int32_t userIdInt;
    uint32_t uidInt;
    uint64_t accessTokenId;
};

enum LocalRequestCode {
    CODE_UPGRADE = 1,
};

/**
 * @brief hks base ability interface
 */
struct HksBasicInterface {
    int32_t (*hksManageStoreKeyBlob)(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
        const struct HksBlob *keyAlias, const struct HksBlob *keyBlob, uint32_t storageType);
    int32_t (*hksManageStoreDeleteKeyBlob)(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
        const struct HksBlob *keyAlias, uint32_t storageType);
    int32_t (*hksManageStoreIsKeyBlobExist)(const struct HksProcessInfo *processInfo,
        const struct HksParamSet *paramSet, const struct HksBlob *keyAlias, uint32_t storageType);
    int32_t (*hksManageStoreGetKeyBlob)(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
        const struct HksBlob *keyAlias, struct HksBlob *keyBlob, uint32_t storageType);
    int32_t (*hksManageStoreGetKeyBlobSize)(const struct HksProcessInfo *processInfo,
        const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
        uint32_t *keyBlobSize, uint32_t storageType);
    int32_t (*hksManageGetKeyCountByProcessName)(const struct HksProcessInfo *processInfo,
        const struct HksParamSet *paramSet, uint32_t *fileCount);

    int32_t (*hksGetProcessInfoForIPC)(const uint8_t *context, struct HksProcessInfo *processInfo);

    int32_t (*appendStorageParamsForGen)(const struct HksProcessInfo *processInfo,
        const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);
    int32_t (*appendStorageParamsForUse)(const struct HksParamSet *paramSet,
        const struct HksProcessInfo *processInfo, struct HksParamSet **outParamSet);
    int32_t (*appendStorageParamsForQuery)(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);
};

/**
 * @brief hks plugin proxy
 */
struct HksPluginProxy {
    int32_t (*hksPluginInit)(struct HksBasicInterface *interfaceInst);
    void (*hksPluginDestory)(void);
    int32_t (*hksPluginOnRemoteRequest)(uint32_t code, void *data, void *reply, void *option);
    int32_t (*hksPluginOnLocalRequest)(uint32_t code, const void *data, void *reply);
    void (*hksPluginOnReceiveEvent)(const void *eventData);
};

#ifdef __cplusplus
}
#endif

#endif // HKS_PLUGIN_DEF_H