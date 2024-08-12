/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef HKS_CORE_SERVICE_KEY_OPERATE_THREE_STAGE_H
#define HKS_CORE_SERVICE_KEY_OPERATE_THREE_STAGE_H

#include <stdint.h>

#include "hks_type.h"
#include "hks_keynode.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCoreInit(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle,
    struct HksBlob *token);

int32_t HksCoreUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData);

int32_t HksCoreFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData);

int32_t HksCoreAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet);

struct HksCoreInitHandler {
    enum HksKeyPurpose pur;
    int32_t (*handler)(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
        uint32_t alg);
};

struct HksCoreUpdateHandler {
    enum HksKeyPurpose pur;
    int32_t (*handler)(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, struct HksBlob *signature, uint32_t alg);
};

struct HksCoreFinishHandler {
    enum HksKeyPurpose pur;
    int32_t (*handler)(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg);
};

struct HksCoreAbortHandler {
    enum HksKeyPurpose pur;
    int32_t (*handler)(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet, uint32_t alg);
};

#ifdef __cplusplus
}
#endif

#endif /* HKS_CORE_SERVICE_KEY_OPERATE_THREE_STAGE_H */