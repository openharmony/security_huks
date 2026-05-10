/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HUKS_NAPI_ML_KEM_H
#define HUKS_NAPI_ML_KEM_H

#include "hks_error_code.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
struct MlKemEncapsulateAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob *sharedKeyAlias = nullptr;
    struct HksParamSet *sharedKeyParamSet = nullptr;
    struct HksEncapsulationResult *encapResult = nullptr;
};
using MlKemEncapsulateAsyncContext = MlKemEncapsulateAsyncContextT *;

struct MlKemDecapsulateAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob *encapOrsharedSecret = nullptr;
    struct HksBlob *sharedKeyAlias = nullptr;
    struct HksParamSet *sharedKeyParamSet = nullptr;
};
using MlKemDecapsulateAsyncContext = MlKemDecapsulateAsyncContextT *;

napi_value HuksNapiMlKemEncapsulate(napi_env env, napi_callback_info info);
napi_value HuksNapiMlKemDecapsulate(napi_env env, napi_callback_info info);

#ifndef NAPI_RES_DEFINED
#define NAPI_RES_DEFINED
struct NapiRes {
    int32_t code{};
    std::string errMsg{};
    NapiRes(int32_t code, std::string errMsg) : code(code), errMsg(std::move(errMsg)) {}
    static NapiRes Ok()
    {
        return {HKS_SUCCESS, ""};
    }
};
#endif
}  // namespace HuksNapiItem

#endif  // HUKS_NAPI_ML_KEM_H