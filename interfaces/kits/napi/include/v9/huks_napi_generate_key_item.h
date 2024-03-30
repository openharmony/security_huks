/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HUKS_NAPI_GENERATE_KEY_ITEM_H
#define HUKS_NAPI_GENERATE_KEY_ITEM_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "hks_param.h"

namespace HuksNapiItem {
struct GenerateKeyAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
};
using GenerateKeyAsyncContext = GenerateKeyAsyncContextT *;

GenerateKeyAsyncContext CreateGenerateKeyAsyncContext();

void DeleteGenerateKeyAsyncContext(napi_env env, GenerateKeyAsyncContext &context);

napi_value GenerateKeyAsyncWork(napi_env env, GenerateKeyAsyncContext context);

napi_value HuksNapiItemGenerateKey(napi_env env, napi_callback_info info);
}  // namespace HuksNapi

#endif  // HUKS_NAPI_GENERATE_KEY_ITEM_H