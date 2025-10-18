/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef HUKS_NAPI_UKEY_H
#define HUKS_NAPI_UKEY_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "huks_napi_common_item.h"

#include "hks_param.h"

namespace HuksNapiItem {
#define NAPI_CALL_RETURN_ERR(env, ret)   \
    if ((ret) != napi_ok)                \
    {                                    \
        GET_AND_THROW_LAST_ERROR((env)); \
        return ret;                      \
    }

#define NAPI_THROW_BASE(env, condition, ret, code, message)           \
    if ((condition))                                                  \
    {                                                                 \
        HKS_LOG_E(message);                                           \
        napi_throw((env), NapiCreateError((env), (code), (message))); \
        return (ret);                                                 \
    }

#define NAPI_THROW(env, condition, code, message) \
    NAPI_THROW_BASE(env, condition, nullptr, code, message)

#define NAPI_THROW_RETURN_ERR(env, condition, ret, code, message) \
    NAPI_THROW_BASE(env, condition, ret, code, message)

class AsyncContext {
public:
    virtual ~AsyncContext()
    {
        if (asyncWork != nullptr && env != nullptr) {
            napi_delete_async_work(env, asyncWork);
        }

        if (callback != nullptr) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }

        if (paramSetIn != nullptr) {
            HksFreeParamSet(&paramSetIn);
        }
        if (paramSetOut != nullptr) {
            HksFreeParamSet(&paramSetOut);
        }
    }

    napi_env env;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
    int32_t result = 0;

    std::function<napi_status(napi_env, napi_callback_info, AsyncContext *)> parse;
    napi_async_execute_callback execute;
    std::function<void(napi_env, AsyncContext *)> resolve;

    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
};

class ProviderRegContext : public AsyncContext {
public:
    ~ProviderRegContext()
    {
        if (name != nullptr) {
            FreeHksBlob(name);
        }
    }
    struct HksBlob *name = nullptr;
};

class UkeyPinContext : public AsyncContext {
public:
    ~UkeyPinContext()
    {
        if (index != nullptr) {
            FreeHksBlob(index);
        }
    }
    struct HksBlob *index = nullptr;
    int32_t outStatus = 0;
    uint32_t retryCount = 0;
};

// 对外接口
napi_value HuksNapiRegisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiUnregisterProvider(napi_env env, napi_callback_info info);

napi_value HuksNapiAuthUkeyPin(napi_env env, napi_callback_info info);

napi_value HuksNapiGetUkeyPinAuthState(napi_env env, napi_callback_info info);

// 工具函数
napi_value NapiCreateError(napi_env env, int32_t errCode, const char *errMsg);

napi_value ParseString(napi_env env, napi_value object, HksBlob *&alias);

} // namespace HuksNapiItem

#endif // HUKS_NAPI_UKEY_H