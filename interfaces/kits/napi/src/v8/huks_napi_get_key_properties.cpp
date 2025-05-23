/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "huks_napi_get_key_properties.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common.h"

namespace HuksNapi {
namespace {
constexpr int HUKS_NAPI_GET_KEY_PROPERTIES_MIN_ARGS = 2;
constexpr int HUKS_NAPI_GET_KEY_PROPERTIES_MAX_ARGS = 3;

constexpr int HKS_DEFAULT_OUTPARAMSET_SIZE = 2048;
}  // namespace

struct GetKeyPropertiesAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
};
using GetKeyPropertiesAsyncContext = GetKeyPropertiesAsyncContextT *;

static GetKeyPropertiesAsyncContext CreateGetKeyPropertiesAsyncContext()
{
    GetKeyPropertiesAsyncContext context =
        static_cast<GetKeyPropertiesAsyncContext>(HksMalloc(sizeof(GetKeyPropertiesAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(GetKeyPropertiesAsyncContextT), 0, sizeof(GetKeyPropertiesAsyncContextT));
    }
    return context;
}

static void DeleteGetKeyPropertiesAsyncContext(napi_env env, GetKeyPropertiesAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->keyAlias, context->paramSetIn);
    if (context->paramSetOut != nullptr) {
        HksFreeParamSet(&context->paramSetOut);
    }
    HKS_FREE(context);
    context = nullptr;
}

static napi_value GetKeyPropertiesParseParams(
    napi_env env, napi_callback_info info, GetKeyPropertiesAsyncContext context)
{
    size_t argc = HUKS_NAPI_GET_KEY_PROPERTIES_MAX_ARGS;
    napi_value argv[HUKS_NAPI_GET_KEY_PROPERTIES_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_GET_KEY_PROPERTIES_MIN_ARGS) {
        napi_throw_error(env, nullptr, "invalid arguments");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAliasAndHksParamSet(env, argv, index, context->keyAlias, context->paramSetIn);
    if (result == nullptr) {
        HKS_LOG_E("getKeyProperties parse params failed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

static napi_value GetKeyPropertiesWriteResult(napi_env env, GetKeyPropertiesAsyncContext context)
{
    return GenerateHksResult(env, context->result, nullptr, 0, *context->paramSetOut);
}

static napi_value GetKeyPropertiesAsyncWork(napi_env env, GetKeyPropertiesAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getKeyPropertiesAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            GetKeyPropertiesAsyncContext napiContext = static_cast<GetKeyPropertiesAsyncContext>(data);

            napiContext->paramSetOut = static_cast<struct HksParamSet *>(HksMalloc(HKS_DEFAULT_OUTPARAMSET_SIZE));
            if (napiContext->paramSetOut != nullptr) {
                napiContext->paramSetOut->paramSetSize = HKS_DEFAULT_OUTPARAMSET_SIZE;
                napiContext->paramSetOut->paramsCnt = 0;
            }

            napiContext->result = HksGetKeyParamSet(napiContext->keyAlias,
                napiContext->paramSetIn, napiContext->paramSetOut);
        },
        [](napi_env env, napi_status status, void *data) {
            GetKeyPropertiesAsyncContext napiContext = static_cast<GetKeyPropertiesAsyncContext>(data);
            napi_value result = GetKeyPropertiesWriteResult(env, napiContext);
            if (napiContext->callback == nullptr) {
                napi_resolve_deferred(env, napiContext->deferred, result);
            } else if (result != nullptr) {
                CallAsyncCallback(env, napiContext->callback, napiContext->result, result);
            }
            DeleteGetKeyPropertiesAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetKeyPropertiesAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiGetKeyProperties(napi_env env, napi_callback_info info)
{
    GetKeyPropertiesAsyncContext context = CreateGetKeyPropertiesAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = GetKeyPropertiesParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteGetKeyPropertiesAsyncContext(env, context);
        return nullptr;
    }

    result = GetKeyPropertiesAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteGetKeyPropertiesAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapi
