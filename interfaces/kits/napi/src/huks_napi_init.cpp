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

#include "huks_napi_init.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common.h"

namespace HuksNapi {
namespace {
constexpr int HUKS_NAPI_INIT_MIN_ARGS = 2;
constexpr int HUKS_NAPI_INIT_MAX_ARGS = 3;

constexpr int HKS_MAX_TOKEN_SIZE = 2048;
}  // namespace

struct InitAsyncContext {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int64_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob *handle = nullptr;
    struct HksBlob *token = nullptr;
};

using InitAsyncCtxPtr = InitAsyncContext *;

static InitAsyncCtxPtr CreateInitAsyncContext()
{
    InitAsyncCtxPtr context = (InitAsyncCtxPtr)HksMalloc(sizeof(InitAsyncContext));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(InitAsyncContext), 0, sizeof(InitAsyncContext));
    }
    return context;
}

static void DeleteInitAsyncContext(napi_env env, InitAsyncCtxPtr &context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
        context->asyncWork = nullptr;
    }

    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
        context->callback = nullptr;
    }

    if (context->keyAlias != nullptr) {
        FreeHksBlob(context->keyAlias);
    }

    if (context->paramSet != nullptr) {
        HksFreeParamSet(&context->paramSet);
    }

    if (context->handle != nullptr) {
        FreeHksBlob(context->handle);
    }

    if (context->token != nullptr) {
        FreeHksBlob(context->token);
    }

    HksFree(context);
    context = nullptr;
}

static napi_value ParseInitParams(napi_env env, napi_callback_info info, InitAsyncCtxPtr context)
{
    size_t argc = HUKS_NAPI_INIT_MAX_ARGS;
    napi_value argv[HUKS_NAPI_INIT_MAX_ARGS] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_INIT_MIN_ARGS) {
        napi_throw_error(env, NULL, "invalid arguments");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAlias(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        HKS_LOG_E("could not get init alias");
        return nullptr;
    }

    index++;
    napi_value properties = nullptr;
    napi_status status =
        napi_get_named_property(env, argv[index], HKS_OPTIONS_PROPERTY_PROPERTIES.c_str(), &properties);
    if (status != napi_ok || properties == nullptr) {
        GET_AND_THROW_LAST_ERROR((env));
        HKS_LOG_E("could not get init property %s", HKS_OPTIONS_PROPERTY_PROPERTIES.c_str());
        return nullptr;
    }
    result = ParseHksParamSet(env, properties, context->paramSet);
    if (result == nullptr) {
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

static int32_t InitOutParams(InitAsyncCtxPtr context)
{
    /* free buffer use DeleteInitAsyncContext */
    context->handle = (HksBlob *)HksMalloc(sizeof(HksBlob));
    if (context->handle == nullptr) {
        HKS_LOG_E("malloc handle failed");
        return HKS_ERROR_MALLOC_FAIL;
    }
    context->handle->data = (uint8_t *)HksMalloc(HKS_MAX_TOKEN_SIZE);
    if (context->handle->data == nullptr) {
        HKS_LOG_E("malloc handle data failed");
        return HKS_ERROR_MALLOC_FAIL;
    }
    context->handle->size = HKS_MAX_TOKEN_SIZE;

    context->token = (HksBlob *)HksMalloc(sizeof(HksBlob));
    if (context->token == nullptr) {
        HKS_LOG_E("malloc token failed");
        return HKS_ERROR_MALLOC_FAIL;
    }
    context->token->data = (uint8_t *)HksMalloc(HKS_MAX_TOKEN_SIZE);
    if (context->token->data == nullptr) {
        HKS_LOG_E("malloc token data failed");
        return HKS_ERROR_MALLOC_FAIL;
    }
    context->token->size = HKS_MAX_TOKEN_SIZE;
    return HKS_SUCCESS;
}

static napi_value InitWriteResult(napi_env env, InitAsyncCtxPtr context)
{
    return GenerateHksHandle(env, context->result, context->handle, context->token);
}

static napi_value InitAsyncWork(napi_env env, InitAsyncCtxPtr context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName;
    napi_create_string_latin1(env, "InitAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            (void)env;
            InitAsyncCtxPtr context = static_cast<InitAsyncCtxPtr>(data);
            int32_t ret = InitOutParams(context);
            if (ret != HKS_SUCCESS) {
                context->result = ret;
                return;
            }
            context->result = HksInit(context->keyAlias, context->paramSet, context->handle, context->token);
        },
        [](napi_env env, napi_status status, void *data) {
            InitAsyncCtxPtr context = static_cast<InitAsyncCtxPtr>(data);
            napi_value result = InitWriteResult(env, context);
            if (context->callback == nullptr) {
                napi_resolve_deferred(env, context->deferred, result);
            } else if (result != nullptr) {
                CallAsyncCallback(env, context->callback, context->result, result);
            }
            DeleteInitAsyncContext(env, context);
        },
        (void *)context,
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteInitAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    }
    return GetNull(env);
}

napi_value HuksNapiInit(napi_env env, napi_callback_info info)
{
    InitAsyncCtxPtr context = CreateInitAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ParseInitParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteInitAsyncContext(env, context);
        return nullptr;
    }

    result = InitAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteInitAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapi
