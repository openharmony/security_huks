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

#include "huks_napi_delete_key.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common.h"

namespace HuksNapi {
namespace {
constexpr int HUKS_NAPI_DELETE_KEY_MIN_ARGS = 2;
constexpr int HUKS_NAPI_DELETE_KEY_MAX_ARGS = 3;
}  // namespace

struct DeleteKeyAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSet = nullptr;
};
using DeleteKeyAsyncContext = DeleteKeyAsyncContextT *;

static DeleteKeyAsyncContext CreateDeleteKeyAsyncContext()
{
    DeleteKeyAsyncContext context = static_cast<DeleteKeyAsyncContext>(HksMalloc(sizeof(DeleteKeyAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(DeleteKeyAsyncContextT), 0, sizeof(DeleteKeyAsyncContextT));
    }
    return context;
}

static void DeleteDeleteKeyAsyncContext(napi_env env, DeleteKeyAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->keyAlias, context->paramSet);
    HKS_FREE(context);
    context = nullptr;
}

static napi_value DeleteKeyParseParams(napi_env env, napi_callback_info info, DeleteKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_DELETE_KEY_MAX_ARGS;
    napi_value argv[HUKS_NAPI_DELETE_KEY_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_DELETE_KEY_MIN_ARGS) {
        napi_throw_error(env, nullptr, "invalid arguments");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAliasAndHksParamSet(env, argv, index, context->keyAlias, context->paramSet);
    if (result == nullptr) {
        HKS_LOG_E("deleteKey parse params failed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

static napi_value DeleteKeyWriteResult(napi_env env, DeleteKeyAsyncContext context)
{
    return GenerateHksResult(env, context->result, nullptr, 0);
}

static napi_value DeleteKeyAsyncWork(napi_env env, DeleteKeyAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "deleteKeyAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            DeleteKeyAsyncContext napiContext = static_cast<DeleteKeyAsyncContext>(data);

            napiContext->result = HksDeleteKey(napiContext->keyAlias, napiContext->paramSet);
        },
        [](napi_env env, napi_status status, void *data) {
            DeleteKeyAsyncContext napiContext = static_cast<DeleteKeyAsyncContext>(data);
            napi_value result = DeleteKeyWriteResult(env, napiContext);
            if (napiContext->callback == nullptr) {
                napi_resolve_deferred(env, napiContext->deferred, result);
            } else if (result != nullptr) {
                CallAsyncCallback(env, napiContext->callback, napiContext->result, result);
            }
            DeleteDeleteKeyAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteDeleteKeyAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiDeleteKey(napi_env env, napi_callback_info info)
{
    DeleteKeyAsyncContext context = CreateDeleteKeyAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = DeleteKeyParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteDeleteKeyAsyncContext(env, context);
        return nullptr;
    }

    result = DeleteKeyAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteDeleteKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapi
