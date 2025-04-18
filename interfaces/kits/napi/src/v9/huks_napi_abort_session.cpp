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

#include "huks_napi_abort_session.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_ABORT_MIN_ARGS = 2;
constexpr int HUKS_NAPI_ABORT_MAX_ARGS = 3;

AbortAsyncContext CreateAbortAsyncContext()
{
    AbortAsyncContext context = static_cast<AbortAsyncContext>(HksMalloc(sizeof(AbortAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(AbortAsyncContextT), 0, sizeof(AbortAsyncContextT));
    }
    return context;
}

void DeleteAbortAsyncContext(napi_env env, AbortAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->handle, context->paramSet);
    HKS_FREE(context);
    context = nullptr;
}

static napi_value ParseAbortParams(napi_env env, napi_callback_info info, AbortAsyncContext context)
{
    size_t argc = HUKS_NAPI_ABORT_MAX_ARGS;
    napi_value argv[HUKS_NAPI_ABORT_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_ABORT_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = GetHandleValue(env, argv[index], context->handle);
    if (result == nullptr) {
        HKS_LOG_E("could not get handle value");
        return nullptr;
    }

    index++;
    napi_value property = GetPropertyFromOptions(env, argv[index], HKS_OPTIONS_PROPERTY_PROPERTIES);
    if (property == nullptr) {
        return nullptr;
    }

    result = ParseHksParamSetAndAddParam(env, property, context->paramSet);
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

napi_value AbortAsyncWork(napi_env env, AbortAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName;
    napi_create_string_latin1(env, "AbortAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AbortAsyncContext napiContext = static_cast<AbortAsyncContext>(data);
            napiContext->result = HksAbort(napiContext->handle, napiContext->paramSet);
        },
        [](napi_env env, napi_status status, void *data) {
            AbortAsyncContext napiContext = static_cast<AbortAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteAbortAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteAbortAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiAbortSession(napi_env env, napi_callback_info info)
{
    AbortAsyncContext context = CreateAbortAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ParseAbortParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteAbortAsyncContext(env, context);
        return nullptr;
    }

    result = AbortAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteAbortAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
