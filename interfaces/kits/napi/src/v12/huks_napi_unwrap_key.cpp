/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "huks_napi_unwrap_key.h"

#include "hks_errcode_adapter.h"
#include "hks_template.h"
#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
namespace {
constexpr int HUKS_NAPI_UNWRAP_KEY_ARGS = 3;
}  // namespace

struct UnwrapKeyAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob *wrappedKey = nullptr;
};
using UnwrapKeyAsyncContext = UnwrapKeyAsyncContextT *;

static UnwrapKeyAsyncContext CreateUnwrapKeyAsyncContext()
{
    UnwrapKeyAsyncContext context = static_cast<UnwrapKeyAsyncContext>(HksMalloc(sizeof(UnwrapKeyAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(UnwrapKeyAsyncContextT), 0, sizeof(UnwrapKeyAsyncContextT));
    }
    return context;
}

static void DeleteUnwrapKeyAsyncContext(napi_env env, UnwrapKeyAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->keyAlias, context->paramSet);

    if (context->wrappedKey != nullptr) {
        FreeHksBlob(context->wrappedKey);
    }

    HKS_FREE(context);
    context = nullptr;
}

static napi_value UnwrapKeyParseParams(napi_env env, napi_callback_info info, UnwrapKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_UNWRAP_KEY_ARGS;
    napi_value argv[HUKS_NAPI_UNWRAP_KEY_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != HUKS_NAPI_UNWRAP_KEY_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_INVALID_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAliasAndHksParamSet(env, argv, index, context->keyAlias, context->paramSet);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_INVALID_ARGUMENT, "could not get paramset");
        HKS_LOG_E("UnwrapKey parse params failed");
        return nullptr;
    }

    index++;
    context->wrappedKey = static_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (context->wrappedKey == nullptr) {
        HKS_LOG_E("malloc context wrappedKey failed");
        return nullptr;
    }

    result = GetUint8Array(env, argv[index], *context->wrappedKey);
    if (result == nullptr) {
        HKS_LOG_E("importWrappedKey parse keyData failed");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value UnwrapKeyAsyncWork(napi_env env, UnwrapKeyAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "UnwrapKeyAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            UnwrapKeyAsyncContext napiContext = static_cast<UnwrapKeyAsyncContext>(data);
            napiContext->result = HksUnwrapKey(napiContext->keyAlias, nullptr, napiContext->wrappedKey,
                napiContext->paramSet);
            struct HksResult result = HksConvertErrCode(napiContext->result);
            if (result.errorCode == HUKS_ERR_CODE_ILLEGAL_ARGUMENT) {
                napiContext->result = HKS_ERROR_NEW_INVALID_ARGUMENT;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            UnwrapKeyAsyncContext napiContext = static_cast<UnwrapKeyAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result,
                resultData);
            DeleteUnwrapKeyAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);
    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteUnwrapKeyAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value HuksNapiUnwrapKey(napi_env env, napi_callback_info info)
{
    UnwrapKeyAsyncContext context = CreateUnwrapKeyAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = UnwrapKeyParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteUnwrapKeyAsyncContext(env, context);
        return nullptr;
    }

    result = UnwrapKeyAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteUnwrapKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
    
