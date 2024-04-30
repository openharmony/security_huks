/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "huks_napi_list_aliases.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
namespace {
constexpr int HUKS_NAPI_LIST_ALIASES_ARGS = 1;
}  // namespace

struct ListAliasesAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksParamSet *paramSet = nullptr;
    struct HksKeyAliasSet *outSet = nullptr;
};
using ListAliasesAsyncContext = ListAliasesAsyncContextT *;

static ListAliasesAsyncContext CreateListAliasesAsyncContext()
{
    ListAliasesAsyncContext context = static_cast<ListAliasesAsyncContext>(HksMalloc(sizeof(ListAliasesAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(ListAliasesAsyncContextT), 0, sizeof(ListAliasesAsyncContextT));
    }
    return context;
}

static void DeleteListAliasesAsyncContext(napi_env env, ListAliasesAsyncContext &context)
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
    if (context->paramSet != nullptr) {
        HksFreeParamSet(&context->paramSet);
    }
    if (context->outSet !=  nullptr) {
        FreeHksKeyAliasSet(context->outSet, context->outSet->aliasesCnt);
    }

    HKS_FREE(context);
    context = nullptr;
}

static napi_value ListAliasesParseParams(napi_env env, napi_callback_info info, ListAliasesAsyncContext context)
{
    size_t argc = HUKS_NAPI_LIST_ALIASES_ARGS;
    napi_value argv[HUKS_NAPI_LIST_ALIASES_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != HUKS_NAPI_LIST_ALIASES_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseGetHksParamSet(env, argv[index], context->paramSet);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramset");
        HKS_LOG_E("listAliases parse params failed");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value ListAliasesAsyncWork(napi_env env, ListAliasesAsyncContext context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "listAliasesAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ListAliasesAsyncContext napiContext = static_cast<ListAliasesAsyncContext>(data);
            napiContext->result = HksListAliases(napiContext->paramSet, &(napiContext->outSet));
        },
        [](napi_env env, napi_status status, void *data) {
            ListAliasesAsyncContext napiContext = static_cast<ListAliasesAsyncContext>(data);
            HksSuccessListAliasesResult resultData;
            SuccessListAliasesReturnResultInit(resultData);
            resultData.aliasSet = napiContext->outSet;
            HksReturnListAliasesResult(env, napiContext->callback, napiContext->deferred, napiContext->result,
                resultData);
            DeleteListAliasesAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteListAliasesAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value HuksNapiListAliases(napi_env env, napi_callback_info info)
{
    ListAliasesAsyncContext context = CreateListAliasesAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ListAliasesParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteListAliasesAsyncContext(env, context);
        return nullptr;
    }

    result = ListAliasesAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteListAliasesAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
