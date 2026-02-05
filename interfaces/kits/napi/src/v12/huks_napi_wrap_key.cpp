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

#include "huks_napi_wrap_key.h"

#include "hks_error_code.h"
#include "js_native_api_types.h"
#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"
#include <cstdint>
#include "hks_template.h"

namespace HuksNapiItem {
namespace {
constexpr int HUKS_NAPI_WRAP_KEY_ARGS = 2;
}  // namespace

struct WrapKeyAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob *wrappedKey = nullptr;
};
using WrapKeyAsyncContext = WrapKeyAsyncContextT *;

static WrapKeyAsyncContext CreateWrapKeyAsyncContext()
{
    WrapKeyAsyncContext context = static_cast<WrapKeyAsyncContext>(HksMalloc(sizeof(WrapKeyAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(WrapKeyAsyncContextT), 0, sizeof(WrapKeyAsyncContextT));
    }
    return context;
}

static void DeleteWrapKeyAsyncContext(napi_env env, WrapKeyAsyncContext &context)
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

static napi_value WrapKeyParseParams(napi_env env, napi_callback_info info, WrapKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_WRAP_KEY_ARGS;
    napi_value argv[HUKS_NAPI_WRAP_KEY_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != HUKS_NAPI_WRAP_KEY_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_INVALID_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAliasAndHksParamSet(env, argv, index, context->keyAlias, context->paramSet);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_INVALID_ARGUMENT, "could not get paramset");
        HKS_LOG_E("WrapKey parse params failed");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static int32_t PrepareWrapKeyContextBuffer(WrapKeyAsyncContext context)
{
    context->wrappedKey = static_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (context->wrappedKey == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    context->wrappedKey->data = static_cast<uint8_t *>(HksMalloc(MAX_KEY_SIZE));
    if (context->wrappedKey->data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    context->wrappedKey->size = MAX_KEY_SIZE;
    return HKS_SUCCESS;
}

static napi_value WrapKeyAsyncWork(napi_env env, WrapKeyAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }
    napi_value resourceName = nullptr;
    napi_status napiStatus = napi_create_string_latin1(env, "WrapKeyAsyncWork", NAPI_AUTO_LENGTH, &resourceName);
    if (napiStatus != napi_ok) {
        return nullptr;
    }
    napi_create_async_work(env, nullptr, resourceName, [](napi_env env, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            WrapKeyAsyncContext napiContext = static_cast<WrapKeyAsyncContext>(data);
            int32_t ret = PrepareWrapKeyContextBuffer(napiContext);
            if (ret == HKS_SUCCESS) {
                napiContext->result = HksWrapKey(napiContext->keyAlias, nullptr, napiContext->paramSet,
                    napiContext->wrappedKey);
            } else {
                napiContext->result = ret;
            }
            struct HksResult result = HksConvertErrCode(napiContext->result);
            if (result.errorCode == HUKS_ERR_CODE_ILLEGAL_ARGUMENT) {
                napiContext->result = HKS_ERROR_NEW_INVALID_ARGUMENT;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            WrapKeyAsyncContext napiContext = static_cast<WrapKeyAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            resultData.outData = napiContext->wrappedKey;
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result,
                resultData);
            DeleteWrapKeyAsyncContext(env, napiContext);
        }, static_cast<void *>(context), &context->asyncWork);
    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteWrapKeyAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value HuksNapiWrapKey(napi_env env, napi_callback_info info)
{
    WrapKeyAsyncContext context = CreateWrapKeyAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = WrapKeyParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteWrapKeyAsyncContext(env, context);
        return nullptr;
    }

    result = WrapKeyAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteWrapKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
