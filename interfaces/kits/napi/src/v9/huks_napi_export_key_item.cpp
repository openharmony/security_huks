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

#include "huks_napi_export_key_item.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_EXPORT_KEY_MIN_ARGS = 2;
constexpr int HUKS_NAPI_EXPORT_KEY_MAX_ARGS = 3;

ExportKeyAsyncContext CreateExportKeyAsyncContext()
{
    ExportKeyAsyncContext context = static_cast<ExportKeyAsyncContext>(HksMalloc(sizeof(ExportKeyAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(ExportKeyAsyncContextT), 0, sizeof(ExportKeyAsyncContextT));
    }
    return context;
}

void DeleteExportKeyAsyncContext(napi_env env, ExportKeyAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    if (context->key != nullptr) {
        if (context->key->data != nullptr && context->key->size != 0) {
            (void)memset_s(context->key->data, context->key->size, 0, context->key->size);
        }
        FreeHksBlob(context->key);
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->keyAlias, context->paramSet);
    HKS_FREE(context);
    context = nullptr;
}

static napi_value ExportKeyParseParams(napi_env env, napi_callback_info info, ExportKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_EXPORT_KEY_MAX_ARGS;
    napi_value argv[HUKS_NAPI_EXPORT_KEY_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_EXPORT_KEY_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAliasAndHksParamSet(env, argv, index, context->keyAlias, context->paramSet);
    if (result == nullptr) {
        HKS_LOG_E("exportKey parse params failed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

static int32_t PrePareExportKeyContextBuffer(ExportKeyAsyncContext context)
{
    context->key = static_cast<struct HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (context->key == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    context->key->data = static_cast<uint8_t *>(HksMalloc(MAX_KEY_SIZE));
    if (context->key->data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    context->key->size = MAX_KEY_SIZE;
    return HKS_SUCCESS;
}

napi_value ExportKeyAsyncWork(napi_env env, ExportKeyAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "exportKeyAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            (void)env;
            ExportKeyAsyncContext napiContext = static_cast<ExportKeyAsyncContext>(data);
            int32_t ret = PrePareExportKeyContextBuffer(napiContext);
            if (ret == HKS_SUCCESS) {
                napiContext->result = HksExportPublicKey(napiContext->keyAlias,
                    napiContext->paramSet, napiContext->key);
            } else {
                napiContext->result = ret;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ExportKeyAsyncContext napiContext = static_cast<ExportKeyAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            resultData.outData = napiContext->key;
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteExportKeyAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteExportKeyAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiExportKeyItem(napi_env env, napi_callback_info info)
{
    ExportKeyAsyncContext context = CreateExportKeyAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ExportKeyParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteExportKeyAsyncContext(env, context);
        return nullptr;
    }

    result = ExportKeyAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteExportKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
