/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "huks_napi_anon_Attest_Key_Item_Offline.h"
#include "hks_error_code.h"

#include "js_native_api_types.h"
#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_attest_key_item.h"
#include "huks_napi_common_item.h"

#undef NAPI_CALL
#undef NAPI_CALL_BASE
#undef GET_AND_THROW_LAST_ERROR
#undef NAPI_CALL_RETURN_VOID
#undef NAPI_ASSERT_RETURN_VOID

namespace HuksNapiItem {
constexpr int HUKS_NAPI_ATTEST_KEY_MIN_ARGS = 2;
constexpr int HUKS_NAPI_ATTEST_KEY_MAX_ARGS = 3;
constexpr int HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT = 3;

static napi_value AttestKeyOfflineAsUserParseParams(napi_env env, napi_callback_info info,
    AttestKeyAsyncContext &context)
{
    size_t argc = HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT;
    napi_value argv[HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT] = { 0 };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        HksNapiThrow(env, HUKS_ERR_CODE_EXTERNAL_ERROR, "bad env");
        HKS_LOG_E("parase env fail!");
        return nullptr;
    }

    if (argc != HUKS_NAPI_ATTEST_KEY_AS_USER_ARGS_COUNT) {
        HksNapiThrowInvalidParamCount(env);
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    int userId = 0;
    size_t index = 0;
    napi_value result = GetUserIdValue(env, argv[index], userId);
    if (result == nullptr) {
        HksNapiThrowGetUserIdFail(env);
        HKS_LOG_E("AttestKeyAsUserParseParams could not get user id value");
        return nullptr;
    }
    index++;
    result = ParseKeyAlias(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get key alias");
        HKS_LOG_E("could not get alias");
        return nullptr;
    }

    index++;
    const std::vector<HksParam> addParams = {
        {.tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = userId}};
    result = ParseHuksParams(env, argv[index], addParams, context->paramSet);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_INVALID_ARGUMENT, "could not get paramset");
        HKS_LOG_E("could not get paramset");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }

    if (!HksCheckIsAllowAsUserApi(context->paramSet)) {
        HksNapiThrowFeatureNotSupport(env);
        HKS_LOG_E("As user api not support");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value AttestKeyAsyncWorkOffline(napi_env env, AttestKeyAsyncContext &context)
{
    napi_value promise = nullptr;

    HKS_IF_NOT_TRUE_LOGE_RETURN(napi_create_promise(env, &context->deferred, &promise) == napi_ok,
        nullptr, "AttestKeyAsyncWorkOffline create promise fail")
    
    napi_value resourceName = nullptr;
    HKS_IF_NOT_TRUE_LOGE_RETURN(napi_create_string_latin1(env, "attestKeyAsyncWork", NAPI_AUTO_LENGTH,
        &resourceName) == napi_ok, nullptr, "attestKeyAsyncWork fail");

    napi_status status = napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            AttestKeyAsyncContext napiContext = static_cast<AttestKeyAsyncContext>(data);
            napiContext->certChain = static_cast<struct HksCertChain *>(HksMalloc(sizeof(struct HksCertChain)));
            if (napiContext->certChain != nullptr) {
                napiContext->result = InitCertChain(napiContext->certChain, &napiContext->certChainCapacity);
                if (napiContext->result != HKS_SUCCESS) {
                    return;
                }
            }
            napiContext->result = HksAnonAttestKeyOffline(
                napiContext->keyAlias, napiContext->paramSet, napiContext->certChain);
        },
        [](napi_env env, napi_status status, void *data) {
            HKS_IF_NULL_LOGE_RETURN_VOID(data, "the received data is nullptr.")
            AttestKeyAsyncContext napiContext = static_cast<AttestKeyAsyncContext>(data);
            HksSuccessReturnResult resultData{};
            SuccessReturnResultInit(resultData);
            resultData.certChain = napiContext->certChain;
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteAttestKeyAsyncContext(env, napiContext);
        }, static_cast<void *>(context), &context->asyncWork);
    if (status != napi_ok) {
        DeleteAttestKeyAsyncContext(env, context);
        HKS_LOG_E("could not creat async work");
        return nullptr;
    }

    status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteAttestKeyAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value HuksNapiAnonAttestKeyItemOfflineAsUser(napi_env env, napi_callback_info info)
{
    AttestKeyAsyncContext context = CreateAttestKeyAsyncContext(true);
    if (context == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = AttestKeyOfflineAsUserParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }
    
    result = AttestKeyAsyncWorkOffline(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}

napi_value HuksNapiAnonAttestKeyItemOffline(napi_env env, napi_callback_info info)
{
    AttestKeyAsyncContext context = CreateAttestKeyAsyncContext(true);
    if (context == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    size_t argc = HUKS_NAPI_ATTEST_KEY_MAX_ARGS;
    napi_value argv[HUKS_NAPI_ATTEST_KEY_MAX_ARGS] = { 0 };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        HksNapiThrow(env, HUKS_ERR_CODE_EXTERNAL_ERROR, "bad env");
        DeleteAttestKeyAsyncContext(env, context);
        HKS_LOG_E("parase env fail!");
        return nullptr;
    }

    if (argc < HUKS_NAPI_ATTEST_KEY_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAlias(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get key alias");
        HKS_LOG_E("could not get alias");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }

    index++;
    result = ParseHuksParams(env, argv[index], {}, context->paramSet);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_INVALID_ARGUMENT, "could not get paramset");
        HKS_LOG_E("could not get paramset");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }

    result = AttestKeyAsyncWorkOffline(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}