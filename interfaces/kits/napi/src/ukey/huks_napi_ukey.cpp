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

#include "huks_napi_ukey.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
namespace {
    constexpr int HKS_MAX_DATA_LEN = 0x6400000; // The maximum length is 100M
    constexpr int HUKS_NAPI_ONE_ARG = 1;
    constexpr int HUKS_NAPI_TWO_ARGS = 2;
}  // namespace

napi_value NapiCreateError(napi_env env, int32_t errCode, const char *errMsg)
{
    napi_value code = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &code));

    napi_value msg = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errMsg, strlen(errMsg), &msg));

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_error(env, code, msg, &result));

    return result;
}

// Helper: build a temporary HksBlob that references vector data (no allocation) and call HKS API
static int32_t CallHksRegisterProvider(const std::vector<uint8_t> &name, struct HksParamSet *paramSetIn)
{
    struct HksBlob nameBlob;
    nameBlob.size = 0;
    nameBlob.data = nullptr;
    if (!name.empty()) {
        nameBlob.size = static_cast<uint32_t>(name.size());
        nameBlob.data = const_cast<uint8_t *>(name.data());
    }
    return HksRegisterProvider(&nameBlob, paramSetIn);
}

static int32_t CallHksUnregisterProvider(const std::vector<uint8_t> &name, struct HksParamSet *paramSetIn)
{
    struct HksBlob nameBlob;
    nameBlob.size = 0;
    nameBlob.data = nullptr;
    if (!name.empty()) {
        nameBlob.size = static_cast<uint32_t>(name.size());
        nameBlob.data = const_cast<uint8_t *>(name.data());
    }
    return HksUnregisterProvider(&nameBlob, paramSetIn);
}

static int32_t CallHksAuthUkeyPin(const std::vector<uint8_t> &index, struct HksParamSet *paramSetIn,
    uint32_t *retryCount)
{
    struct HksBlob indexBlob;
    indexBlob.size = 0;
    indexBlob.data = nullptr;
    if (!index.empty()) {
        indexBlob.size = static_cast<uint32_t>(index.size());
        indexBlob.data = const_cast<uint8_t *>(index.data());
    }
    return HksAuthUkeyPin(&indexBlob, paramSetIn, retryCount);
}

static int32_t CallHksGetUkeyPinAuthState(const std::vector<uint8_t> &index, struct HksParamSet *paramSetIn,
    int32_t *status)
{
    struct HksBlob indexBlob;
    indexBlob.size = 0;
    indexBlob.data = nullptr;
    if (!index.empty()) {
        indexBlob.size = static_cast<uint32_t>(index.size());
        indexBlob.data = const_cast<uint8_t *>(index.data());
    }
    return HksGetUkeyPinAuthState(&indexBlob, paramSetIn, status);
}

// NOTE: ParseString fills `str` with UTF-8 bytes WITHOUT a trailing NUL.
// `str.size()` equals the byte length. Do NOT pass str.data() to APIs expecting C strings.
// Convert to std::string or append '\0' when a NUL-terminated buffer is required.
napi_value ParseString(napi_env env, napi_value object, std::vector<uint8_t> &str)
{
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));
    NAPI_THROW(env, valueType != napi_valuetype::napi_string,
               HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "invalid type, expect string");

    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, object, nullptr, 0, &length);

    NAPI_THROW(env, status != napi_ok, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get string length");
    NAPI_THROW(env, length > HKS_MAX_DATA_LEN, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the length of str is too long");

    str.resize(length + 1);
    if (length == 0) {
        str.clear();
        return GetInt32(env, 0);
    }
    
    size_t result = 0;
    status = napi_get_value_string_utf8(env, object, static_cast<char *>(static_cast<void *>(str.data())),
        length + 1, &result);
    NAPI_THROW(env, status != napi_ok, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get string");
    NAPI_THROW(env, result != length, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "string length mismatch");

    // remove '\0' added by napi_get_value_string_utf8
    str.pop_back();
    return GetInt32(env, 0);
}

napi_value ParseHksCryptoExternalParams(napi_env env, napi_value object, HksParamSet *&paramSet)
{
    if (paramSet != nullptr) {
        HKS_LOG_E("param input invalid");
        return nullptr;
    }

    std::vector<HksParam> params{};
    HksParamSet *outParamSet = nullptr;
    do {
        if (HksInitParamSet(&outParamSet) != HKS_SUCCESS) {
            napi_throw_error(env, NULL, "native error");
            HKS_LOG_E("paramset init failed");
            break;
        }

        if (ParseParams(env, object, params) == nullptr) {
            HKS_LOG_E("parse params failed");
            break;
        }

        if (!params.empty()) {
            if (HksAddParams(outParamSet, params.data(), params.size()) != HKS_SUCCESS) {
                HKS_LOG_E("add params failed");
                break;
            }
        }

        if (HksBuildParamSet(&outParamSet) != HKS_SUCCESS) {
            HKS_LOG_E("HksBuildParamSet failed");
            break;
        }

        FreeParsedParams(params);
        paramSet = outParamSet;
        return GetInt32(env, 0);
    } while (0);

    HksFreeParamSet(&outParamSet);
    FreeParsedParams(params);
    return nullptr;
}


static napi_value CreateAsyncWork(napi_env env, napi_callback_info info, std::unique_ptr<AsyncContext> context,
    const char *resource)
{
    if (context->parse != nullptr) {
        NAPI_CALL(env, context->parse(env, info, context.get()));
    }

    napi_value promise = nullptr;
    napi_status status;
    if (context->callback == nullptr) {
        status = napi_create_promise(env, &context->deferred, &promise);
        NAPI_THROW(env, status != napi_ok, HKS_ERROR_BAD_STATE, "could not create promise");
    }

    napi_value resourceName = nullptr;
    status = napi_create_string_utf8(env, resource, NAPI_AUTO_LENGTH, &resourceName);
    NAPI_THROW(env, status != napi_ok, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get string");

    status = napi_create_async_work(
        env,
        nullptr,
        resourceName,
        context->execute,
        [](napi_env env, napi_status status, void *data) {
            AsyncContext *napiContext = static_cast<AsyncContext *>(data);
            napiContext->resolve(env, napiContext);
            delete napiContext;
        },
        static_cast<void *>(context.get()),
        &context->asyncWork);
    NAPI_THROW(env, status != napi_ok, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not create async work");

    context->env = env;
    status = napi_queue_async_work(env, context->asyncWork);
    NAPI_THROW(env, status != napi_ok, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not queue async work");

    if (status != napi_ok) {
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        context.release();
        return promise;
    } else {
        context.release();
        return GetNull(env);
    }
}

napi_value HuksNapiRegisterProvider(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<ProviderRegContext>();
    NAPI_THROW(env, context == nullptr, HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not create context");

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        ProviderRegContext *asyncContext = reinterpret_cast<ProviderRegContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_TWO_ARGS, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseString(env, argv[0], asyncContext->name);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get stringname");

        result = ParseHksCryptoExternalParams(env, argv[1], context->paramSetIn);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramSet");

        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        ProviderRegContext *napiContext = static_cast<ProviderRegContext *>(data);
        napiContext->result = CallHksRegisterProvider(napiContext->name, napiContext->paramSetIn);
    };

    context->resolve = [](napi_env env, AsyncContext *context) {
        ProviderRegContext *napiContext = static_cast<ProviderRegContext *>(context);
        HksReturnNapiUndefined(env, napiContext->callback, napiContext->deferred, napiContext->result);
    };

    napi_value result = CreateAsyncWork(env, info, std::move(context), __func__);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
    }
    return result;
}

napi_value HuksNapiUnregisterProvider(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<ProviderRegContext>();
    NAPI_THROW(env, context == nullptr, HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not create context");

    // parse / execute / resolve setup
    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        ProviderRegContext *asyncContext = reinterpret_cast<ProviderRegContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_ONE_ARG, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseString(env, argv[0], asyncContext->name);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get stringname");

        if (argc < HUKS_NAPI_TWO_ARGS) {
            context->paramSetIn = static_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
            NAPI_THROW_RETURN_ERR(env, context->paramSetIn == nullptr, napi_generic_failure,
                                  HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not allocate memory for paramSetIn");

            (void)memset_s(context->paramSetIn, sizeof(HksParamSet), 0, sizeof(HksParamSet));
            context->paramSetIn->paramSetSize = 0;
            return napi_ok;
        }
        result = ParseHksCryptoExternalParams(env, argv[1], context->paramSetIn);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramSet");

        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        ProviderRegContext *napiContext = static_cast<ProviderRegContext *>(data);
        napiContext->result = CallHksUnregisterProvider(napiContext->name, napiContext->paramSetIn);
    };

    context->resolve = [](napi_env env, AsyncContext *context) {
        ProviderRegContext *napiContext = static_cast<ProviderRegContext *>(context);
        HksReturnNapiUndefined(env, napiContext->callback, napiContext->deferred, napiContext->result);
    };

    napi_value result = CreateAsyncWork(env, info, std::move(context), __func__);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
    }
    return result;
}

napi_value HuksNapiAuthUkeyPin(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<UkeyPinContext>();
    NAPI_THROW(env, context == nullptr, HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not create context");

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        UkeyPinContext *asyncContext = reinterpret_cast<UkeyPinContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_TWO_ARGS, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseString(env, argv[0], asyncContext->index);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get stringname");

        result = ParseHksCryptoExternalParams(env, argv[1], context->paramSetIn);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramSet");

        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(data);
        napiContext->result = CallHksAuthUkeyPin(napiContext->index, napiContext->paramSetIn,
            &napiContext->retryCount);
    };

    context->resolve = [](napi_env env, AsyncContext *context) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(context);
        SetRetryCount(napiContext->retryCount);
        HksReturnNapiUndefined(env, napiContext->callback, napiContext->deferred, napiContext->result);
    };

    napi_value result = CreateAsyncWork(env, info, std::move(context), __func__);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
    }
    return result;
}

napi_value HuksNapiGetUkeyPinAuthState(napi_env env, napi_callback_info info)
{
    auto context = std::make_unique<UkeyPinContext>();
    NAPI_THROW(env, context == nullptr, HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not create context");

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        UkeyPinContext *asyncContext = reinterpret_cast<UkeyPinContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_ONE_ARG, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseString(env, argv[0], asyncContext->index);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get stringname");
        if (argc < HUKS_NAPI_TWO_ARGS) {
            context->paramSetIn = static_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
            NAPI_THROW_RETURN_ERR(env, context->paramSetIn == nullptr, napi_generic_failure,
                                  HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not allocate memory for paramSetIn");
            (void)memset_s(context->paramSetIn, sizeof(HksParamSet), 0, sizeof(HksParamSet));
            context->paramSetIn->paramSetSize = 0;
            return napi_ok;
        }
        result = ParseHksCryptoExternalParams(env, argv[1], context->paramSetIn);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramSet");
        return napi_ok;
    };
    context->execute = [](napi_env env, void *data) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(data);
        napiContext->result = CallHksGetUkeyPinAuthState(napiContext->index, napiContext->paramSetIn,
            &napiContext->outStatus);
    };
    context->resolve = [](napi_env env, AsyncContext *context) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(context);
        HksSuccessReturnResult resultData;
        SuccessReturnResultInit(resultData);
        resultData.isOnlyReturnBoolResult = true;
        resultData.boolReturned = (napiContext->result == HKS_SUCCESS && napiContext->outStatus == 0);
        HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
    };
    napi_value result = CreateAsyncWork(env, info, std::move(context), __func__);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
    }
    return result;
}

}  // namespace HuksNapiItem