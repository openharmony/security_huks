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

napi_value ParseHksBlob(napi_env env, napi_value object, HksBlob *&str)
{
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));
    NAPI_THROW(env, valueType != napi_valuetype::napi_string, 
               HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "invalid type, expect string");

    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, object, nullptr, 0, &length);

    NAPI_THROW(env, status != napi_ok, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get string length");
    NAPI_THROW(env, length > HKS_MAX_DATA_LEN, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the length of str is too long");

    char *data = static_cast<char *>(HksMalloc(length + 1));
    NAPI_THROW(env, data == nullptr, HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not alloc memory");

    (void)memset_s(data, length + 1, 0, length + 1);
    size_t result = 0;
    status = napi_get_value_string_utf8(env, object, data, length + 1, &result);
    if (status != napi_ok) {
        HKS_FREE(data);
        NAPI_THROW(env, true, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get string");
    }

    str = static_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (str == nullptr) {
        HKS_FREE(data);
        NAPI_THROW(env, true, HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not alloc memory");
    }
    str->data = reinterpret_cast<uint8_t *>(data);
    str->size = static_cast<uint32_t>(length & UINT32_MAX);

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


static napi_value CreateAsyncWork(napi_env env, napi_callback_info info, std::unique_ptr<AsyncContext> context, const char *resource)
{
    if(context->parse != nullptr) {
        NAPI_CALL(env, context->parse(env, info, context.get()));
    }
    
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, resource, NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
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

    context->env = env;
    napi_status status = napi_queue_async_work(env, context->asyncWork);

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
    auto context = std::unique_ptr<ProviderRegContext>(new (std::nothrow)ProviderRegContext());

    NAPI_THROW(env, context == nullptr, HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "could not create context");

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        ProviderRegContext *asyncContext = reinterpret_cast<ProviderRegContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
        
        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_ONE_ARG, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseHksBlob(env, argv[0], asyncContext->name);
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
        napiContext->result = HksRegisterProvider(napiContext->name, napiContext->paramSetIn);
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
    auto context = std::unique_ptr<ProviderRegContext>(new (std::nothrow)ProviderRegContext());

    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        ProviderRegContext *asyncContext = reinterpret_cast<ProviderRegContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
        
        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_ONE_ARG, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseHksBlob(env, argv[0], asyncContext->name);
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
        napiContext->result = HksUnregisterProvider(napiContext->name, napiContext->paramSetIn);
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
    auto context = std::unique_ptr<UkeyPinContext>(new (std::nothrow)UkeyPinContext());

    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        UkeyPinContext *asyncContext = reinterpret_cast<UkeyPinContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
        
        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_TWO_ARGS, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseHksBlob(env, argv[0], asyncContext->index);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure, 
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get stringname");

        result = ParseHksCryptoExternalParams(env, argv[1], context->paramSetIn);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure, 
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramSet");

        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(data);
        napiContext->result = HksAuthUkeyPin(napiContext->index, napiContext->paramSetIn, &napiContext->retryCount);
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
    auto context = std::unique_ptr<UkeyPinContext>(new (std::nothrow)UkeyPinContext());

    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        UkeyPinContext *asyncContext = reinterpret_cast<UkeyPinContext *>(context);
        size_t argc = HUKS_NAPI_TWO_ARGS;
        napi_value argv[HUKS_NAPI_TWO_ARGS] = { nullptr };
        NAPI_CALL_RETURN_ERR(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
        
        NAPI_THROW_RETURN_ERR(env, argc < HUKS_NAPI_ONE_ARG, napi_generic_failure,
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");

        napi_value result = ParseHksBlob(env, argv[0], asyncContext->index);
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
        napiContext->result = HksGetUkeyPinAuthState(napiContext->index, napiContext->paramSetIn, &napiContext->outStatus);
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
