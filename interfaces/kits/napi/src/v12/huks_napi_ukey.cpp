#include "huks_napi_ukey.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_TWO_ARGS = 2;
napi_value ParseStringAndHksParamSet(napi_env env, napi_value *argv, size_t &index,
    HksBlob *&Name, HksParamSet *&paramSet)
{
    // 复用huks解析string和paramSet的方法
    return ParseKeyAliasAndHksParamSet(env, argv, index, Name, paramSet);
}

static napi_value ParseTwoArgsStringParamSetAndCallback(napi_env env, napi_callback_info info,
    HksBlob *&blobOut, HksParamSet *&paramSetOut, napi_ref &callbackRef)
{
    size_t argc = HUKS_NAPI_TWO_ARGS;
    napi_value argv[HUKS_NAPI_TWO_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_TWO_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseStringAndHksParamSet(env, argv, index, blobOut, paramSetOut);
    if (result == nullptr) {
        HKS_LOG_E("ParseTwoArgs failed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        callbackRef = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
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
    auto context = std::unique_ptr<RegisterAndUngisterProviderContext>(new (std::nothrow)RegisterAndUngisterProviderContext());

    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        RegisterAndUngisterProviderContext *asyncContext = reinterpret_cast<RegisterAndUngisterProviderContext *>(context);
        napi_value result = ParseTwoArgsStringParamSetAndCallback(env, info, asyncContext->name, context->paramSetIn, context->callback);
        if (result == nullptr) {
            HKS_LOG_E("generateKey parse params failed");
            return napi_generic_failure;
        }
        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        RegisterAndUngisterProviderContext *napiContext = static_cast<RegisterAndUngisterProviderContext *>(data);
        napiContext->result = RegisterProvider(napiContext->name, napiContext->paramSetIn);
    };

    context->resolve = [](napi_env env, AsyncContext *context) {
        RegisterAndUngisterProviderContext *napiContext = static_cast<RegisterAndUngisterProviderContext *>(context);
        HksSuccessReturnResult resultData;
        SuccessReturnResultInit(resultData);
        HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
    };

    napi_value result = CreateAsyncWork(env, info, std::move(context), __func__);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
    }
    return result;
}

napi_value HuksNapiUnregisterProvider(napi_env env, napi_callback_info info)
{
    auto context = std::unique_ptr<RegisterAndUngisterProviderContext>(new (std::nothrow)RegisterAndUngisterProviderContext());

    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    context->parse = [](napi_env env, napi_callback_info info, AsyncContext *context) -> napi_status {
        RegisterAndUngisterProviderContext *asyncContext = reinterpret_cast<RegisterAndUngisterProviderContext *>(context);
        napi_value result = ParseTwoArgsStringParamSetAndCallback(env, info, asyncContext->name, context->paramSetIn, context->callback);
        if (result == nullptr) {
            HKS_LOG_E("generateKey parse params failed");
            return napi_generic_failure;
        }
        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        RegisterAndUngisterProviderContext *napiContext = static_cast<RegisterAndUngisterProviderContext *>(data);
        napiContext->result = UnRegisterProvider(napiContext->name, napiContext->paramSetIn);
    };

    context->resolve = [](napi_env env, AsyncContext *context) {
        RegisterAndUngisterProviderContext *napiContext = static_cast<RegisterAndUngisterProviderContext *>(context);
        HksSuccessReturnResult resultData;
        SuccessReturnResultInit(resultData);
        HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
    };

    napi_value result = CreateAsyncWork(env, info, std::move(context), __func__);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
    }
    return result;
}

napi_value HuksNapiVerifyPin(napi_env env, napi_callback_info info)
{
    auto context = std::unique_ptr<VerifyPinAsyncContext>(new (std::nothrow) VerifyPinAsyncContext());
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

        napi_value result = ParseString(env, argv[0], asyncContext->index);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure, 
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get stringname");

        result = ParseGetHksParamSet(env, argv[1], context->paramSetIn);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure, 
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramSet");

        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(data);
        napiContext->result = AuthUkeyPin(napiContext->index, napiContext->paramSetIn);
    };

    context->resolve = [](napi_env env, AsyncContext *context) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(context);
        HksSuccessReturnResult resultData;
        SuccessReturnResultInit(resultData);
        HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
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
        result = ParseGetHksParamSet(env, argv[1], context->paramSetIn);
        NAPI_THROW_RETURN_ERR(env, result == nullptr, napi_generic_failure, 
                              HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramSet");

        return napi_ok;
    };

    context->execute = [](napi_env env, void *data) {
        UkeyPinContext *napiContext = static_cast<UkeyPinContext *>(data);
        napiContext->result = GetUkeyPinAuthState(napiContext->index, napiContext->paramSetIn);
    };

    context->resolve = [](napi_env env, AsyncContext *context) {
        VerifyPinAsyncContext *napiContext = static_cast<VerifyPinAsyncContext *>(context);
        HksSuccessReturnResult resultData;
        SuccessReturnResultInit(resultData);
        HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
    };

    napi_value result = CreateAsyncWork(env, info, std::move(context), __func__);
    if (result == nullptr) {
        HKS_LOG_E("could not do async work");
    }
    return result;
}

}  // namespace HuksNapiItem