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

#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "cipher.h"
#include "cipher_log.h"
#include "securec.h"

namespace OHOS::Ace::Napi {
namespace {
}

struct CallbackContext {
    napi_ref callbackSuccess = nullptr;
    napi_ref callbackFail = nullptr;
    napi_ref callbackComplete = nullptr;
};

struct CommonNapiValue {
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_value action_napi = nullptr;
    napi_value text_napi = nullptr;
    napi_value key_napi = nullptr;
    napi_value transformation_napi = nullptr;
};

struct RsaAsyncContext {
    CommonNapiValue *commonNapi = nullptr;
    CallbackContext *callback = nullptr;
    RsaKeyData *rsaKey = nullptr;
    RsaData *textIn = nullptr;
    RsaData *textOut = nullptr;
};

struct AesAsyncContext {
    CommonNapiValue *commonNapi = nullptr;
    napi_value iv_napi = nullptr;
    napi_value ivOffset_napi = nullptr;
    napi_value ivLen_napi = nullptr;
    CallbackContext *callback = nullptr;
    AesCryptContext *aes = nullptr;
    AesIvMode *iv = nullptr;
    char *key = nullptr;
    char *textIn = nullptr;
    char *action = nullptr;
};

static const char FAIL_CODE[] = "System error";
static int g_ret = 0;

static void GetString(napi_env env, napi_value object, char **element, size_t *len)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_string) {
        napi_get_value_string_utf8(env, object, nullptr, 0, len);
        *element = (char *)malloc(*len);
        napi_get_value_string_utf8(env, object, *element, *len, len);
    } else {
        *element = nullptr;
    }
}

static void GetInt32(napi_env env, napi_value object, int32_t *len)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, object, len);
    } else {
        *len = 0;
    }
}

static void ReadAesData(napi_env env, AesAsyncContext *context)
{
    context->aes = (AesCryptContext *)malloc(sizeof(AesCryptContext));
    context->aes->mode = CIPHER_AES_ECB;
    context->iv = (AesIvMode *)malloc(sizeof(AesIvMode));

    // get action
    size_t len = 0;
    GetString(env, context->commonNapi->action_napi, &context->action, &len);
    CIPHER_LOG_E("chenhao action is %s", context->action);

    // get text
    len = 0;
    GetString(env, context->commonNapi->text_napi, &context->textIn, &len);
    CIPHER_LOG_E("chenhao textIn is %s", context->textIn);

    // get key
    len = 0;
    GetString(env, context->commonNapi->key_napi, &context->key, &len);
    CIPHER_LOG_E("chenhao key is %s", context->key);

    // get trans
    len = 0;
    GetString(env, context->commonNapi->transformation_napi, &context->iv->transformation, &len);
    CIPHER_LOG_E("chenhao trans is %s", context->iv->transformation);

    GetInt32(env, context->ivLen_napi, &context->iv->ivLen);
    len = 0;
    GetString(env, context->iv_napi, &context->iv->ivBuf, &len);
    GetInt32(env, context->ivOffset_napi, &context->iv->ivOffset);
}

static void GetAesInput(napi_env env, napi_value object, AesAsyncContext *context)
{
    CIPHER_LOG_E("chenhao enter GetInput");
    napi_value successFunc = nullptr;
    napi_value failFunc = nullptr;
    napi_value completeFunc = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_object) {
        napi_get_named_property(env, object, "action", &context->commonNapi->action_napi);
        
        napi_get_named_property(env, object, "text", &context->commonNapi->text_napi);
        napi_get_named_property(env, object, "key", &context->commonNapi->key_napi);
        napi_get_named_property(env, object, "transformation", &context->commonNapi->transformation_napi);
        napi_get_named_property(env, object, "iv", &context->iv_napi);
        napi_get_named_property(env, object, "ivOffset", &context->ivOffset_napi);
        napi_get_named_property(env, object, "ivLen", &context->ivLen_napi);
        napi_get_named_property(env, object, "success", &successFunc);
        napi_get_named_property(env, object, "fail", &failFunc);
        napi_get_named_property(env, object, "complete", &completeFunc);
    }

    //create async function
    napi_typeof(env, successFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, successFunc, 1, &context->callback->callbackSuccess);
    }

    napi_typeof(env, failFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, failFunc, 1, &context->callback->callbackFail);
    }
    napi_typeof(env, completeFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, completeFunc, 1, &context->callback->callbackComplete);
    }

    ReadAesData(env, context);
}

static int32_t AesExcute(AesAsyncContext *asyncContext)
{
    int ret = InitAesCryptData(asyncContext->action, asyncContext->textIn, asyncContext->key,
        asyncContext->iv, asyncContext->aes);
    if (ret != ERROR_SUCCESS) {
        CIPHER_LOG_E("InitAesCryptData fail, ret is %d", ret);
        return ret;
    }

    ret = AesCrypt(asyncContext->aes);
    if (ret != ERROR_SUCCESS) {
        CIPHER_LOG_E("AesCrypt fail, ret is %d", ret);
    }
    return ret;

}

static void ReadRsaData(napi_env env, RsaAsyncContext *context)
{
    context->rsaKey = (RsaKeyData *)malloc(sizeof(RsaKeyData));
    context->rsaKey->trans = nullptr;
    context->textIn = (RsaData *)malloc(sizeof(RsaData));
    context->textOut = (RsaData *)malloc(sizeof(RsaData));
    context->textOut->data = nullptr;
    context->textOut->length = 0;

    // get action
    size_t len = 0;
    GetString(env, context->commonNapi->action_napi, &context->rsaKey->action, &len);
    CIPHER_LOG_E("chenhao action is %s", context->rsaKey->action);

    // get text
    GetString(env, context->commonNapi->text_napi, &context->textIn->data, &context->textIn->length);
    CIPHER_LOG_E("chenhao textIn is %s", context->textIn->data);

    // get key
    GetString(env, context->commonNapi->key_napi, &context->rsaKey->key, &context->rsaKey->keyLen);
    CIPHER_LOG_E("chenhao key is %s", context->rsaKey->key);

    // get trans
    len = 0;
    GetString(env, context->commonNapi->transformation_napi, &context->rsaKey->trans, &len);
    CIPHER_LOG_E("chenhao trans is %s", context->rsaKey->trans);
}

static void GetRsaInput(napi_env env, napi_value object, RsaAsyncContext *context)
{
    CIPHER_LOG_E("chenhao enter GetInput");
    napi_value successFunc = nullptr;
    napi_value failFunc = nullptr;
    napi_value completeFunc = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_object) {
        napi_get_named_property(env, object, "action", &context->commonNapi->action_napi);
        
        napi_get_named_property(env, object, "text", &context->commonNapi->text_napi);
        napi_get_named_property(env, object, "key", &context->commonNapi->key_napi);
        napi_get_named_property(env, object, "transformation", &context->commonNapi->transformation_napi);
        napi_get_named_property(env, object, "success", &successFunc);
        napi_get_named_property(env, object, "fail", &failFunc);
        napi_get_named_property(env, object, "complete", &completeFunc);
    }

    //create async function
    napi_typeof(env, successFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, successFunc, 1, &context->callback->callbackSuccess);
    }

    napi_typeof(env, failFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, failFunc, 1, &context->callback->callbackFail);
    }
    napi_typeof(env, completeFunc, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, completeFunc, 1, &context->callback->callbackComplete);
    }

    ReadRsaData(env, context);
}

static int32_t RsaExcute(RsaAsyncContext *asyncContext)
{
    if ((asyncContext->rsaKey->key == nullptr) || (asyncContext->textIn->data == nullptr)) {
        CIPHER_LOG_E("chenhao g_ret here 1");
        return -1;
    }

    int32_t ret = RsaCrypt(asyncContext->rsaKey, asyncContext->textIn, asyncContext->textOut);
    if ((ret != ERROR_SUCCESS) || (asyncContext->textOut->length == 0)) {
        CIPHER_LOG_E("chenhao ret here 2, ret is %d", ret);
        return -1;
    }

    asyncContext->textOut->data = (char *)malloc(asyncContext->textOut->length);
    if (asyncContext->textOut->data == nullptr) {
        return -1;
    }
    ret = memset_s(asyncContext->textOut->data, asyncContext->textOut->length, 0, asyncContext->textOut->length);
    if (ret) {
        return ret;
    }

    ret = RsaCrypt(asyncContext->rsaKey, asyncContext->textIn, asyncContext->textOut);
    if (ret != ERROR_SUCCESS) {
        return ret;
    }
    CIPHER_LOG_E("asyncContext->textOut->data is %s", asyncContext->textOut->data);
    return ret;
}

void SetComplete(napi_env env, CallbackContext *asyncContext)
{
    napi_value callback = nullptr;
    napi_value ret;
    napi_call_function(env, nullptr, callback, 1, nullptr, &ret);
    napi_delete_reference(env, asyncContext->callbackComplete); 
}

void SetSuccess(napi_env env, char *textOut, size_t textLength, CallbackContext *asyncContext)
{
    napi_value callback = nullptr;
    napi_value ret;

    napi_value result = nullptr;
    napi_value returnObj = nullptr;
    napi_create_object(env, &returnObj);
    napi_create_string_utf8(env, textOut, textLength, &result);
    napi_set_named_property(env, returnObj, "text", result);

    napi_value successObj = nullptr;
    napi_create_object(env, &successObj);
    napi_set_named_property(env, successObj, "data", returnObj);

    napi_get_reference_value(env, asyncContext->callbackSuccess, &callback);
    napi_call_function(env, nullptr, callback, 1, &successObj, &ret);
    napi_delete_reference(env, asyncContext->callbackSuccess); 
}

void SetFail(napi_env env, CallbackContext *asyncContext)
{
    napi_value callback = nullptr;
    napi_value ret;

    napi_value result = nullptr;
    napi_value returnData = nullptr;
    napi_create_object(env, &returnData);
    napi_create_string_utf8(env, FAIL_CODE, sizeof(FAIL_CODE), &result);
    napi_set_named_property(env, returnData, "data", result);

    napi_value errorCode = nullptr;
    napi_value returnCode = nullptr;
    napi_create_object(env, &returnCode);
    napi_create_int32(env, 200, &errorCode);
    napi_set_named_property(env, returnCode, "code", errorCode);
    
    napi_value params[2] = { returnData, returnCode };
    napi_get_reference_value(env, asyncContext->callbackFail, &callback);
    napi_call_function(env, nullptr, callback, 2, params, &ret);
    napi_delete_reference(env, asyncContext->callbackFail); 
}

static napi_value JSCipherRsa(napi_env env, napi_callback_info info)
{
    CIPHER_LOG_E("chenhao enter JSCipherRsacute");
    size_t argc = 1;
    napi_value argv[1] = {0};
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    auto rsaAsyncContext = new RsaAsyncContext();

    GetRsaInput(env, argv[0], rsaAsyncContext);

    //excute async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JSCipherRsa", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            RsaAsyncContext *asyncContext = (RsaAsyncContext *)data;
            g_ret = RsaExcute(asyncContext);
        },

        [](napi_env env, napi_status status, void *data) {
            RsaAsyncContext *asyncContext = (RsaAsyncContext *)data;
            if (g_ret != ERROR_SUCCESS){
                SetFail(env, asyncContext->callback);
                SetComplete(env, asyncContext->callback);
            } else {
                SetSuccess(env, asyncContext->textOut->data, asyncContext->textOut->length, asyncContext->callback);
                SetComplete(env, asyncContext->callback);
            }
            napi_delete_async_work(env, asyncContext->commonNapi->work);
            delete asyncContext;
        },
        (void *)rsaAsyncContext,
        &rsaAsyncContext->commonNapi->work);
        napi_queue_async_work(env, rsaAsyncContext->commonNapi->work);
        return nullptr;
}

static napi_value JSCipherAes(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    auto aesAsyncContext = new AesAsyncContext();

    GetAesInput(env, argv[0], aesAsyncContext);

    //excute async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JSCipherAes", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            AesAsyncContext *asyncContext = (AesAsyncContext *)data;
            g_ret = AesExcute(asyncContext);
        },

        [](napi_env env, napi_status status, void *data) {
            AesAsyncContext *asyncContext = (AesAsyncContext *)data;
            if (g_ret != ERROR_SUCCESS){
                SetFail(env, asyncContext->callback);
                SetComplete(env, asyncContext->callback);
            } else {
                SetSuccess(env, asyncContext->aes->data.text, (size_t)asyncContext->aes->data.textLen,
                    asyncContext->callback);
                SetComplete(env, asyncContext->callback);
            }
            napi_delete_async_work(env, asyncContext->commonNapi->work);
            delete asyncContext;
        },
        (void *)aesAsyncContext,
        &aesAsyncContext->commonNapi->work);
        napi_queue_async_work(env, aesAsyncContext->commonNapi->work);
        return nullptr;
}


static napi_value CipherExport(napi_env env, napi_value exports)
{
    static napi_property_descriptor cipherDesc[] = {
        DECLARE_NAPI_FUNCTION("aes", JSCipherAes),
        DECLARE_NAPI_FUNCTION("rsa", JSCipherRsa),
    };
    NAPI_CALL(env, napi_define_properties(
        env, exports, sizeof(cipherDesc) / sizeof(cipherDesc[0]), cipherDesc));
    return exports;
}

static napi_module CipherModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = CipherExport,
    .nm_modname = "cipher",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void CipherRegister()
{
    napi_module_register(&CipherModule);
}
}
