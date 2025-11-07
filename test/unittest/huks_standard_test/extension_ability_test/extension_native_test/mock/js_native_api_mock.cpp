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

#include "assistant.h"
#include "uv.h"

napi_status napi_get_uv_event_loop(napi_env env, struct uv_loop_s** loop)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_uv_event_loop(env, loop);
}

napi_status napi_call_function(napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value* argv,
    napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_call_function(env, recv, func, argc, argv, result);
}

napi_status napi_get_reference_value(napi_env env, napi_ref ref, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_reference_value(env, ref, result);
}

napi_status napi_get_named_property(napi_env env, napi_value object, const char* utf8name, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_named_property(env, object, utf8name, result);
}

napi_status napi_get_value_int32(napi_env env, napi_value value, int32_t* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_value_int32(env, value, result);
}

napi_status napi_get_value_int64(napi_env env, napi_value value, int64_t* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_value_int64(env, value, result);
}

napi_status napi_create_string_utf8(napi_env env, const char* str, size_t length, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_string_utf8(env, str, length, result);
}

napi_status napi_create_int32(napi_env env, int32_t value, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_int32(env, value, result);
}

napi_status napi_create_uint32(napi_env env, uint32_t value, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_uint32(env, value, result);
}

napi_status napi_create_int64(napi_env env, int64_t value, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_int64(env, value, result);
}

napi_status napi_get_value_string_utf8(napi_env env, napi_value value, char* buf, size_t bufsize, size_t* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_value_string_utf8(env, value, buf, bufsize, result);
}

napi_status napi_get_boolean(napi_env env, bool value, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_boolean(env, value, result);
}

napi_status napi_create_array(napi_env env, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_array(env, result);
}

napi_status napi_get_array_length(napi_env env, napi_value value, uint32_t* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_array_length(env, value, result);
}

napi_status napi_get_element(napi_env env, napi_value object, uint32_t index, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_element(env, object, index, result);
}

napi_status napi_escape_handle(napi_env env, napi_escapable_handle_scope scope, napi_value escapee, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_escape_handle(env, scope, escapee, result);
}

napi_status napi_get_null(napi_env env, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_null(env, result);
}

napi_status napi_create_object(napi_env env, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_object(env, result);
}

napi_status napi_create_array_with_length(napi_env env, size_t length, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_array_with_length(env, length, result);
}

napi_status napi_create_double(napi_env env, double value, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_double(env, value, result);
}

napi_status napi_set_named_property(napi_env env, napi_value object, const char* utf8Name, napi_value value)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_set_named_property(env, object, utf8Name, value);
}

napi_status napi_create_function(napi_env env, const char* utf8name, size_t length, napi_callback cb, void* data,
    napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_function(env, utf8name, length, cb, data, result);
}

napi_status napi_get_cb_info(napi_env env, napi_callback_info cbinfo, size_t* argc, napi_value* argv,
    napi_value* thisArg, void** data)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_cb_info(env, cbinfo, argc, argv, thisArg, data);
}

napi_status napi_get_undefined(napi_env env, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_undefined(env, result);
}

napi_status napi_get_value_bool(napi_env env, napi_value value, bool* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_value_bool(env, value, result);
}

napi_status napi_send_event(napi_env env, const std::function<void()>& cb, napi_event_priority priority,
    const char* name)
{
    if (cb) {
        cb();
    }
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_send_event(env, cb, priority);
}

napi_status napi_create_arraybuffer(napi_env env, size_t byte_length, void** data, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_arraybuffer(env, byte_length, data, result);
}

napi_status napi_create_typedarray(napi_env env, napi_typedarray_type type,
    size_t length, napi_value arraybuffer, size_t byte_offset, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_typedarray(
        env, type, length, arraybuffer, byte_offset, result);
}

napi_status napi_create_bigint_uint64(napi_env env, uint64_t value, napi_value* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_create_bigint_uint64(env, value, result);
}

napi_status napi_set_element(napi_env env, napi_value object, uint32_t index, napi_value value)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_set_element(env, object, index, value);
}

napi_status napi_get_arraybuffer_info(
    napi_env env, napi_value arraybuffer, void** data, size_t* byte_length)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_arraybuffer_info(env, arraybuffer, data, byte_length);
}

napi_status napi_get_typedarray_info(napi_env env, napi_value typedarray,
    napi_typedarray_type* type, size_t* length, void** data, napi_value* arraybuffer, size_t* byte_offset)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_typedarray_info(env, typedarray,
        type, length, data, arraybuffer, byte_offset);
}

napi_status napi_get_value_uint32(napi_env env, napi_value value, uint32_t* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_value_uint32(env, value, result);
}

napi_status napi_get_value_bigint_uint64(napi_env env, napi_value value, uint64_t* result, bool* lossless)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_get_value_bigint_uint64(env, value, result, lossless);
}

napi_status napi_is_callable(napi_env env, napi_value value, bool* result)
{
    if (OHOS::Security::Huks::Assistant::ins_ == nullptr) {
        return napi_invalid_arg;
    }
    return OHOS::Security::Huks::Assistant::ins_->napi_is_callable(env, value, result);
}
