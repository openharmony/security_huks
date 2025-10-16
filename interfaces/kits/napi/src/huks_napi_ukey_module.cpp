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

#include "hks_template.h"
#include "js_native_api.h"
#include "ukey/huks_napi_ukey.h"
#include "hks_tag.h"

using namespace HuksNapiItem;

extern "C" {

static napi_value CreateU32(napi_env env, uint32_t value)
{
    napi_value napiValue{};
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

inline void AddInt32Property(napi_env env, napi_value object, const char *name, int32_t value)
{
    napi_value property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, value, &property));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name, property));
}

static napi_value CreateHuksExternalTagType(napi_env env)
{
    napi_value tagType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &tagType));
    AddInt32Property(env, tagType, "HUKS_EXT_CRYPTO_TAG_TYPE_BYTES", HKS_EXT_CRYPTO_TAG_TYPE_BYTES);
    AddInt32Property(env, tagType, "HUKS_EXT_CRYPTO_TAG_TYPE_INT", HKS_EXT_CRYPTO_TAG_TYPE_INT);
    AddInt32Property(env, tagType, "HUKS_EXT_CRYPTO_TAG_TYPE_UINT", HKS_EXT_CRYPTO_TAG_TYPE_UINT);
    return tagType;
}

static napi_value CreateHuksExternalTag(napi_env env)
{
    napi_value tag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &tag));

    AddInt32Property(env, tag, "HUKS_EXT_CRYPTO_TAG_UKEY_PIN", HKS_EXT_CRYPTO_TAG_UKEY_PIN);
    AddInt32Property(env, tag, "HUKS_EXT_CRYPTO_TAG_ABILITY_NAME", HKS_EXT_CRYPTO_TAG_ABILITY_NAME);
    AddInt32Property(env, tag, "HUKS_EXT_CRYPTO_TAG_EXTRA_DATA", HKS_EXT_CRYPTO_TAG_EXTRA_DATA);
    AddInt32Property(env, tag, "HUKS_EXT_CRYPTO_TAG_UID", HKS_EXT_CRYPTO_TAG_UID);
    AddInt32Property(env, tag, "HUKS_EXT_CRYPTO_TAG_PURPOSE", HKS_EXT_CRYPTO_TAG_PURPOSE);
    AddInt32Property(env, tag, "HUKS_EXT_CRYPTO_TAG_TIMEOUT", HKS_EXT_CRYPTO_TAG_TIMEOUT);

    return tag;
}


static napi_value HuksExternalCryptoRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor propDesc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_DEVICE", CreateU32(env, HKS_TAG_REMOTE_DEVICE)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_APP", CreateU32(env, HKS_TAG_REMOTE_APP)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_CONTAINER", CreateU32(env, HKS_TAG_REMOTE_CONTAINER)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_ABILITY_SN", CreateU32(env, HKS_TAG_REMOTE_ABILITY_SN)),


        DECLARE_NAPI_PROPERTY("HuksExternalCryptoTagType", CreateHuksExternalTagType(env)),
        DECLARE_NAPI_PROPERTY("HuksExternalCryptoTag", CreateHuksExternalTag(env)),
        DECLARE_NAPI_FUNCTION("registerProvider", HuksNapiRegisterProvider),
        DECLARE_NAPI_FUNCTION("unregisterProvider", HuksNapiUnregisterProvider),
        DECLARE_NAPI_FUNCTION("authUkeyPin", HuksNapiAuthUkeyPin),
        DECLARE_NAPI_FUNCTION("getUkeyPinAuthState", HuksNapiGetUkeyPinAuthState),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, std::size(propDesc), propDesc));
    return exports;
}

static napi_module g_externalCryptoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = HuksExternalCryptoRegister,
    .nm_modname = "security.huksExternalCrypto",
    .nm_priv = nullptr,
    .reserved = { 0 },
};

__attribute__((constructor)) void RegisterExternalCryptoModule(void)
{
    napi_module_register(&g_externalCryptoModule);
}
}
