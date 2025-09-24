#include "ukey/huks_napi_ukey.h"
#include "hks_tag.h"

using namespace HuksNapiItem;

extern "C" {

static napi_value CreateByte(napi_env env, int32_t value)
{
    napi_value napiValue{};
    NAPI_CALL(env, napi_create_object(env, &napiValue));

    return napiValue;
}

static napi_value HuksExternalCryptoRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor propDesc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_DEVICE", CreateByte(env, HKS_TAG_REMOTE_DEVICE)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_APP", CreateByte(env, HKS_TAG_REMOTE_APP)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_CONTAINER", CreateByte(env, HKS_TAG_REMOTE_CONTAINER)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_PIN", CreateByte(env, HKS_TAG_PIN)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_ABILITY_NAME", CreateByte(env, HKS_TAG_ABILITY_NAME)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_REMOTE_ABILITY_SN", CreateByte(env, HKS_TAG_REMOTE_ABILITY_SN)),
        DECLARE_NAPI_STATIC_PROPERTY("HUKS_TAG_EXTRA_DATA", CreateByte(env, HKS_TAG_EXTRA_DATA)),

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
    .nm_modname = "security.huks.external_crypto",
    .nm_priv = nullptr,
    .reserved = { 0 },
};

__attribute__((constructor)) void RegisterExternalCryptoModule(void)
{
    napi_module_register(&g_externalCryptoModule);
}
}
