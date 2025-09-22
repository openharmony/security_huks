#include "ukey/huks_napi_ukey.h"

using namespace HuksNapiItem;

extern "C" {
static napi_value HuksExternalCryptoRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor funcDesc[] = {
        DECLARE_NAPI_FUNCTION("registerProvider", HuksNapiRegisterProvider),
        DECLARE_NAPI_FUNCTION("unregisterProvider", HuksNapiUnregisterProvider),
        DECLARE_NAPI_FUNCTION("authUkeyPin", HuksNapiAuthUkeyPin),
        DECLARE_NAPI_FUNCTION("getUkeyPinAuthState", HuksNapiGetUkeyPinAuthState),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(funcDesc) / sizeof(funcDesc[0]), funcDesc));
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
