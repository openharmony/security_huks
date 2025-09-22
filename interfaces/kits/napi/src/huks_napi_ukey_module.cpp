#include "ukey/huks_napi_ukey.h"
#include "hks_tag.h"

using namespace HuksNapiItem;

// Keep style consistent with main huks_napi.cpp
namespace {
inline void AddInt32Property(napi_env env, napi_value object, const char *name, int32_t value)
{
    napi_value property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, value, &property));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name, property));
}

static napi_value CreateExtensionAbilityTag(napi_env env)
{
    napi_value tag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &tag));
    /* ExtensionAbility TAG: 300001 - 300100 */
    AddInt32Property(env, tag, "HUKS_TAG_REMOTE_DEVICE", HKS_TAG_REMOTE_DEVICE);
    AddInt32Property(env, tag, "HUKS_TAG_REMOTE_APP", HKS_TAG_REMOTE_APP);
    AddInt32Property(env, tag, "HUKS_TAG_REMOTE_CONTAINER", HKS_TAG_REMOTE_CONTAINER);
    AddInt32Property(env, tag, "HUKS_TAG_PIN", HKS_TAG_PIN);
    AddInt32Property(env, tag, "HUKS_TAG_ABILITY_NAME", HKS_TAG_ABILITY_NAME);
    AddInt32Property(env, tag, "HUKS_TAG_REMOTE_ABILITY_SN", HKS_TAG_REMOTE_ABILITY_SN);
    AddInt32Property(env, tag, "HUKS_TAG_EXTRA_DATA", HKS_TAG_EXTRA_DATA);
    return tag;
}
} // anonymous namespace

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

    napi_value extTag = CreateExtensionAbilityTag(env);
    NAPI_CALL(env, napi_set_named_property(env, exports, "ExtensionAbilityTag", extTag));
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
