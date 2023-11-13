#ifndef HUKS_NAPI_ANON_ATTEST_KEY_ITEM_H
#define HUKS_NAPI_ANON_ATTEST_KEY_ITEM_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "hks_type.h"

namespace HuksNapiItem {
napi_value HuksNapiAnonAttestKeyItem(napi_env env, napi_callback_info info);
}  // namespace HuksNapiItem

#endif  // HUKS_NAPI_ANON_ATTEST_KEY_ITEM_H