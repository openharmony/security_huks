/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_permission_check.h"

#ifdef L2_STANDARD
#ifdef HKS_SUPPORT_ACCESS_TOKEN
#include <cinttypes>
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "hks_base_check.h"
#include "hks_log.h"
#include "hks_template.h"
#endif
#endif

#include "hks_param.h"
#include <stdint.h>

#ifdef L2_STANDARD
#ifdef HKS_SUPPORT_ACCESS_TOKEN
using namespace OHOS;
int32_t SensitivePermissionCheck(const char *permission)
{
    OHOS::Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    int result = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permission);
    if (result == OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        HKS_LOG_I("Check Permission success!");
        return HKS_SUCCESS;
    } else {
        HKS_LOG_E("Check Permission failed!%" LOG_PUBLIC "s", permission);
        return HKS_ERROR_NO_PERMISSION;
    }
}

namespace {
static int32_t CheckTokenType(void)
{
    auto accessTokenIDEx = IPCSkeleton::GetCallingFullTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(
        static_cast<OHOS::Security::AccessToken::AccessTokenID>(accessTokenIDEx));
    switch (tokenType) {
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE:
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL:
            return HKS_SUCCESS;
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_HAP:
            if (!OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx)) {
                HKS_LOG_E("not system hap, check permission failed, accessTokenIDEx %" LOG_PUBLIC PRIu64,
                    accessTokenIDEx);
                return HKS_ERROR_NOT_SYSTEM_APP;
            } else {
                return HKS_SUCCESS;
            }
        default:
            HKS_LOG_E("unknown tokenid, accessTokenIDEx %" LOG_PUBLIC PRIu64, accessTokenIDEx);
            return HKS_ERROR_INVALID_ACCESS_TYPE;
    }
}
}

int32_t SystemApiPermissionCheck(int callerUserId)
{
    int32_t ret = CheckTokenType();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "CheckTokenType fail %" LOG_PUBLIC "d", ret)
    if (callerUserId < 0 || callerUserId >= HKS_ROOT_USER_UPPERBOUND) {
        HKS_LOG_E("invalid callerUserId %" LOG_PUBLIC "d", callerUserId);
        return HKS_ERROR_NO_PERMISSION;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckAcrossAccountsPermission(const struct HksParamSet *paramSet, int32_t callerUserId)
{
    struct HksParam *specificUserId = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &specificUserId);
    if (ret == HKS_SUCCESS) {
        ret = SystemApiPermissionCheck(callerUserId);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check systemapi permission failed");
        ret = SensitivePermissionCheck("ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS");
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check interact across local accounts permission failed")
    } else if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        return HKS_SUCCESS;
    }
    return ret;
}
#endif
#else
int32_t HksCheckAcrossAccountsPermission(const struct HksParamSet *paramSet, int32_t callerUserId)
{
    (void)paramSet;
    (void)callerUserId;
    return HKS_SUCCESS;
}
#endif  // L2_STANDARD
