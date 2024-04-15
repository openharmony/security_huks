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

#include "hks_at_api_wrap.h"

#include <unistd.h>

#include "accesstoken_kit.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#define ACCESS_TOKEN_SA_ID 3503

using namespace OHOS;
using namespace OHOS::Security::AccessToken;

static int32_t CheckAccessTokenAvailable()
{
    sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        HKS_LOG_E("get SystemAbilityManager failed.");
        return HKS_ERROR_COMMUNICATION_FAILURE;
    }

    // retry if check system ability failed.
    do {
        sptr<IRemoteObject> sa;
        for (uint32_t i = 0; i < HKS_MAX_RETRY_TIME; ++i) {
            sa = sm->CheckSystemAbility(ACCESS_TOKEN_SA_ID);
            if (sa != nullptr) {
                break;
            }
            HKS_LOG_E("access token proxy is nullptr, retry %" LOG_PUBLIC "u", i);
            usleep(HKS_SLEEP_TIME_FOR_RETRY);
        }
        if (sa != nullptr) {
            break;
        }
        return HKS_ERROR_BAD_STATE;
    } while (false);
    return HKS_SUCCESS;
}

int32_t HksGetAtType(uint64_t accessTokenId, enum HksAtType *atType)
{
    if (CheckAccessTokenAvailable() != HKS_SUCCESS) {
        HKS_LOG_E("access token sa is unavailable.");
        return HKS_ERROR_BAD_STATE;
    }

    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag((uint32_t)accessTokenId);
    switch (type) {
        case ATokenTypeEnum::TOKEN_HAP:
            *atType = HKS_TOKEN_HAP;
            break;
        case ATokenTypeEnum::TOKEN_NATIVE:
            *atType = HKS_TOKEN_NATIVE;
            break;
        case ATokenTypeEnum::TOKEN_SHELL:
            *atType = HKS_TOKEN_SHELL;
            break;
        default:
            HKS_LOG_E("Get access token type unexpectly error, access token type is %" LOG_PUBLIC "d.", type);
            return HKS_ERROR_INVALID_KEY_FILE;
    }
    return HKS_SUCCESS;
}

int32_t HksGetHapNameFromAccessToken(int32_t tokenId, char *hapName, int32_t hapNameSize)
{
    if (CheckAccessTokenAvailable() != HKS_SUCCESS) {
        HKS_LOG_E("access token sa is unavailable.");
        return HKS_ERROR_BAD_STATE;
    }
    HapTokenInfo tokenInfo;
    int result = AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo);
    if (result != HKS_SUCCESS) {
        HKS_LOG_I("GetHapTokenInfo failed, tokenId :%" LOG_PUBLIC "d", tokenId);
        return HKS_ERROR_BAD_STATE;
    }

    uint32_t hapNameLen = strlen(tokenInfo.bundleName.c_str());
    if (memcpy_s(hapName, hapNameSize, tokenInfo.bundleName.c_str(), hapNameLen) != EOK) {
        HKS_LOG_E("memcpy for hapName failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    return HKS_SUCCESS;
}
