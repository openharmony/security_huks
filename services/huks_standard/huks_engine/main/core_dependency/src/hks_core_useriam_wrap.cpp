/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_core_useriam_wrap.h"
#include "hks_log.h"
#include "hks_template.h"

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
#ifdef HKS_CORE_ENABLE_HDI_DRIVER
#include "v2_0/user_auth_types.h"

using AuthType = OHOS::HDI::UserAuth::V2_0::AuthType;

static int32_t ConvertToHksAuthType(AuthType authType, enum HksUserAuthType *hksAuthType)
{
    switch (authType) {
        case AuthType::FACE:
            *hksAuthType = HKS_USER_AUTH_TYPE_FACE;
            break;
        case AuthType::PIN:
            *hksAuthType =  HKS_USER_AUTH_TYPE_PIN;
            break;
        case AuthType::FINGERPRINT:
            *hksAuthType =  HKS_USER_AUTH_TYPE_FINGERPRINT;
            break;
        default:
            HKS_LOG_E("Invalid authType!");
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return HKS_SUCCESS;
}

int32_t HksCoreConvertUserIamTypeToHksType(enum HksUserIamType type, uint32_t userIamValue, uint32_t *hksValue)
{
    HKS_IF_NULL_RETURN(hksValue, HKS_ERROR_NULL_POINTER)

    switch (type) {
        case HKS_AUTH_TYPE:
            return ConvertToHksAuthType(static_cast<AuthType>(userIamValue),
                reinterpret_cast<enum HksUserAuthType *>(hksValue));
        default:
            break;
    }
    return HKS_ERROR_NOT_SUPPORTED;
}
#else

#include "hks_useridm_api_wrap.h"

int32_t HksCoreConvertUserIamTypeToHksType(enum HksUserIamType type, uint32_t userIamValue, uint32_t *hksValue)
{
    return HksConvertUserIamTypeToHksType(type, userIamValue, hksValue);
}
#endif
#else

int32_t HksCoreConvertUserIamTypeToHksType(enum HksUserIamType type, uint32_t userIamValue, uint32_t *hksValue)
{
    (void)type;
    (void)userIamValue;
    (void)hksValue;
    return HKS_ERROR_NOT_SUPPORTED;
}
#endif