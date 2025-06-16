/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_useridm_api_wrap.h"

#include <array>
#include <utility>
#include "hks_condition.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
#include "user_idm_client.h"

#define USER_IAM OHOS::UserIam::UserAuth

#define BIT_NUM  48
#define FACTOR  0x000000000000FFFF

static constexpr const uint32_t g_maxEnrolledLen = 256;

static constexpr std::array g_supportIamAuthType = {
    USER_IAM::AuthType::PIN, USER_IAM::AuthType::FACE, USER_IAM::AuthType::FINGERPRINT
};

static constexpr std::array g_hksIamAuthTypeConvertMap = {
    std::pair<HksUserAuthType, USER_IAM::AuthType>(HKS_USER_AUTH_TYPE_PIN, USER_IAM::AuthType::PIN),
    std::pair<HksUserAuthType, USER_IAM::AuthType>(HKS_USER_AUTH_TYPE_FACE, USER_IAM::AuthType::FACE),
    std::pair<HksUserAuthType, USER_IAM::AuthType>(HKS_USER_AUTH_TYPE_FINGERPRINT, USER_IAM::AuthType::FINGERPRINT),
};

void *HksLockUserIdm(void)
{
    auto *cntr = new (std::nothrow) OHOS::Security::Hks::HksIpcCounter();
    HKS_IF_NULL_LOGE_RETURN(cntr, nullptr, "useridm wrap new HksIpcCounter failed")
    int32_t ret = cntr->Wait();
    HKS_IF_TRUE_RETURN(ret == HKS_SUCCESS, cntr)
    HKS_LOG_E("useridm wrap HksIpcCounter wait failed %" LOG_PUBLIC "d", ret);
    delete cntr;
    return nullptr;
}

void HksUnlockUserIdm(void *ptr)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(ptr, "useridm wrap HksUnlockUserIdm nullptr")
    delete static_cast<OHOS::Security::Hks::HksIpcCounter *>(ptr);
}

static int32_t ConvertFromHksAuthType(enum HksUserAuthType hksAuthType, enum USER_IAM::AuthType *authType)
{
    for (auto[hksType, iamType] : g_hksIamAuthTypeConvertMap) {
        if (hksAuthType == hksType) {
            *authType = iamType;
            return HKS_SUCCESS;
        }
    }
    HKS_LOG_E("Invalid hksAuthType: %" LOG_PUBLIC "d!", hksAuthType);
    return HKS_ERROR_NOT_SUPPORTED;
}

static int32_t ConvertToHksAuthType(enum USER_IAM::AuthType iamAuthType, enum HksUserAuthType *hksAuthType)
{
    for (auto[hksType, iamType] : g_hksIamAuthTypeConvertMap) {
        if (iamAuthType == iamType) {
            *hksAuthType = hksType;
            return HKS_SUCCESS;
        }
    }
    HKS_LOG_E("Invalid iamAuthType: %" LOG_PUBLIC "d!", iamAuthType);
    return HKS_ERROR_NOT_SUPPORTED;
}

static uint32_t GetSupportAuthTypeNum(const USER_IAM::SecUserInfo &info)
{
    uint32_t supportAuthNum = 0;
    for (const USER_IAM::EnrolledInfo &tmp : info.enrolledInfo) {
        auto it = std::find(g_supportIamAuthType.begin(), g_supportIamAuthType.end(), tmp.authType);
        if (it != g_supportIamAuthType.end()) {
            supportAuthNum++;
        } else {
            HKS_LOG_E("no support authType: %" LOG_PUBLIC "d!", tmp.authType);
        }
    }
    return supportAuthNum;
}

class GetSecUserInfoCallbackImplHuks : public USER_IAM::GetSecUserInfoCallback {
public:
    GetSecUserInfoCallbackImplHuks(struct SecInfoWrap **mOutSecInfo, HksCondition *mCondition):outSecInfo(mOutSecInfo),
        condition(mCondition) {}
    virtual ~GetSecUserInfoCallbackImplHuks() = default;
    void OnSecUserInfo(int32_t result, const USER_IAM::SecUserInfo &info) override;
    volatile bool isCallbacked = false;

private:
    struct SecInfoWrap **outSecInfo;
    HksCondition *condition;
};

void GetSecUserInfoCallbackImplHuks::OnSecUserInfo(int32_t result, const USER_IAM::SecUserInfo &info)
{
    int32_t ret = HKS_SUCCESS;
    do {
        if (info.enrolledInfo.size() > g_maxEnrolledLen || info.enrolledInfo.size() == 0) {
            HKS_LOG_E("invalid num of enrolledInfo %" LOG_PUBLIC "u", (uint32_t)info.enrolledInfo.size());
            ret = HKS_ERROR_GET_USERIAM_SECINFO_FAILED;
            break;
        }
        *outSecInfo = static_cast<struct SecInfoWrap *>(HksMalloc(sizeof(struct SecInfoWrap)));
        if (*outSecInfo == NULL) {
            HKS_LOG_E("Malloc outSecInfo failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        uint32_t supportAuthNum = GetSupportAuthTypeNum(info);
        if (supportAuthNum == 0) {
            HKS_LOG_E("All enrolledInfos not support!");
            ret = HKS_ERROR_NOT_SUPPORTED;
            break;
        }

        (*outSecInfo)->enrolledInfo = static_cast<struct EnrolledInfoWrap *>(
            HksMalloc(sizeof(struct EnrolledInfoWrap) * supportAuthNum));
        if ((*outSecInfo)->enrolledInfo == NULL) {
            HKS_LOG_E("Malloc enrolledInfo failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        (**outSecInfo).secureUid = info.secureUid;
        (**outSecInfo).enrolledInfoLen = supportAuthNum;
        uint32_t hksEnrollIndex = 0;
        for (uint32_t i = 0; i < info.enrolledInfo.size(); ++i) {
            HKS_LOG_I("i: %" LOG_PUBLIC "d, enrolledId begin: %" LOG_PUBLIC "u, enrolledId end: %" LOG_PUBLIC "u",
                i, (uint32_t)(info.enrolledInfo[i].enrolledId & FACTOR),
                (uint32_t)((info.enrolledInfo[i].enrolledId >> BIT_NUM) & FACTOR));
            enum HksUserAuthType authType;
            if (ConvertToHksAuthType(info.enrolledInfo[i].authType, &authType) != HKS_SUCCESS) {
                continue;
            }

            (**outSecInfo).enrolledInfo[hksEnrollIndex].authType = authType;
            (**outSecInfo).enrolledInfo[hksEnrollIndex].enrolledId = info.enrolledInfo[i].enrolledId;
            hksEnrollIndex++;
        }
    } while (0);
    if (ret != HKS_SUCCESS && *outSecInfo != NULL) {
        HKS_FREE((*outSecInfo)->enrolledInfo);
        HKS_FREE(*outSecInfo);
    }
    isCallbacked = true;
    HksConditionNotify(condition);
}

int32_t HksUserIdmGetSecInfo(int32_t userId, struct SecInfoWrap **outSecInfo) // callback
{
    HKS_IF_NULL_LOGE_RETURN(outSecInfo, HKS_ERROR_INVALID_ARGUMENT, "HksUserIdmGetSecInfo arguments invalid!")

    HksCondition *condition = HksConditionCreate();
    HKS_IF_NULL_LOGE_RETURN(condition, HKS_FAILURE, "create condition failed!")

    auto mCallback = std::make_shared<GetSecUserInfoCallbackImplHuks>(outSecInfo, condition);
    if (mCallback == nullptr) {
        HKS_LOG_E("make_shared GetSecUserInfoCallbackImplHuks failed!");
        HksConditionDestroy(condition);
        return HKS_ERROR_MALLOC_FAIL;
    }
    std::shared_ptr<USER_IAM::GetSecUserInfoCallback> callback = mCallback;

    int32_t ret = USER_IAM::UserIdmClient::GetInstance().GetSecUserInfo(userId, callback);
    int32_t waitRet = HksConditionWait(condition);
    if (waitRet != HKS_SUCCESS) {
        HKS_LOG_E("HksConditionWait GetSecUserInfo fail! %" LOG_PUBLIC "d", waitRet);
    } else {
        HKS_LOG_I("HksConditionWait GetSecUserInfo succ!");
    }
    HksConditionDestroy(condition);

    HKS_IF_TRUE_LOGE_RETURN(ret != USER_IAM::ResultCode::SUCCESS || !mCallback->isCallbacked || *outSecInfo == NULL,
        HKS_ERROR_GET_USERIAM_SECINFO_FAILED,
        "GetSecUserInfo fail ret %" LOG_PUBLIC "d isCallbacked %" LOG_PUBLIC "d", ret, mCallback->isCallbacked);
    HKS_LOG_I("GetSecUserInfo succ! ret %" LOG_PUBLIC "d", ret);
    return HKS_SUCCESS;
}

class GetCredentialInfoCallbackImplHuks : public USER_IAM::GetCredentialInfoCallback {
public:
    GetCredentialInfoCallbackImplHuks(uint32_t *mNumOfAuthInfo, HksCondition *mCondition)
        :numOfAuthInfo(mNumOfAuthInfo), condition(mCondition)
    {
    }
    virtual ~GetCredentialInfoCallbackImplHuks() {}

    volatile bool isCallbacked = false;

    void OnCredentialInfo(int32_t result, const std::vector<USER_IAM::CredentialInfo> &infoList) override;
private:
    uint32_t *numOfAuthInfo;
    HksCondition *condition;
};

void GetCredentialInfoCallbackImplHuks::OnCredentialInfo(int32_t result,
    const std::vector<USER_IAM::CredentialInfo> &infoList)
{
    static_cast<void>(result);
    *numOfAuthInfo = infoList.size();
    isCallbacked = true;
    HksConditionNotify(condition);
}

int32_t HksUserIdmGetAuthInfoNum(int32_t userId, enum HksUserAuthType hksAuthType, uint32_t *numOfAuthInfo) // callback
{
    HKS_IF_NULL_LOGE_RETURN(numOfAuthInfo, HKS_ERROR_INVALID_ARGUMENT, "HksGetAuthInfo arguments invalid!")

    HksCondition *condition = HksConditionCreate();
    HKS_IF_NULL_LOGE_RETURN(condition, HKS_ERROR_BAD_STATE, "create condition failed!")

    auto huksCallback = std::make_shared<GetCredentialInfoCallbackImplHuks>(numOfAuthInfo, condition);
    if (huksCallback == nullptr) {
        HKS_LOG_E("make_shared GetCredentialInfoCallbackImplHuks failed!");
        HksConditionDestroy(condition);
        return HKS_ERROR_MALLOC_FAIL;
    }
    std::shared_ptr<USER_IAM::GetCredentialInfoCallback> callback = huksCallback;

    enum USER_IAM::AuthType authType;

    int32_t ret = ConvertFromHksAuthType(hksAuthType, &authType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("ConvertFromHksAuthType failed: %" LOG_PUBLIC "d!", ret);
        HksConditionDestroy(condition);
        return ret;
    }

    ret = USER_IAM::UserIdmClient::GetInstance().GetCredentialInfo(userId, authType, callback);
    int32_t waitRet = HksConditionWait(condition);
    if (waitRet != HKS_SUCCESS) {
        HKS_LOG_E("HksConditionWait GetCredentialInfo fail! %" LOG_PUBLIC "d", waitRet);
    } else {
        HKS_LOG_I("HksConditionWait GetCredentialInfo succ!");
    }
    if (ret == USER_IAM::ResultCode::SUCCESS && huksCallback->isCallbacked) {
        HKS_LOG_I("GetCredentialInfo succ!");
        ret = HKS_SUCCESS;
    } else if (ret == USER_IAM::ResultCode::NOT_ENROLLED) { // follow userIam errorCode
        HKS_LOG_E("no credential enrolled");
        ret = HKS_ERROR_CREDENTIAL_NOT_EXIST;
    } else {
        HKS_LOG_E("GetAuthInfo failed: %" LOG_PUBLIC "d!", ret);
        ret = HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED;
    }

    HksConditionDestroy(condition);
    return ret;
}

int32_t HksConvertUserIamTypeToHksType(enum HksUserIamType type, uint32_t userIamValue, uint32_t *hksValue)
{
    HKS_IF_NULL_RETURN(hksValue, HKS_ERROR_NULL_POINTER)
    HKS_IF_TRUE_RETURN(type != HKS_AUTH_TYPE, HKS_ERROR_NOT_SUPPORTED)
    return ConvertToHksAuthType(static_cast<enum USER_IAM::AuthType>(userIamValue),
        reinterpret_cast<enum HksUserAuthType *>(hksValue));
}
#else
int32_t HksUserIdmGetSecInfo(int32_t userId, struct SecInfoWrap **outSecInfo)
{
    (void)userId;
    (void)outSecInfo;
    return HKS_ERROR_NOT_SUPPORTED;
}

int32_t HksUserIdmGetAuthInfoNum(int32_t userId, enum HksUserAuthType hksAuthType, uint32_t *numOfAuthInfo)
{
    (void)userId;
    (void)hksAuthType;
    (void)numOfAuthInfo;
    return HKS_ERROR_NOT_SUPPORTED;
}

int32_t HksConvertUserIamTypeToHksType(enum HksUserIamType type, uint32_t userIamValue, uint32_t *hksValue)
{
    (void)type;
    (void)userIamValue;
    (void)hksValue;
    return HKS_ERROR_NOT_SUPPORTED;
}
#endif
