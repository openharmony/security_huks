/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hks_config_parser.h"

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "hks_at_api_wrap.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type_inner.h"


static const struct HksFileTransferSystemAbilityConfig SA_UPGRADE_CFG_LIST[] = HUKS_SA_UPGRADE_CONFIG;
static const struct HksFileTransferHapConfig HAP_UPGRADE_CFG_LIST[] = HUKS_HAP_UPGRADE_CONFIG;
static const uint32_t SA_SKIP_UPGRADE_CFG_LIST[] = HUKS_SA_SKIP_UPGRADE_CONFIG;
static const char *HAP_SKIP_UPGRADE_CFG_LIST[] = HUKS_HAP_SKIP_UPGRADE_CONFIG;

static int32_t ParseOwnerIdFromParamSet(const struct HksParamSet *paramSet, uint32_t *uid, uint64_t *accessTokenId,
    uint32_t *userId)
{
    bool getUid = false;
    bool getAccessToken = false;
    bool getUserId = false;
    int32_t ret;
    for (uint32_t i = 0; i < paramSet->paramsCnt; ++i) {
        if (paramSet->params[i].tag == HKS_TAG_PROCESS_NAME) {
            // the uid data should be uint32_t
            if (paramSet->params[i].blob.size != sizeof(uint32_t)) {
                HKS_LOG_E("process name blob data is over the size of uint32_t.");
                ret = HKS_ERROR_INVALID_KEY_FILE;
                break;
            }
            *uid = *(uint32_t *)paramSet->params[i].blob.data;
            getUid = true;
            continue;
        }
        if (paramSet->params[i].tag == HKS_TAG_ACCESS_TOKEN_ID) {
            *accessTokenId = paramSet->params[i].uint64Param;
            getAccessToken = true;
            continue;
        }
        if (paramSet->params[i].tag == HKS_TAG_SPECIFIC_USER_ID) {
            *userId = paramSet->params[i].uint32Param;
            getUserId = true;
            continue;
        }
        if (paramSet->params[i].tag == HKS_TAG_USER_ID && !getUserId) {
            *userId = paramSet->params[i].uint32Param;
            getUserId = true;
            continue;
        }
        if (getUid && getAccessToken && getUserId) {
            break;
        }
    }
    ret = getUid && getAccessToken && getUserId ? HKS_SUCCESS : HKS_ERROR_INVALID_KEY_FILE;
    return ret;
}

static int32_t ParseOwnerIdFromFileContent(const struct HksBlob *fileContent, uint32_t *uid, uint64_t *accessTokenId,
    uint32_t *userId)
{
    struct HksParamSet *tmpParamSet = NULL;
    int32_t ret = HksGetParamSet((const struct HksParamSet *)fileContent->data, fileContent->size, &tmpParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "fresh paramset failed.")

    ret = ParseOwnerIdFromParamSet(tmpParamSet, uid, accessTokenId, userId);
    HKS_FREE(tmpParamSet);
    return ret;
}

static void InitDefaultStrategy(struct HksUpgradeFileTransferInfo *info)
{
    info->skipTransfer = false;
    info->needDe = false;
    info->needFrontUser = false;
}

static int32_t MatchSaConfig(uint32_t uid, uint32_t userId, struct HksUpgradeFileTransferInfo *info)
{
    InitDefaultStrategy(info);
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(SA_SKIP_UPGRADE_CFG_LIST); ++i) {
        if (uid == SA_SKIP_UPGRADE_CFG_LIST[i]) {
            HKS_LOG_I("%" LOG_PUBLIC "u needs skip transfer upgrade.", uid);
            info->skipTransfer = true;
            return HKS_SUCCESS;
        }
    }

    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(SA_UPGRADE_CFG_LIST); ++i) {
        if (SA_UPGRADE_CFG_LIST[i].uid == uid) {
            info->needDe = SA_UPGRADE_CFG_LIST[i].needDe;
            info->needFrontUser = SA_UPGRADE_CFG_LIST[i].needFrontUser;
            HKS_LOG_I("match sa config, need de %" LOG_PUBLIC "d, need with withUser %" LOG_PUBLIC "d.",
                info->needDe, info->needFrontUser);
            break;
        }
    }
    info->uid = uid;
    info->userId = userId;
    return HKS_SUCCESS;
}

static int32_t MatchHapConfig(uint32_t uid, uint32_t userId, uint64_t accessTokenId,
    struct HksUpgradeFileTransferInfo *info)
{
    char hapName[HAP_NAME_LEN_MAX] = { 0 };
    int32_t ret = HksGetHapNameFromAccessToken(accessTokenId, hapName, HAP_NAME_LEN_MAX);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "get hap name from accessTokenId failed, accessTokenId is %" LOG_PUBLIC PRIu64, accessTokenId)

    InitDefaultStrategy(info);
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(HAP_SKIP_UPGRADE_CFG_LIST); ++i) {
        if (strlen(HAP_SKIP_UPGRADE_CFG_LIST[i]) != strlen(hapName)) {
            continue;
        }
        if (HksMemCmp(HAP_SKIP_UPGRADE_CFG_LIST[i], hapName, strlen(hapName)) == EOK) {
            info->skipTransfer = true;
            HKS_LOG_I("%" LOG_PUBLIC "u, %" LOG_PUBLIC "s needs skip transfer upgrade.", uid, hapName);
            return HKS_SUCCESS;
        }
    }
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(HAP_UPGRADE_CFG_LIST); ++i) {
        if (strlen(HAP_UPGRADE_CFG_LIST[i].hapName) != strlen(hapName)) {
            continue;
        }
        if (HksMemCmp(HAP_UPGRADE_CFG_LIST[i].hapName, hapName, strlen(hapName)) == EOK) {
            info->needDe = HAP_UPGRADE_CFG_LIST[i].needDe;
            info->needFrontUser = HAP_UPGRADE_CFG_LIST[i].needFrontUser;
            HKS_LOG_I("match hap config, need de %" LOG_PUBLIC "d, need with withUser %" LOG_PUBLIC "d.",
                info->needDe, info->needFrontUser);
            break;
        }
    }
    info->uid = uid;
    info->userId = userId;
    return HKS_SUCCESS;
}

int32_t HksMatchConfig(uint32_t uid, uint32_t userId, uint64_t accessTokenId, struct HksUpgradeFileTransferInfo *info)
{
    enum HksAtType type;
    int32_t ret = HksGetAtType(accessTokenId, &type);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get access token type failed.")
    if (type == HKS_TOKEN_HAP) {
        return MatchHapConfig(uid, userId, accessTokenId, info);
    }
    return MatchSaConfig(uid, userId, info);
}

// get transfer config info of a key file, which contains the owner info
int32_t HksParseConfig(const struct HksBlob *fileContent, struct HksUpgradeFileTransferInfo *info)
{
    uint32_t uid = 0;
    uint64_t accessTokenId = 0;
    uint32_t userId = 0;
    int32_t ret = ParseOwnerIdFromFileContent(fileContent, &uid, &accessTokenId, &userId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "parse file failed.")
    return HksMatchConfig(uid, userId, accessTokenId, info);
}
