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

#ifndef HKS_CONFIG_PARSER_H
#define HKS_CONFIG_PARSER_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

enum HksUpgradeFileTransferUserType {
    WITH_OWNER = 0,
    // default user is 100 for current account system policy
    WITH_USER
};

// config struct for hap
struct HksFileTransferHapConfig {
    const char *hapName;
    // enum HksAuthStorageLevel storageType;
    // enum HksUpgradeFileTransferUserType userType;
    bool needDe;
    bool needFrontUser;
};

// config struct for sa
struct HksFileTransferSystemAbilityConfig {
    uint32_t uid;
    // enum HksAuthStorageLevel storageType;
    bool needDe;
    bool needFrontUser;
    // enum HksUpgradeFileTransferUserType userType;
};

// transfer info leading the huks to upgrade
struct HksUpgradeFileTransferInfo {
    bool skipTransfer;
    bool needDe;
    bool needFrontUser;
    // enum HksAuthStorageLevel storageType;
    // enum HksUpgradeFileTransferUserType userType;
    uint32_t uid;
    uint32_t userId;
};

// match config: file_content => uid + user id + access token id.
// match HksFileTransferHapConfig and HksFileTransferSystemAbilityConfig into HksUpgradeFileTransferInfo
int32_t HksParseConfig(const struct HksBlob *fileContent, struct HksUpgradeFileTransferInfo *info);

int32_t HksMatchConfig(uint32_t uid, uint32_t userId, uint64_t accessTokenId, struct HksUpgradeFileTransferInfo *info);

#ifdef __cplusplus
}
#endif

#endif // HKS_CONFIG_PARSER_H