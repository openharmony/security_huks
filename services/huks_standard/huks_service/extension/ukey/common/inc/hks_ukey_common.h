/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_UKEY_COMMON_H
#define HKS_UKEY_COMMON_H

#include <iostream>
#include <utility>
#include <vector>
#include <map>
#include <hks_type.h>

namespace OHOS {
namespace Security {
namespace Huks {

    enum ExtensionErrCode {
        EXTENSION_SUCCESS = 0,
        EXTENSION_ERRCODE_OPERATION_FAIL = 34800000,
        EXTENSION_ERRCODE_UKEY_NOT_EXIST = 34800001,
        EXTENSION_ERRCODE_UKEY_FAIL = 34800002,
        EXTENSION_ERRCODE_PIN_NOT_AUTH = 34800003,
        EXTENSION_ERRCODE_HANDLE_NOT_EXIST = 34800004,
        EXTENSION_ERRCODE_HANDLE_FAIL = 34800005,
        EXTENSION_ERRCODE_PIN_CODE_ERROR = 34800006,
        EXTENSION_ERRCODE_PIN_LOCKED = 34800007,
    };

    bool CheckStringParamLenIsOk(const std::string &str, uint32_t min, uint32_t max);
    bool IsHksExtCertInfoSetEmpty(const struct HksExtCertInfoSet& certSet);
    HksBlob Base64StringToBlob(const std::string &inStr);
    std::string BlobToBase64String(const struct HksBlob &strBlob);
    HksBlob StringToBlob(const std::string &inStr);
    std::string BlobToString(const HksBlob &strBlob);
    int32_t CertInfoToString(const struct HksExtCertInfo& certInfo, std::string& jsonStr);
    int32_t JsonArrayToCertInfoSet(const std::string &certJsonArr, struct HksExtCertInfoSet& certSet);
    int32_t ConvertExtensionToHksErrorCode(const int32_t extensionErrorCode,
        const std::map<int32_t, int32_t> &errorMapping);
}
}
}

#endif