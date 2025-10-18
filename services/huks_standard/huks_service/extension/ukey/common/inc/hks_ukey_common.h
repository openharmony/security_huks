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
#include <hks_type.h>

namespace OHOS {
namespace Security {
namespace Huks {

    bool IsHksBlobEmpty(const struct HksBlob& blob);

    bool IsHksExtCertInfoSetEmpty(const struct HksExtCertInfoSet& certSet);
    HksBlob Base64StringToBlob(const std::string &inStr);
    std::string BlobToBase64String(const struct HksBlob &strBlob);
    HksBlob StringToBlob(const std::string &inStr);
    std::string BlobToString(const HksBlob &strBlob);

    int32_t StringToCertInfo(const std::string &certInfoJson, struct HksExtCertInfo& certInfo);

    int32_t CertInfoToString(const struct HksExtCertInfo& certInfo, std::string& jsonStr);

    int32_t JsonArrayToCertInfoSet(const std::string &certJsonArr, struct HksExtCertInfoSet& certSet);

    int32_t CertInfoSetToJsonArray(const struct HksExtCertInfoSet& certSet, std::string& jsonArrayStr);

    void FreeCertInfoSet(HksExtCertInfoSet &certSet);

}
}
}

#endif