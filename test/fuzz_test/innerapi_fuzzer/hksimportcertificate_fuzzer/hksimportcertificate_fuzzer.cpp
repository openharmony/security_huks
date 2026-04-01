/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "hksimportcertificate_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int DoSomethingInterestingWithHksImportCertificate(uint8_t *data, size_t size)
{
    // 至少需要能容纳一个长度字段 + 最小证书信息
    if (data == nullptr || size < (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint32_t) + sizeof(uint32_t))) {
        return -1;
    }

    uint32_t paramSetDataSize = *reinterpret_cast<uint32_t *>(data);
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    // 确保参数集数据长度不超过剩余数据大小
    if (paramSetDataSize > size) {
        return -1;
    }

    // 2. 构造参数集（使用参数集数据区域）
    uint8_t *paramData = data;
    size_t paramSize = paramSetDataSize;
    WrapParamSet ps = ConstructHksParamSetFromFuzz(paramData, paramSize);

    data += paramSetDataSize;
    size -= paramSetDataSize;

    // 确保剩余数据足够构造证书信息
    if (size < (sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint32_t) + sizeof(uint32_t))) {
        HksFreeParamSet(&ps.s);
        return -1;
    }

    // 4. 构造 keyAlias
    uint32_t aliasSize = *reinterpret_cast<uint32_t *>(data);
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);
    if (aliasSize == 0 || aliasSize > size) {
        HksFreeParamSet(&ps.s);
        return -1;
    }
    uint8_t *aliasData = (uint8_t *)HksMalloc(aliasSize);
    if (aliasData == nullptr) {
        HksFreeParamSet(&ps.s);
        return -1;
    }
    memcpy(aliasData, data, aliasSize);
    struct HksBlob keyAlias = { aliasSize, aliasData };
    data += aliasSize;
    size -= aliasSize;

    // 5. 构造证书信息
    HksExtCertInfo certInfo = { 0 };

    // purpose
    if (size < sizeof(int32_t)) {
        free(aliasData);
        HksFreeParamSet(&ps.s);
        return -1;
    }
    certInfo.purpose = *reinterpret_cast<int32_t *>(data);
    data += sizeof(int32_t);
    size -= sizeof(int32_t);

    // index
    if (size < sizeof(uint32_t)) {
        free(aliasData);
        HksFreeParamSet(&ps.s);
        return -1;
    }
    uint32_t indexSize = *reinterpret_cast<uint32_t *>(data);
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);
    if (indexSize == 0 || indexSize > 1024) {
        indexSize = 1024;
    }
    if (size < indexSize) {
        free(aliasData);
        HksFreeParamSet(&ps.s);
        return -1;
    }
    certInfo.index.size = indexSize;
    certInfo.index.data = (uint8_t *)HksMalloc(indexSize);
    if (certInfo.index.data == nullptr) {
        free(aliasData);
        HksFreeParamSet(&ps.s);
        return -1;
    }
    memcpy(certInfo.index.data, data, indexSize);
    data += indexSize;
    size -= indexSize;

    // cert
    if (size < sizeof(uint32_t)) {
        free(aliasData);
        free(certInfo.index.data);
        HksFreeParamSet(&ps.s);
        return -1;
    }
    uint32_t certSize = *reinterpret_cast<uint32_t *>(data);
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);
    if (certSize == 0 || certSize > 4096) {
        certSize = 4096;
    }
    if (size < certSize) {
        free(aliasData);
        free(certInfo.index.data);
        HksFreeParamSet(&ps.s);
        return -1;
    }
    certInfo.cert.size = certSize;
    certInfo.cert.data = (uint8_t *)HksMalloc(certSize);
    if (certInfo.cert.data == nullptr) {
        free(aliasData);
        free(certInfo.index.data);
        HksFreeParamSet(&ps.s);
        return -1;
    }
    memcpy(certInfo.cert.data, data, certSize);

    [[maybe_unused]] int ret = HksImportCertificate(&keyAlias, &certInfo, ps.s);

    free(keyAlias.data);
    free(certInfo.index.data);
    free(certInfo.cert.data);
    HksFreeParamSet(&ps.s);
    return 0;
}

}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<uint8_t> v(data, data + size);
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksImportCertificate(v.data(), v.size());
    return 0;
}