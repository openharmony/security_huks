/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "hksexportprovidercertificates_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t nameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> nameBuf = fdp.ConsumeBytes<uint8_t>(nameSize);
    if (nameBuf.size() == 0) {
        nameBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob providerName = { static_cast<uint32_t>(nameBuf.size()), nameBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    HksExtCertInfoSet certInfoSet = { 0, nullptr };
    int32_t ret = HksExportProviderCertificates(&providerName, ps.s, &certInfoSet);
    (void)HksFreeExtCertSet(&certInfoSet);
    return ret;
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob providerName = { 12, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_prov")) };
    struct HksExtCertInfoSet certSet = { 0, nullptr };
    WrapParamSet exportPs = BuildFixedParamSet({});
    int32_t ret = HksExportProviderCertificates(&providerName, exportPs.s, &certSet);
    printf("fuzz_exportprovidercertificates init: HksExportProviderCertificates ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}