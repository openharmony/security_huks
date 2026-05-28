/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "hksvalidatecertchain_fuzzer.h"

#include <algorithm>

#include "hks_fuzz_util.h"

constexpr int CERT_SIZE = 4096;
constexpr int CERT_COUNT = 4;

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    std::vector<uint8_t> certRootBuffer(CERT_SIZE);
    std::vector<uint8_t> certCaBuffer(CERT_SIZE);
    std::vector<uint8_t> certDeviceBuffer(CERT_SIZE);
    std::vector<uint8_t> certAppBuffer(CERT_SIZE);

    uint32_t rootSize = fdp.ConsumeIntegralInRange<uint32_t>(0, CERT_SIZE);
    std::vector<uint8_t> rootData = fdp.ConsumeBytes<uint8_t>(rootSize);
    if (rootData.size() > 0) {
        std::copy(rootData.begin(), rootData.end(), certRootBuffer.begin());
    }

    uint32_t caSize = fdp.ConsumeIntegralInRange<uint32_t>(0, CERT_SIZE);
    std::vector<uint8_t> caData = fdp.ConsumeBytes<uint8_t>(caSize);
    if (caData.size() > 0) {
        std::copy(caData.begin(), caData.end(), certCaBuffer.begin());
    }

    uint32_t deviceSize = fdp.ConsumeIntegralInRange<uint32_t>(0, CERT_SIZE);
    std::vector<uint8_t> deviceData = fdp.ConsumeBytes<uint8_t>(deviceSize);
    if (deviceData.size() > 0) {
        std::copy(deviceData.begin(), deviceData.end(), certDeviceBuffer.begin());
    }

    uint32_t appSize = fdp.ConsumeIntegralInRange<uint32_t>(0, CERT_SIZE);
    std::vector<uint8_t> appData = fdp.ConsumeBytes<uint8_t>(appSize);
    if (appData.size() > 0) {
        std::copy(appData.begin(), appData.end(), certAppBuffer.begin());
    }

    struct HksBlob resultCerts[CERT_COUNT] = {
        { CERT_SIZE, certRootBuffer.data() },
        { CERT_SIZE, certCaBuffer.data() },
        { CERT_SIZE, certDeviceBuffer.data() },
        { CERT_SIZE, certAppBuffer.data() },
    };
    struct HksCertChain certChain = {
        .certs = resultCerts,
        .certsCount = CERT_COUNT
    };

    uint32_t paramSetOutSize = fdp.ConsumeIntegralInRange<uint32_t>(sizeof(struct HksParamSet), CERT_SIZE);
    std::vector<uint8_t> paramSetOutBuf(paramSetOutSize);
    struct HksParamSet *paramSetOut = reinterpret_cast<struct HksParamSet *>(paramSetOutBuf.data());
    paramSetOut->paramSetSize = paramSetOutSize;

    return HksValidateCertChain(&certChain, paramSetOut);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob certBuf = { 4, reinterpret_cast<uint8_t *>(const_cast<char *>("cert")) };
    struct HksCertChain certChain = { &certBuf, 1 };
    uint8_t paramSetOutBuf[128] = {0};
    struct HksParamSet *paramSetOut = reinterpret_cast<struct HksParamSet *>(paramSetOutBuf);
    paramSetOut->paramSetSize = 128;
    int32_t ret = HksValidateCertChain(&certChain, paramSetOut);
    printf("fuzz_validatecertchain init: HksValidateCertChain ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}