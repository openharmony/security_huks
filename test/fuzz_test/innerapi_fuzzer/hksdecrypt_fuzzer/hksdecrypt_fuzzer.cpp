/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "hksdecrypt_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t keySize = fdp.ConsumeIntegralInRange(1, 32);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    struct HksBlob key = { static_cast<uint32_t>(keyVec.size()), keyVec.data() };

    (void)HksFuzzGenerateKey(fdp, key);

    uint32_t ctSize = fdp.ConsumeIntegralInRange(1, 32);
    std::vector<uint8_t> ct = fdp.ConsumeBytes<uint8_t>(ctSize);
    struct HksBlob cipherText = { static_cast<uint32_t>(ct.size()), ct.data() };

    uint32_t ptSize = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> ptBuf(ptSize);
    struct HksBlob plainText = { static_cast<uint32_t>(ptBuf.size()), ptBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksDecrypt(&key, ps.s, &cipherText, &plainText);
}
}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
