/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "hksukey_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_fuzz_util.h"

constexpr int BLOB_NUM = 2;

namespace OHOS {
namespace Security {
namespace Hks {

int DoSomethingInterestingWithRegisterProvider(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob providerName = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };
    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    [[maybe_unused]] int ret = HksRegisterProvider(&providerName, ps.s);

    return 0;
}

int DoSomethingInterestingWithUnregisterProvider(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob providerName = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };
    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    [[maybe_unused]] int ret = HksUnregisterProvider(&providerName, ps.s);

    return 0;
}

int DoSomethingInterestingWithHksExportProviderCertificates(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob providerName = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    HksExtCertInfoSet certInfoSet = { 0, nullptr };
    [[maybe_unused]] int ret = HksExportProviderCertificates(&providerName, ps.s, &certInfoSet);
    HksFreeExtCertSet(&certInfoSet);
    return 0;
}

int DoSomethingInterestingWithHksExportCertificate(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob resourceId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    HksExtCertInfoSet certInfoSet = { 0, nullptr };
    [[maybe_unused]] int ret = HksExportCertificate(&resourceId, ps.s, &certInfoSet);
    HksFreeExtCertSet(&certInfoSet);
    return 0;
}

int DoSomethingInterestingWithHksAuthUkeyPin(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob resourceId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    uint32_t retryCount = 0;
    [[maybe_unused]] int ret = HksAuthUkeyPin(&resourceId, ps.s, &retryCount);
    return 0;
}

int DoSomethingInterestingWithHksGetUkeyPinAuthState(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob resourceId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    int32_t status = 0;
    [[maybe_unused]] int ret = HksGetUkeyPinAuthState(&resourceId, ps.s, &status);
    return 0;
}

int DoSomethingInterestingWithHksOpenRemoteHandle(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob resourceId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    [[maybe_unused]] int ret = HksOpenRemoteHandle(&resourceId, ps.s);
    return 0;
}

int DoSomethingInterestingWithHksCloseRemoteHandle(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob resourceId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    [[maybe_unused]] int ret = HksCloseRemoteHandle(&resourceId, ps.s);
    return 0;
}

int DoSomethingInterestingWithHksClearUkeyPinAuthState(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob resourceId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    [[maybe_unused]] int ret = HksClearUkeyPinAuthState(&resourceId);
    return 0;
}

int DoSomethingInterestingWithHksGetRemoteProperty(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (BLOB_NUM * sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob resourceId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };
    struct HksBlob propertyId = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };
    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);
    HksParamSet *psOut = nullptr;
    [[maybe_unused]] int ret = HksGetRemoteProperty(&resourceId, &propertyId, ps.s, &psOut);
    return 0;
}

}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<uint8_t> v(data, data + size);
    (void)OHOS::Security::Hks::DoSomethingInterestingWithRegisterProvider(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksExportProviderCertificates(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksOpenRemoteHandle(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksGetRemoteProperty(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksExportCertificate(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksAuthUkeyPin(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksGetUkeyPinAuthState(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksClearUkeyPinAuthState(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithHksCloseRemoteHandle(v.data(), v.size());
    (void)OHOS::Security::Hks::DoSomethingInterestingWithUnregisterProvider(v.data(), v.size());
    return 0;
}
