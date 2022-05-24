/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hksgeneratekey_fuzzer.h"

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include <iostream>
#include <stddef.h>
#include <stdint.h>
#include <securec.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size <= (sizeof(struct HksParamSet) + 10))
        {
            return false;
        }

        uint8_t *mydata = (uint8_t *)HksMalloc(sizeof(uint8_t) * size);
        if (mydata == nullptr)
        {
            return false;
        }

        (void)memcpy_s(mydata, size, data, size);

        struct HksBlob keyAlias = { 10, (uint8_t *)mydata };
        struct HksParamSet *paramSetIn = (struct HksParamSet *)(mydata + 10);
        paramSetIn->paramSetSize = (size - 10) < HKS_PARAM_SET_MAX_SIZE ? (size - 10) : HKS_PARAM_SET_MAX_SIZE;

        HksGenerateKey(&keyAlias, paramSetIn, NULL);

        if (mydata != nullptr)
        {
            HksFree(mydata);
        }

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

