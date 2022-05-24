/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hksgetkeyparamset_fuzzer.h"

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include <securec.h>

#define BLOB_SIZE 10
#define DOUBLE 2

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size <= (sizeof(struct HksParamSet) * DOUBLE + BLOB_SIZE)) {
            return false;
        }

        uint8_t *mydata = (uint8_t *)HksMalloc(sizeof(uint8_t) * size);
        if(mydata == nullptr) {
            return false;
        }

        (void)memcpy_s(mydata, size, data, size);

        struct HksBlob keyAlias = { BLOB_SIZE, (uint8_t *)mydata };

        int paramSize = (size - BLOB_SIZE) / DOUBLE;
        struct HksParamSet *paramSetIn = (struct HksParamSet *)(mydata + BLOB_SIZE);
        paramSetIn->paramSetSize = 
        paramSize < HKS_PARAM_SET_MAX_SIZE ? paramSize : HKS_PARAM_SET_MAX_SIZE;

        struct HksParamSet *paramSetOut = (struct HksParamSet *)(mydata + BLOB_SIZE + paramSize);
        paramSetOut->paramSetSize = 
        paramSize < HKS_PARAM_SET_MAX_SIZE ? paramSize : HKS_PARAM_SET_MAX_SIZE;

        (void)HksGetKeyParamSet(&keyAlias, paramSetIn, paramSetOut);

        if(mydata != nullptr) {
            HksFree(mydata);
        }

        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

