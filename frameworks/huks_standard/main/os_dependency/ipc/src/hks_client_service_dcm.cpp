/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "hks_client_service_dcm.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <dlfcn.h>
#include <memory>
#include <mutex>
#include <thread>
#include <securec.h>

#include "hks_cfi.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"

typedef enum {
    DCM_SUCCESS = 0
} DcmErrorCode;

struct DcmBlobT {
    uint32_t size;
    uint8_t *data;
};
using DcmBlob = DcmBlobT;

struct DcmCertChainT {
    DcmBlob *cert;
    uint32_t certCount;
};
using DcmCertChain = DcmCertChainT;

using DcmCallback = void (*)(uint32_t errCode, uint8_t *errInfo, uint32_t infoSize, DcmCertChain *certChain);

class DcmAttest {
    std::condition_variable attestFinished{};
    bool callbackCalled = false;
    bool timeout = false;
    bool isCallingFailed = false;

    std::condition_variable sleepAlarm{};
    HksCertChain *certChain{};

    using AttestFunction = int32_t (*)(const DcmBlob *localAttestCert, DcmCallback callback);
    void *certMgrSdkHandle {};
    AttestFunction dcmAnonymousAttestKey {};

    void DcmCallback(uint32_t errCode, uint8_t *errInfo, uint32_t infoSize, DcmCertChain *dcmCertChain);
    void WaitTimeout();
  public:
    explicit DcmAttest(HksCertChain *certChain);
    ~DcmAttest();
    int32_t AttestWithAnon(HksBlob *cert);
};

void DcmAttest::DcmCallback(uint32_t errCode, uint8_t *errInfo, uint32_t infoSize, DcmCertChain *dcmCertChain)
{
    callbackCalled = true;
    do {
        if (errCode != DCM_SUCCESS) {
            HKS_LOG_I("DcmCallBack result is fail, erroCode = %" LOG_PUBLIC "d", errCode);
            break;
        }
        if (certChain == nullptr || certChain->certs == nullptr) {
            HKS_LOG_E("certChain buffer from caller is null.");
            break;
        }
        if (dcmCertChain == nullptr) {
            HKS_LOG_E("dcmCertChain is NULL");
            break;
        }
        if (certChain->certsCount < dcmCertChain->certCount) {
            HKS_LOG_E("cert count from huks is not enough to load dcm certChain.");
            break;
        }
        HKS_LOG_I("Begin to extract anon certChain.");
        for (uint32_t i = 0; i < dcmCertChain->certCount; ++i) {
            if (certChain->certs[i].data == nullptr) {
                HKS_LOG_E("single cert chain from huks is null.");
                isCallingFailed = true;
                break;
            }
            if (dcmCertChain->cert[i].data == nullptr) {
                HKS_LOG_E("single dcmCertChain buffer is null.");
                isCallingFailed = true;
                break;
            }
            if (memcpy_s(certChain->certs[i].data, certChain->certs[i].size, dcmCertChain->cert[i].data,
                dcmCertChain->cert[i].size) != EOK) {
                HKS_LOG_E("huks certChain cert size is smaller than dcmCertChain certChain size: %" LOG_PUBLIC
                    "u, dcmCertSize: %" LOG_PUBLIC "u", certChain->certs[i].size, dcmCertChain->cert[i].size);
                isCallingFailed = true;
                break;
            }
            certChain->certs[i].size = dcmCertChain->cert[i].size;
        }
        HKS_LOG_I("Extract anon certChain final Success!");
    } while (0);
    attestFinished.notify_all();
}

void DcmAttest::WaitTimeout()
{
    HKS_LOG_I("begin wait_for");
    {
        std::mutex sleepLock{};
        std::unique_lock<std::mutex> lock(sleepLock);
        std::cv_status waitResult =
            sleepAlarm.wait_for(lock, std::chrono::seconds(10));
        if (waitResult == std::cv_status::timeout) {
            HKS_LOG_E("watting for dcm is timeout!");
        } else {
            HKS_LOG_I("finished successfully! waked up!");
        }
    }
    timeout = true;
    attestFinished.notify_all();
}

DcmAttest::DcmAttest(HksCertChain *certChain) : certChain(certChain)
{
    HKS_LOG_I("begin dlopen libdevice_cert_mgr_sdk.z.so");
    certMgrSdkHandle = dlopen("libdevice_cert_mgr_sdk.z.so", RTLD_NOW);
    if (certMgrSdkHandle == nullptr) {
        HKS_LOG_E("dlopen libdevice_cert_mgr_sdk.z.so failed! %" LOG_PUBLIC "s", dlerror());
        return;
    }
    HKS_LOG_I("dlopen ok!");
    dcmAnonymousAttestKey = reinterpret_cast<AttestFunction>(dlsym(certMgrSdkHandle, "DcmAnonymousAttestKey"));
    if (dcmAnonymousAttestKey == nullptr) {
        HKS_LOG_E("dlsym failed %" LOG_PUBLIC "s", dlerror());
        return;
    }
    HKS_LOG_I("dlsym ok!");
}

DcmAttest::~DcmAttest()
{
    if (certMgrSdkHandle == nullptr) {
        return;
    }
    int ret = dlclose(certMgrSdkHandle);
    HKS_LOG_W("dlclose ret %" LOG_PUBLIC "d", ret);
}

ENABLE_CFI(int32_t DcmAttest::AttestWithAnon(HksBlob *cert))
{
    HKS_LOG_I("enter attest for dcm.");
    if (dcmAnonymousAttestKey == nullptr) {
        HKS_LOG_E("dcmAnonymousAttestKey is NULL!");
        return HKS_ERROR_IPC_DLOPEN_FAIL;
    }
    std::thread timerThread([this]() { WaitTimeout(); });
    DcmBlob dcmCert = {.size = cert->size, .data = cert->data};
    HKS_LOG_I("begin to pack callback for dcmAnonymousAttestKey");
    static auto callback = [this](uint32_t errCode, uint8_t *errInfo, uint32_t infoSize, DcmCertChain *dcmCertChain) {
        DcmCallback(errCode, errInfo, infoSize, dcmCertChain);
    };
    HKS_LOG_I("begin to call dcmAnonymousAttestKey!");
    int32_t ret = dcmAnonymousAttestKey(&dcmCert, [](uint32_t errCode, uint8_t *errInfo, uint32_t infoSize,
        DcmCertChain *dcmCertChain) {
        callback(errCode, errInfo, infoSize, dcmCertChain);
    });
    if (ret != DCM_SUCCESS) {
        HKS_LOG_E("calling dcm anon attestKey not success,ret = %" LOG_PUBLIC "d", ret);
        sleepAlarm.notify_all();
        timerThread.join();
        return ret;
    }
    HKS_LOG_I("Calling DcmAnonymousAttestKey ok, begin to wait callback!");
    std::mutex mtx{};
    std::unique_lock<std::mutex> lock(mtx);
    // only wait callback if ret is success
    attestFinished.wait(lock, [&] { return callbackCalled || timeout; });
    if (callbackCalled) {
        HKS_LOG_I("callbackCalled return certchain.");
    } else {
        HKS_LOG_E("no callbackCalled");
        ret = HKS_ERROR_COMMUNICATION_TIMEOUT;
    }
    if (isCallingFailed) {
        ret = HKS_ERROR_BUFFER_TOO_SMALL;
    }
    HKS_LOG_I("begin notify sleep thread");
    sleepAlarm.notify_all();
    HKS_LOG_I("begin timerThread.join()");
    timerThread.join();
    return ret;
}

int32_t DcmGenerateCertChain(HksBlob *cert, HksCertChain *certChain)
{
    DcmAttest attest(certChain);
    return attest.AttestWithAnon(cert);
}
