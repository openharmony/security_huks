#include "hks_remote_handle_manager.h"
#include "hks_ukey_session_manager.h"
#include "hks_cpp_paramset.h"
#include "hks_ukey_common.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_template.h"
#include "huks_access_ext_base_stub.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include <string>
#include <vector>
#include <tuple>
#include "hks_json_wrapper.h"
namespace OHOS::Security::Huks {

// ==================== ProviderInfo ====================
bool ProviderInfo::operator==(const ProviderInfo &other) const
{
    return m_bundleName == other.m_bundleName && m_providerName == other.m_providerName &&
        m_abilityName == other.m_abilityName;
}

bool ProviderInfo::operator<(const ProviderInfo &other) const
{
    return std::tie(m_bundleName, m_providerName, m_abilityName) <
        std::tie(other.m_bundleName, other.m_providerName, other.m_abilityName);
}

// ==================== HksCryptoExtStubImpl ====================
class HksCryptoExtStubImpl : public HuksAccessExtBaseStub {
public:
    explicit HksCryptoExtStubImpl() = default;
    ~HksCryptoExtStubImpl() {}

    ErrCode OpenRemoteHandle(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode CloseRemoteHandle(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode AuthUkeyPin(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& errcode,
        int32_t& authState,
        uint32_t& retryCnt) { errcode = HKS_SUCCESS; authState = 1; retryCnt = 0; return ERR_OK; }

    ErrCode GetUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& state,
        int32_t& errcode) { state = 1; errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode Sign(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode Verify(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& plainText,
        const std::vector<uint8_t>& signature,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode ExportCertificate(
    const std::string& index,
    const CppParamSet& params,
    std::string& certJsonArr,
    int32_t& errcode)
{
    CommJsonObject certArray = CommJsonObject::CreateArray();
    if (certArray.IsNull()) {
        errcode = HKS_ERROR_MALLOC_FAIL;
        return ERR_OK;
    }
    CommJsonObject certObj = CommJsonObject::CreateObject();
    if (certObj.IsNull()) {
        errcode = HKS_ERROR_MALLOC_FAIL;
        return ERR_OK;
    }
    if (!certObj.SetValue("purpose", 1) ||
        !certObj.SetValue("index", std::string("mock_cert_index")) ||
        !certObj.SetValue("cert", std::string("MIIBIjANBgkqh"))) {
        errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
        return ERR_OK;
    }
    if (!certArray.AppendElement(certObj)) {
        errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
        return ERR_OK;
    }
    certJsonArr = certArray.Serialize(false);
    errcode = HKS_SUCCESS;
    return ERR_OK;
}

ErrCode ExportProviderCertificates(
    const CppParamSet& params,
    std::string& certJsonArr,
    int32_t& errcode)
{
    CommJsonObject certArray = CommJsonObject::CreateArray();
    if (certArray.IsNull()) {
        errcode = HKS_ERROR_MALLOC_FAIL;
        return ERR_OK;
    }
    for (int i = 0; i < 2; i++) {
        CommJsonObject certObj = CommJsonObject::CreateObject();
        if (certObj.IsNull()) {
            errcode = HKS_ERROR_MALLOC_FAIL;
            return ERR_OK;
        }
        if (!certObj.SetValue("purpose", i + 1) ||
            !certObj.SetValue("index", std::string("cert_") + std::to_string(i)) ||
            !certObj.SetValue("cert", std::string("MIIBIjAN") + std::to_string(i))) {
            errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
            return ERR_OK;
        }
        if (!certArray.AppendElement(certObj)) {
            errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
            return ERR_OK;
        }
    }
    certJsonArr = certArray.Serialize(false);
    errcode = HKS_SUCCESS;
    return ERR_OK;
}

    ErrCode InitSession(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode UpdateSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode FinishSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode GetProperty(
        const std::string& handle,
        const std::string& propertyId,
        const CppParamSet& params,
        CppParamSet& outParams,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode GetResourceId(
        const CppParamSet& params,
        std::string& resourceId,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode ClearUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode ImportWrappedKey(
        const std::string& index,
        const std::string& wrappingKeyIndex,
        const CppParamSet& params,
        const std::vector<uint8_t>& wrappedData,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode ExportPublicKey(
        const std::string& index,
        const CppParamSet& params,
        std::vector<uint8_t>& outData,
        int32_t& errcode)
        { outData = {0x01, 0x02, 0x03}; errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode ImportCertificate(
        const std::string& index,
        const std::string& certJsonStr,
        const CppParamSet& params,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }

    ErrCode GenerateKey(
        const std::string& index,
        const CppParamSet& params,
        int32_t& errcode) { errcode = HKS_SUCCESS; return ERR_OK; }
};

// ==================== HksProviderLifeCycleManager mock ====================
std::shared_ptr<HksProviderLifeCycleManager> HksProviderLifeCycleManager::GetInstanceWrapper()
{
    return HksProviderLifeCycleManager::GetInstance();
}

void HksProviderLifeCycleManager::ReleaseInstance()
{
    HksProviderLifeCycleManager::DestroyInstance();
}

void HksProviderLifeCycleManager::PrintRegisterProviders() {}

int32_t HksProviderLifeCycleManager::OnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::function<void(HksProcessInfo)> callback)
{
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::GetExtensionProxy(const ProviderInfo &providerInfo,
    sptr<IHuksAccessExtBase> &proxy)
{
    proxy = sptr<HuksAccessExtBaseStub>(new HksCryptoExtStubImpl());
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::HapGetAllConnectInfoByProviderName(const std::string &bundleName,
    const std::string &providerName, const int32_t userid,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &providerInfos)
{
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::GetAllProviderInfosByProviderName(const std::string &providerName,
    const int32_t &userid, std::vector<ProviderInfo> &providerInfos)
{
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::HksHapGetConnectInfos(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &connectionInfos)
{
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::OnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, bool isdeath, int32_t &deleteCount)
{
    deleteCount = 0;
    return HKS_SUCCESS;
}

int32_t HksGetProviderInfo(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, ProviderInfo &providerInfo)
{
    return HKS_SUCCESS;
}

// ==================== HksRemoteHandleManager mock ====================
bool g_clearAuthStateCalled = false;
bool g_clearMapByUidCalled = false;
uint32_t g_clearMapByUidArg = 0;
bool g_createRemoteHandleCalled = false;
bool g_closeRemoteHandleCalled = false;

void ResetHandleManagerMockFlags()
{
    g_clearAuthStateCalled = false;
    g_clearMapByUidCalled = false;
    g_clearMapByUidArg = 0;
    g_createRemoteHandleCalled = false;
    g_closeRemoteHandleCalled = false;
}

std::shared_ptr<HksRemoteHandleManager> HksRemoteHandleManager::GetInstanceWrapper()
{
    return HksRemoteHandleManager::GetInstance();
}

void HksRemoteHandleManager::ReleaseInstance()
{
    HksRemoteHandleManager::DestroyInstance();
}

int32_t HksRemoteHandleManager::CreateRemoteHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    g_createRemoteHandleCalled = true;
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CloseRemoteHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    g_closeRemoteHandleCalled = true;
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteClearPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CheckAuthStateIsOk(const HksProcessInfo &processInfo, const std::string &index)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::FindRemoteCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certificatesOut)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::FindRemoteAllCertificate(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certificatesOut)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ImportRemoteCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const struct HksExtCertInfo &certInfo, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::MergeProviderCertificates(const ProviderInfo &providerInfo,
    const std::string &providerCertVec, CommJsonObject &combinedArray)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetRemoteProperty(const HksProcessInfo &processInfo,
    const std::string &index, const std::string &propertyId, const CppParamSet &paramSet,
    CppParamSet &outParams)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteImportWrappedKey(const HksProcessInfo &processInfo,
    const std::string &index, const std::string &wrappingKeyIndex, const CppParamSet &paramSet,
    const std::vector<uint8_t> &wrappedData)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteExportPublicKey(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::vector<uint8_t> &outData)
{
    outData = {0x01, 0x02, 0x03};
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ExtensionGenerateKey(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ClearUidIndexMap(const ProviderInfo &providerInfo)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ParseIndexAndProviderInfo(const std::string &index,
    ProviderInfo &providerInfo, std::string &newIndex)
{
    return HKS_SUCCESS;
}

void HksRemoteHandleManager::ClearAuthState(const HksProcessInfo &processInfo)
{
    g_clearAuthStateCalled = true;
}

int32_t HksRemoteHandleManager::ParseAndValidateIndex(const std::string &index,
    const uint32_t uid, ProviderInfo &providerInfo, std::string &handle)
{
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetProviderProxy(const ProviderInfo &providerInfo,
    OHOS::sptr<IHuksAccessExtBase> &proxy)
{
    proxy = sptr<HuksAccessExtBaseStub>(new HksCryptoExtStubImpl());
    return HKS_SUCCESS;
}

void HksRemoteHandleManager::ClearMapByHandle(const int32_t &ret, const std::string &handle) {}

void HksRemoteHandleManager::ClearMapByUid(const uint32_t uid)
{
    g_clearMapByUidCalled = true;
    g_clearMapByUidArg = uid;
}

// ==================== HksSessionManager mock ====================
bool g_hksClearHandleCalled = false;
bool g_initSessionCalled = false;

void ResetSessionManagerMockFlags()
{
    g_hksClearHandleCalled = false;
    g_initSessionCalled = false;
}

std::shared_ptr<HksSessionManager> HksSessionManager::GetInstanceWrapper()
{
    return HksSessionManager::GetInstance();
}

void HksSessionManager::ReleaseInstance()
{
    HksSessionManager::DestroyInstance();
}

int32_t HksSessionManager::ExtensionInitSession(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle)
{
    g_initSessionCalled = true;
    handle = 100;
    return HKS_SUCCESS;
}

int32_t HksSessionManager::ExtensionUpdateSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    return HKS_SUCCESS;
}

int32_t HksSessionManager::ExtensionFinishSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    return HKS_SUCCESS;
}

int32_t HksSessionManager::ExtensionAbortSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

bool HksSessionManager::HksClearHandle(const HksProcessInfo &processInfo, const CppParamSet &paramSet)
{
    g_hksClearHandleCalled = true;
    return true;
}

void HksSessionManager::HksClearHandle(const ProviderInfo &providerInfo) {}

bool HksSessionManager::HksClearHandle(const HksProcessInfo &processInfo,
    const CppParamSet &paramSet, const std::string &index)
{
    return true;
}

void HksSessionManager::ClearSessionMapByHandle(int32_t ret, uint32_t handle) {}

} // namespace OHOS::Security::Huks
