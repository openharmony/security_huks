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

#include "hks_plugin_manager_test.h"
#include "hks_function_types.h"
#include <unordered_map>

using namespace testing::ext;

const std::string TEST_PROVIDER = "testProvider";

namespace OHOS {
namespace Security {
namespace Huks {
void ExtensionPluginMgrTest::SetUpTestCase(void) {
}

void ExtensionPluginMgrTest::TearDownTestCase(void) {
}

void ExtensionPluginMgrTest::SetUp() {
    HuksPluginLoader::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

void ExtensionPluginMgrTest::TearDown() {
    HuksPluginLoader::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest001
 * @tc.desc: 第一次注册，动态库加载成功且注册函数执行成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest001, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> g_genAesParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(g_genAesParams);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    std::string index = "";
    ret = mgr->OnCreateRemoteKeyHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnCreateRemoteKeyHandle fail";

    ret = mgr->OnCloseRemoteKeyHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnCloseRemoteKeyHandle fail";

    int32_t authState = 0;
    uint32_t retryCnt = 0;
    ret = mgr->OnAuthUkeyPin(processInfo, index, paramSet, authState, retryCnt);
    EXPECT_EQ(ret, 0) << "fail: OnAuthUkeyPin fail";

    int32_t state = 0;
    ret = mgr->OnGetVerifyPinStatus(processInfo, index, paramSet, state);
    EXPECT_EQ(ret, 0) << "fail: OnGetVerifyPinStatus fail";

    ret = mgr->OnClearUkeyPinAuthStatus(processInfo, index);
    EXPECT_EQ(ret, 0) << "fail: OnClearUkeyPinAuthStatus fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: UnRegisterProvider is not fail";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest002
 * @tc.desc: 第二次调用注册函数，register函数执行成功;非最后一次调用解注册函数，且函数执行成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest002, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> g_genAesParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(g_genAesParams);
    
    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    std::string TEST_PROVIDER2 = "testProvider2";
    ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER2, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";

    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER2, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest003
 * @tc.desc: 最后一次调用解注册函数，函数执行成功，且动态库关闭成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest003, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> g_genAesParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(g_genAesParams);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    std::string propertyId = "";
    CppParamSet outParams(g_genAesParams);
    const std::string index = "";
    ret = mgr->OnGetRemoteProperty(processInfo, index, propertyId, paramSet, outParams);
    EXPECT_EQ(ret, 0) << "fail: OnGetRemoteProperty fail";

    std::string certsJson = "";
    ret = mgr->OnExportCertificate(processInfo, index, paramSet, certsJson);
    EXPECT_EQ(ret, 0) << "fail: OnExportCertificate fail";

    std::string certsJsonArr = "";
    ret = mgr->OnExportProviderAllCertificates(processInfo, TEST_PROVIDER, paramSet, certsJsonArr);
    EXPECT_EQ(ret, 0) << "fail: OnExportProviderAllCertificates fail";

    uint32_t uhandle = 0;
    ret = mgr->OnInitSession(processInfo, index, paramSet, uhandle);
    EXPECT_EQ(ret, 0) << "fail: OnInitSession fail";

    std::vector<uint8_t> inData;
    std::vector<uint8_t> outData;
    ret = mgr->OnUpdateSession(processInfo, uhandle, paramSet, inData, outData);
    EXPECT_EQ(ret, 0) << "fail: OnUpdateSession fail";

    ret = mgr->OnFinishSession(processInfo, uhandle, paramSet, inData, outData);
    EXPECT_EQ(ret, 0) << "fail: OnUpdateSession fail";

    ret = mgr->OnAbortSession(processInfo, uhandle, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnAbortSession fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";

    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, HKS_ERROR_LIB_REPEAT_CLOSE) << "fail: unregist is not -298.";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest004
 * @tc.desc: 覆盖OnGenerateKey, OnImportWrappedKey, OnExportPublicKey, OnImportCertificate成功路径
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest004, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    const std::string index = "testIndex";

    // OnGenerateKey
    ret = mgr->OnGenerateKey(processInfo, index, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnGenerateKey fail";

    // OnExportPublicKey
    std::vector<uint8_t> outData;
    ret = mgr->OnExportPublicKey(processInfo, index, paramSet, outData);
    EXPECT_EQ(ret, 0) << "fail: OnExportPublicKey fail";

    // OnImportWrappedKey
    const std::string wrappingKeyIndex = "wrappingKey";
    std::vector<uint8_t> wrappedData = {0x01, 0x02, 0x03};
    ret = mgr->OnImportWrappedKey(processInfo, index, wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_EQ(ret, 0) << "fail: OnImportWrappedKey fail";

    // OnImportCertificate
    struct HksExtCertInfo certInfo {};
    uint8_t indexBuf[] = "certIndex";
    uint8_t certBuf[] = "certData";
    certInfo.purpose = 1;
    certInfo.index.size = sizeof(indexBuf);
    certInfo.index.data = indexBuf;
    certInfo.cert.size = sizeof(certBuf);
    certInfo.cert.data = certBuf;
    ret = mgr->OnImportCertificate(processInfo, index, certInfo, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnImportCertificate fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest005
 * @tc.desc: 未注册时调用On方法，m_pluginProviderMap.Find失败，返回HKS_ERROR_FIND_FUNC_MAP_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest005, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);
    const std::string index = "testIndex";

    // 不调用RegisterProvider，m_pluginProviderMap为空，Find应失败
    int ret = mgr->OnCreateRemoteKeyHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    ret = mgr->OnCloseRemoteKeyHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    int32_t authState = 0;
    uint32_t retryCnt = 0;
    ret = mgr->OnAuthUkeyPin(processInfo, index, paramSet, authState, retryCnt);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    int32_t state = 0;
    ret = mgr->OnGetVerifyPinStatus(processInfo, index, paramSet, state);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    ret = mgr->OnClearUkeyPinAuthStatus(processInfo, index);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    CppParamSet outParams(tmpParams);
    ret = mgr->OnGetRemoteProperty(processInfo, index, "propId", paramSet, outParams);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest006
 * @tc.desc: 未注册时调用session/key相关On方法，Find失败
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest006, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);
    const std::string index = "testIndex";

    std::string certsJson;
    int ret = mgr->OnExportCertificate(processInfo, index, paramSet, certsJson);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    std::string certsJsonArr;
    ret = mgr->OnExportProviderAllCertificates(processInfo, TEST_PROVIDER, paramSet, certsJsonArr);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    ret = mgr->OnGenerateKey(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    struct HksExtCertInfo certInfo {};
    ret = mgr->OnImportCertificate(processInfo, index, certInfo, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    uint32_t handle = 0;
    ret = mgr->OnInitSession(processInfo, index, paramSet, handle);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    std::vector<uint8_t> inData, outData;
    ret = mgr->OnUpdateSession(processInfo, handle, paramSet, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    ret = mgr->OnFinishSession(processInfo, handle, paramSet, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    ret = mgr->OnAbortSession(processInfo, handle, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    ret = mgr->OnImportWrappedKey(processInfo, index, "wrapKey", paramSet, inData);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";

    ret = mgr->OnExportPublicKey(processInfo, index, paramSet, outData);
    EXPECT_EQ(ret, HKS_ERROR_FIND_FUNC_MAP_FAIL) << "fail: should fail when not registered";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest007
 * @tc.desc: GetInstanceWrapper / ReleaseInstance 正常获取和释放实例
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest007, TestSize.Level0)
{
    auto loader = HuksPluginLoader::GetInstanceWrapper();
    EXPECT_NE(loader, nullptr) << "fail: loader should not be null";

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    EXPECT_NE(mgr, nullptr) << "fail: mgr should not be null";

    // 多次获取应为同一实例
    auto loader2 = HuksPluginLoader::GetInstanceWrapper();
    EXPECT_EQ(loader, loader2) << "fail: should be same instance";

    auto mgr2 = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    EXPECT_EQ(mgr, mgr2) << "fail: should be same instance";

    HuksPluginLoader::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest008
 * @tc.desc: UnRegisterProvider当refCount=0时返回HKS_ERROR_LIB_REPEAT_CLOSE
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest008, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);

    // 未注册就调用UnRegister，refCount为0
    bool isDeath = false;
    int ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, HKS_ERROR_LIB_REPEAT_CLOSE) << "fail: should return LIB_REPEAT_CLOSE";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest009
 * @tc.desc: 注册三个provider，逐个解注册，最后一次解注册关闭动态库
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest009, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);

    int ret = mgr->RegisterProvider(processInfo, "providerA", paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist providerA fail";

    ret = mgr->RegisterProvider(processInfo, "providerB", paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist providerB fail";

    ret = mgr->RegisterProvider(processInfo, "providerC", paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist providerC fail";

    // 注册后可以正常调用On方法
    const std::string index = "idx";
    ret = mgr->OnCreateRemoteKeyHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnCreateRemoteKeyHandle fail";

    // 解注册第一个，refCount从3到2，不应关闭动态库
    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, "providerA", paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist providerA fail";

    // 解注册第二个，refCount从2到1，不应关闭动态库
    ret = mgr->UnRegisterProvider(processInfo, "providerB", paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist providerB fail";

    // 解注册第三个，refCount从1到0，应关闭动态库
    ret = mgr->UnRegisterProvider(processInfo, "providerC", paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist providerC fail";

    // 再次解注册应返回HKS_ERROR_LIB_REPEAT_CLOSE
    ret = mgr->UnRegisterProvider(processInfo, "providerC", paramSet, isDeath);
    EXPECT_EQ(ret, HKS_ERROR_LIB_REPEAT_CLOSE) << "fail: should return LIB_REPEAT_CLOSE";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest010
 * @tc.desc: LoadPlugins时如果m_pluginHandle已不为空，直接返回HKS_SUCCESS（不重复加载）
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest010, TestSize.Level0)
{
    auto loader = HuksPluginLoader::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);

    // 第一次RegisterProvider会LoadPlugins
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: first regist fail";

    // 第二次RegisterProvider，m_pluginHandle != nullptr，LoadPlugins直接返回HKS_SUCCESS
    ret = mgr->RegisterProvider(processInfo, "provider2", paramSet);
    EXPECT_EQ(ret, 0) << "fail: second regist fail";

    // 清理
    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";
    ret = mgr->UnRegisterProvider(processInfo, "provider2", paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest011
 * @tc.desc: UnLoadPlugins当m_pluginHandle为nullptr时，直接返回HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest011, TestSize.Level0)
{
    auto loader = HuksPluginLoader::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);
    OHOS::SafeMap<PluginMethodEnum, void*> pluginProviderMap;

    // 新实例的m_pluginHandle为nullptr，UnLoadPlugins应直接返回HKS_SUCCESS
    int ret = loader->UnLoadPlugins(processInfo, TEST_PROVIDER, paramSet, pluginProviderMap);
    EXPECT_EQ(ret, HKS_SUCCESS) << "fail: UnLoadPlugins should return SUCCESS when handle is null";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest012
 * @tc.desc: 清空m_pluginMethodNameMap后调用LoadPlugins，GetMethodByEnum返回空，LoadPlugins返回失败
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest012, TestSize.Level0)
{
    // 创建loader实例（构造函数会填充m_pluginMethodNameMap）
    auto loader = HuksPluginLoader::GetInstanceWrapper();
    // 清空map，使GetMethodByEnum对所有enum都返回空字符串
    loader->m_pluginMethodNameMap.Clear();

    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);
    OHOS::SafeMap<PluginMethodEnum, void*> pluginProviderMap;

    // LoadPlugins会在循环中调用GetMethodByEnum，因map为空返回""，触发失败路径
    int ret = loader->LoadPlugins(processInfo, TEST_PROVIDER, paramSet, pluginProviderMap);
    EXPECT_NE(ret, HKS_SUCCESS) << "fail: LoadPlugins should fail when method name map is empty";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest013
 * @tc.desc: 清空m_pluginMethodNameMap后调用RegisterProvider，LoadPlugins失败导致RegisterProvider返回错误
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest013, TestSize.Level0)
{
    auto loader = HuksPluginLoader::GetInstanceWrapper();
    // 清空map使LoadPlugins失败
    loader->m_pluginMethodNameMap.Clear();

    HksProcessInfo processInfo {};
    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(tmpParams);

    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS) << "fail: RegisterProvider should fail when LoadPlugins fails";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest014
 * @tc.desc: 验证构造函数注册的map内容正确
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest014, TestSize.Level0)
{
    auto loader = HuksPluginLoader::GetInstanceWrapper();

    // 验证所有关键enum都已注册
    std::string method = "";
    bool isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_REGISTER_PROVIDER should be registered";
    EXPECT_FALSE(method.empty()) << "fail: method string should not be empty";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_CREATE_REMOTE_KEY_HANDLE should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_AUTH_UKEY_PIN should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_INIT_SESSION, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_INIT_SESSION should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_GENERATE_KEY, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_GENERATE_KEY should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_IMPORT_WRAPPED_KEY, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_IMPORT_WRAPPED_KEY should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_EXPORT_PUBLIC_KEY, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_EXPORT_PUBLIC_KEY should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_IMPORT_CERTIFICATE, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_IMPORT_CERTIFICATE should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_UNREGISTER_ALL_OBSERVERS, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_UNREGISTER_ALL_OBSERVERS should be registered";

    isFind = loader->m_pluginMethodNameMap.Find(PluginMethodEnum::FUNC_ON_ABORT_SESSION, method);
    EXPECT_TRUE(isFind) << "fail: FUNC_ON_ABORT_SESSION should be registered";

    // 验证不存在的enum返回false
    isFind = loader->m_pluginMethodNameMap.Find(static_cast<PluginMethodEnum>(9999), method);
    EXPECT_FALSE(isFind) << "fail: non-existent enum should not be found";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest015
 * @tc.desc: 多次创建和销毁实例，验证构造函数和ReleaseInstance正确工作
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest015, TestSize.Level0)
{
    // 反复创建和销毁，验证无崩溃且每次构造函数正确执行
    for (int i = 0; i < 3; i++) {
        auto loader = HuksPluginLoader::GetInstanceWrapper();
        EXPECT_NE(loader, nullptr) << "fail: loader instance should not be null";

        auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
        EXPECT_NE(mgr, nullptr) << "fail: mgr instance should not be null";

        // 每次获取后map应该有内容
        EXPECT_FALSE(loader->m_pluginMethodNameMap.Empty()) << "fail: method name map should not be empty";

        HuksPluginLoader::ReleaseInstance();
        HuksPluginLifeCycleMgr::ReleaseInstance();
    }
}
}
}
}