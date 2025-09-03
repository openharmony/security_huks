#include <string>
#include <unordered_map>

#include "hks_cpp_paramset.h"
#include <mutex>
// #include "safe_map.h"

enum class PluginMethodEnum{

};
// 在枚举里面去对应
std::string RegisterFunName = "_ZN27HksProviderLifeCycleManager18OnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERK11CppParamSet";



using RegisterFun = int32_t (*)(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet);

class HuksExtensionPluginManager{
private:
    void* m_pluginHandle = nullptr; // 存储 dlopen 返回的句柄
    static std::once_flag initFlag;
    std::unordered_map<std::string, RegisterFun>m_pluginProviderMap;
    //OHOS::SafeMap<std::string, std::shared_ptr<CrypoExtensionProxy>> m_pluginProviderMap;

    //CreateInstance()
   // GetInstance()
    int32_t LoadPlugins(const std::string& AbilityName);
    int32_t RecordPlugin();
    int32_t RemovePlugin();
    int32_t ExecutePlugin();

public:
    int32_t RegisterProvider(struct HksProcessInfo &info, const std::string &AbilityName,
    const CppParamSet& paramSet);
};
