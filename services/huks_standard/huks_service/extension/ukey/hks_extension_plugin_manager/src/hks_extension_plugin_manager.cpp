#include "hks_extension_plugin_manager.h"

std::once_flag HuksExtensionPluginManager::initFlag;

int32_t HuksExtensionPluginManager::RegisterProvider(struct HksProcessInfo &info, const std::string& AbilityName,
    const CppParamSet& paramSet){
    int32_t ret = -2;

    // 使用 std::call_once 来确保初始化逻辑只执行一次
    std::call_once(initFlag, [this, &AbilityName, &ret]() {
        ret = this->LoadPlugins(AbilityName); // 执行初始化
    });
    // 如果初始化失败，每次调用都返回错误码
    if (ret != HKS_SUCCESS) {
        // 记录日志：初始化失败
        return ret;
    }

    // 后续调用（包括第一次初始化成功后的调用）的实际业务逻辑
    // 例如：根据 AbilityName 从 map 中查找函数指针并调用
    auto it = m_pluginProviderMap.find(AbilityName);
    if (it != m_pluginProviderMap.end()) {
        RegisterFun funcPtr = reinterpret_cast<RegisterFun>(it->second);
        if (funcPtr != nullptr) {
            return funcPtr(info, AbilityName, paramSet); // 调用动态库中的函数
        }
    }
    // 没有找到对应的函数指针，返回错误
    return -1;
}

int32_t HuksExtensionPluginManager::LoadPlugins(const std::string& AbilityName){

}