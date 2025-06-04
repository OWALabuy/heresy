#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <filesystem>
#include "Node.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class ConfigManager {
private:
    std::string configDir;
    std::string xrayConfigPath;
    
    // 默认的路由规则
    json defaultRoutingRules();
    
    // 默认的入站设置
    json defaultInbounds();
    
    // 根据节点生成出站设置
    json generateOutbound(const Node* node);
    
public:
    // 构造函数
    ConfigManager(const std::string& configDir = "~/.heresy/");
    
    // 生成并保存Xray配置文件
    bool generateXrayConfig(const Node* node);
    
    // 获取Xray配置文件路径
    std::string getXrayConfigPath() const;
    
    // 设置系统代理
    bool setSystemProxy(bool enable, int port = 10809);
    
    // 检查Xray进程状态
    bool isXrayRunning();
    
    // 启动Xray
    bool startXray(const std::string& xrayPath = "xray");
    
    // 停止Xray
    bool stopXray();
};

#endif 