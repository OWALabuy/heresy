#include "ConfigManager.h"
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <string>
#include <thread>
#include <chrono>
#include "VlessNode.h"
#include "VmessNode.h"
#include "TrojanNode.h"
#include "Hy2Node.h"
#include "DatabaseManager.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>
#include <cstring>
#endif

namespace fs = std::filesystem;

ConfigManager::ConfigManager(const std::string& configDir) {
    // 处理路径中的~符号，指向用户主目录
    if (configDir.substr(0, 1) == "~") {
        const char* home = std::getenv("HOME");
        if (home) {
            this->configDir = std::string(home) + configDir.substr(1);
        } else {
            this->configDir = configDir;
        }
    } else {
        this->configDir = configDir;
    }
    
    // 确保目录存在
    fs::path dir = fs::path(this->configDir);
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }
    
    this->xrayConfigPath = this->configDir + "xray_config.json";
}

json ConfigManager::defaultRoutingRules() {
    // 这里可以根据需要自定义路由规则
    json routing = {
        {"domainStrategy", "IPIfNonMatch"},
        {"rules", json::array({
            {
                {"type", "field"},
                {"outboundTag", "direct"},
                {"domain", json::array({
                    "domain:baidu.com",
                    "domain:qq.com",
                    "domain:bilibili.com",
                    "geosite:cn"
                })}
            },
            {
                {"type", "field"},
                {"outboundTag", "direct"},
                {"ip", json::array({
                    "geoip:private",
                    "geoip:cn"
                })}
            },
            {
                {"type", "field"},
                {"port", "53"},
                {"network", "udp"},
                {"outboundTag", "dns-out"}
            }
        })}
    };
    
    return routing;
}

json ConfigManager::defaultInbounds() {
    json inbounds = json::array({
        {
            {"tag", "socks-in"},
            {"port", 10808},
            {"listen", "127.0.0.1"},
            {"protocol", "socks"},
            {"settings", {
                {"auth", "noauth"},
                {"udp", true},
                {"ip", "127.0.0.1"}
            }},
            {"sniffing", {
                {"enabled", true},
                {"destOverride", json::array({"http", "tls"})}
            }}
        },
        {
            {"tag", "http-in"},
            {"port", 10809},
            {"listen", "127.0.0.1"},
            {"protocol", "http"},
            {"settings", {
                {"auth", "noauth"},
                {"udp", true},
                {"ip", "127.0.0.1"}
            }},
            {"sniffing", {
                {"enabled", true},
                {"destOverride", json::array({"http", "tls"})}
            }}
        }
    });
    
    return inbounds;
}

json ConfigManager::generateOutbound(const Node* node) {
    if (node->getProtocol() == "vless") {
        const VlessNode* vlessNode = static_cast<const VlessNode*>(node);
        // 转换为JSON，获取配置片段
        std::string configStr = vlessNode->toXrayConfig();
        json outbound = json::parse(configStr);
        return outbound;
    } else if (node->getProtocol() == "vmess") {
        const VmessNode* vmessNode = static_cast<const VmessNode*>(node);
        // 转换为JSON，获取配置片段
        std::string configStr = vmessNode->toXrayConfig();
        json outbound = json::parse(configStr);
        return outbound;
    } else if (node->getProtocol() == "trojan") {
        const TrojanNode* trojanNode = static_cast<const TrojanNode*>(node);
        // 转换为JSON，获取配置片段
        std::string configStr = trojanNode->toXrayConfig();
        json outbound = json::parse(configStr);
        return outbound;
    } else if (node->getProtocol() == "hy2") {
        const Hy2Node* hy2Node = static_cast<const Hy2Node*>(node);
        // 转换为JSON，获取配置片段
        std::string configStr = hy2Node->toXrayConfig();
        json outbound = json::parse(configStr);
        return outbound;
    } else {
        // 默认情况，创建一个通用的出站配置
        json outbound = {
            {"protocol", node->getProtocol()},
            {"settings", {}},
            {"tag", "proxy"}
        };
        return outbound;
    }
}

bool ConfigManager::generateXrayConfig(const Node* node) {
    if (!node) {
        std::cerr << "节点为空，无法生成配置" << std::endl;
        return false;
    }
    
    try {
        // 创建基本配置
        json config = {
            {"log", {
                {"loglevel", "warning"}
            }},
            {"inbounds", defaultInbounds()},
            {"outbounds", json::array({
                generateOutbound(node),
                {
                    {"protocol", "freedom"},
                    {"tag", "direct"},
                    {"settings", {}}
                },
                {
                    {"protocol", "blackhole"},
                    {"tag", "block"},
                    {"settings", {}}
                },
                {
                    {"protocol", "dns"},
                    {"tag", "dns-out"}
                }
            })},
            {"routing", defaultRoutingRules()}
        };
        
        // 写入配置文件
        std::ofstream configFile(xrayConfigPath);
        if (!configFile.is_open()) {
            std::cerr << "无法打开配置文件进行写入: " << xrayConfigPath << std::endl;
            return false;
        }
        
        configFile << config.dump(4);
        configFile.close();
        
        std::cout << "已生成配置文件: " << xrayConfigPath << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "生成配置文件时出错: " << e.what() << std::endl;
        return false;
    }
}

std::string ConfigManager::getXrayConfigPath() const {
    return xrayConfigPath;
}

bool ConfigManager::setSystemProxy(bool enable, int port) {
#ifdef _WIN32
    // Windows系统代理设置
    std::string command;
    if (enable) {
        command = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 1 /f";
        system(command.c_str());
        
        command = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer /t REG_SZ /d 127.0.0.1:" + std::to_string(port) + " /f";
        system(command.c_str());
    } else {
        command = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 0 /f";
        system(command.c_str());
    }
    return true;
#else
    // Linux系统代理设置
    std::string command;
    if (enable) {
        // 设置HTTP代理
        command = "gsettings set org.gnome.system.proxy mode 'manual'";
        system(command.c_str());
        
        command = "gsettings set org.gnome.system.proxy.http host '127.0.0.1'";
        system(command.c_str());
        
        command = "gsettings set org.gnome.system.proxy.http port " + std::to_string(port);
        system(command.c_str());
        
        // 设置HTTPS代理
        command = "gsettings set org.gnome.system.proxy.https host '127.0.0.1'";
        system(command.c_str());
        
        command = "gsettings set org.gnome.system.proxy.https port " + std::to_string(port);
        system(command.c_str());
        
        // 设置SOCKS代理
        command = "gsettings set org.gnome.system.proxy.socks host '127.0.0.1'";
        system(command.c_str());
        
        command = "gsettings set org.gnome.system.proxy.socks port " + std::to_string(port - 1); // SOCKS端口通常是HTTP端口-1
        system(command.c_str());
    } else {
        command = "gsettings set org.gnome.system.proxy mode 'none'";
        system(command.c_str());
    }
    return true;
#endif
}

bool ConfigManager::isXrayRunning() {
#ifdef _WIN32
    // Windows检查进程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }
    
    do {
        if (strcmp(pe32.szExeFile, "xray.exe") == 0) {
            CloseHandle(hSnapshot);
            return true;
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return false;
#else
    // Linux检查进程
    FILE* fp = popen("pgrep -x xray", "r");
    if (fp == NULL) {
        return false;
    }
    
    char path[1035];
    bool found = false;
    
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        found = true;
        break;
    }
    
    pclose(fp);
    return found;
#endif
}

bool ConfigManager::startXray(const std::string& xrayPath) {
    if (isXrayRunning()) {
        std::cout << "Xray已经在运行中" << std::endl;
        return true;
    }
    
    // 如果当前节点是Hysteria2，需要先启动Hysteria2
    Node* node = nullptr;
    DatabaseManager dbManager;
    if (dbManager.open()) {
        // 这里应该根据应用程序中保存的当前节点ID来获取节点
        // 为简单起见，我们将假设数据库中的第一个节点就是当前选中的节点
        std::vector<Node*> nodes = dbManager.getAllNodes();
        if (!nodes.empty()) {
            Node* currentNode = nodes[0];
            if (currentNode && currentNode->getProtocol() == "hy2") {
                std::string home = std::getenv("HOME") ? std::getenv("HOME") : ".";
                std::string configDir = home + "/.heresy/";
                std::string hy2ConfigPath = configDir + "hy2_config.yaml";
                
                // 启动Hysteria2
                std::string hy2Command;
#ifdef _WIN32
                hy2Command = "start /b hysteria-windows-amd64.exe -c " + hy2ConfigPath + " > nul 2>&1";
#else
                hy2Command = "hysteria -c " + hy2ConfigPath + " > /dev/null 2>&1 &";
#endif
                system(hy2Command.c_str());
                
                // 给Hysteria2一些启动时间
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            
            // 释放内存
            for (auto node : nodes) {
                delete node;
            }
        }
    }
    
#ifdef _WIN32
    // Windows启动进程
    std::string command = "start /b " + xrayPath + " -c " + xrayConfigPath;
    system(command.c_str());
#else
    // Linux启动进程
    std::string command = xrayPath + " -c " + xrayConfigPath + " > /dev/null 2>&1 &";
    system(command.c_str());
#endif
    
    // 稍微等待一下，确保进程启动
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    return isXrayRunning();
}

bool ConfigManager::stopXray() {
    // 先停止Xray
    if (!isXrayRunning()) {
        std::cout << "Xray未在运行" << std::endl;
        return true;
    }
    
#ifdef _WIN32
    // Windows停止进程
    system("taskkill /f /im xray.exe");
    
    // 检查是否有Hysteria2在运行，如果有也停止它
    system("taskkill /f /im hysteria-windows-amd64.exe");
#else
    // Linux停止进程
    system("pkill -x xray");
    
    // 检查是否有Hysteria2在运行，如果有也停止它
    system("pkill -x hysteria");
#endif
    
    // 稍微等待一下，确保进程已停止
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    return !isXrayRunning();
} 