#include "Hy2Node.h"
#include <iostream>
#include <regex>
#include <sstream>
#include <nlohmann/json.hpp>
#include "base64.h"
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

Hy2Node::Hy2Node(std::string auth, std::string addr, int port, std::string info,
                 std::string sni, std::string obfs, std::string obfs_password, bool insecure)
    : Node("hy2", auth, addr, port, info), 
      sni(sni),
      obfs(obfs),
      obfs_password(obfs_password),
      insecure(insecure) {
}

Hy2Node* Hy2Node::parseFromUrl(const std::string& url) {
    // Hysteria2链接格式：hy2://auth@server:port?sni=xxx&obfs=salamander&obfs-password=xxx#info
    std::regex hy2Regex(R"(hy2://([^@]+)@([^:]+):(\d+)\??([^#]*)#?(.*))");
    std::smatch match;

    if (!std::regex_match(url, match, hy2Regex)) {
        std::cerr << "不是有效的Hysteria2 URL: " << url << std::endl;
        return nullptr;
    }

    std::string auth = match[1].str();
    std::string addr = match[2].str();
    int port = std::stoi(match[3].str());
    std::string params = match[4].str();
    std::string info = match[5].str();

    // 默认值
    std::string sni = addr;
    std::string obfs = "";
    std::string obfs_password = "";
    bool insecure = false;

    // 解析参数
    if (!params.empty()) {
        std::stringstream ss(params);
        std::string param;

        while (std::getline(ss, param, '&')) {
            size_t pos = param.find('=');
            if (pos != std::string::npos) {
                std::string key = param.substr(0, pos);
                std::string value = param.substr(pos + 1);

                if (key == "sni") {
                    sni = value;
                } else if (key == "obfs") {
                    obfs = value;
                } else if (key == "obfs-password") {
                    obfs_password = value;
                } else if (key == "insecure") {
                    insecure = (value == "1" || value == "true");
                } else {
                    // 存储其他参数
                }
            }
        }
    }

    Hy2Node* node = new Hy2Node(auth, addr, port, info, sni, obfs, obfs_password, insecure);
    return node;
}

std::string Hy2Node::getSni() const {
    return sni;
}

std::string Hy2Node::getObfs() const {
    return obfs;
}

std::string Hy2Node::getObfsPassword() const {
    return obfs_password;
}

bool Hy2Node::getInsecure() const {
    return insecure;
}

std::string Hy2Node::getExtraParam(const std::string& key) const {
    auto it = extra_params.find(key);
    if (it != extra_params.end()) {
        return it->second;
    }
    return "";
}

void Hy2Node::setSni(const std::string& sni) {
    this->sni = sni;
}

void Hy2Node::setObfs(const std::string& obfs) {
    this->obfs = obfs;
}

void Hy2Node::setObfsPassword(const std::string& obfs_password) {
    this->obfs_password = obfs_password;
}

void Hy2Node::setInsecure(bool insecure) {
    this->insecure = insecure;
}

void Hy2Node::setExtraParam(const std::string& key, const std::string& value) {
    extra_params[key] = value;
}

std::string Hy2Node::toXrayConfig() const {
    // 生成Hysteria2配置文件
    std::string home = std::getenv("HOME") ? std::getenv("HOME") : ".";
    std::string configDir = home + "/.heresy/";
    
    // 确保目录存在
    fs::path dir = fs::path(configDir);
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }
    
    std::string hy2ConfigPath = configDir + "hy2_config.yaml";
    
    // 生成Hysteria2配置文件
    std::ofstream hy2ConfigFile(hy2ConfigPath);
    if (hy2ConfigFile.is_open()) {
        hy2ConfigFile << "server: " << getAddr() << ":" << getPort() << std::endl;
        hy2ConfigFile << "auth: " << getUuid() << std::endl;
        hy2ConfigFile << "sni: " << getSni() << std::endl;
        
        if (!getObfs().empty()) {
            hy2ConfigFile << "obfs: " << getObfs() << std::endl;
        }
        
        if (!getObfsPassword().empty()) {
            hy2ConfigFile << "obfs-password: " << getObfsPassword() << std::endl;
        }
        
        if (getInsecure()) {
            hy2ConfigFile << "insecure: true" << std::endl;
        }
        
        hy2ConfigFile << "http: " << std::endl;
        hy2ConfigFile << "  listen: 127.0.0.1:10998" << std::endl;
        hy2ConfigFile << "socks5: " << std::endl;
        hy2ConfigFile << "  listen: 127.0.0.1:10999" << std::endl;
        
        hy2ConfigFile.close();
    }
    
    // 使用XRay的出站规则连接到Hysteria2的本地端口
    json outbound = {
        {"protocol", "http"},
        {"settings", {
            {"servers", json::array({
                {
                    {"address", "127.0.0.1"},
                    {"port", 10998}
                }
            })}
        }},
        {"tag", "proxy"}
    };
    
    return outbound.dump(4);
} 