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

Hy2Node::Hy2Node(std::string uuid, std::string addr, int port, std::string info,
                 std::string sni, std::string obfs, std::string obfs_password, bool insecure)
    : Node("hy2", uuid, addr, port, info), 
      sni(sni),
      obfs(obfs),
      obfs_password(obfs_password),
      insecure(insecure) {
}

Hy2Node* Hy2Node::parseFromUrl(const std::string& url) {
    // hysteria2://uuid@host:port?insecure=1&sni=example.com&obfs=salamander&obfs-password=123456#info
    std::regex hy2Regex(R"(hysteria2://([^@]+)@([^:]+):(\d+)\??([^#]*)(?:#(.*))?)", std::regex::ECMAScript);
    std::smatch match;

    if (!std::regex_match(url, match, hy2Regex)) {
        std::cerr << "无法解析节点: " << url.substr(0, 50) << "..." << std::endl;
        return nullptr;
    }

    std::string uuid = match[1].str();
    std::string addr = match[2].str();
    int port = std::stoi(match[3].str());
    std::string params = match[4].str();
    std::string info = match[5].str();

    // URL解码info (处理中文和特殊字符)
    info = urlDecode(info);

    // 默认设置
    std::string sni = addr; // 默认使用地址作为SNI
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
                
                // URL解码参数值
                value = urlDecode(value);

                if (key == "sni") {
                    sni = value;
                } else if (key == "obfs") {
                    obfs = value;
                } else if (key == "obfs-password") {
                    obfs_password = value;
                } else if (key == "insecure") {
                    insecure = (value == "1" || value == "true");
                }
            }
        }
    }

    // 创建节点
    Hy2Node* node = new Hy2Node(uuid, addr, port, info, sni, obfs, obfs_password, insecure);
    return node;
}

// URL解码函数
std::string Hy2Node::urlDecode(const std::string& encoded) {
    std::string result;
    char ch;
    int i, len = encoded.length();
    
    for (i = 0; i < len; i++) {
        if (encoded[i] == '%') {
            if (i + 2 < len) {
                std::string hex = encoded.substr(i + 1, 2);
                int value = 0;
                std::istringstream(hex) >> std::hex >> value;
                ch = static_cast<char>(value);
                result += ch;
                i += 2;
            }
        } else if (encoded[i] == '+') {
            result += ' ';
        } else {
            result += encoded[i];
        }
    }
    
    return result;
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