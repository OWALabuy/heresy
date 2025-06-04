#include "TrojanNode.h"
#include <iostream>
#include <regex>
#include <sstream>
#include <nlohmann/json.hpp>
#include "base64.h"

using json = nlohmann::json;

TrojanNode::TrojanNode(std::string password, std::string addr, int port, std::string info,
                     std::string sni, std::string type)
    : Node("trojan", password, addr, port, info), 
      sni(sni),
      type(type) {
}

TrojanNode* TrojanNode::parseFromUrl(const std::string& url) {
    // Trojan链接格式：trojan://password@server:port?sni=domain.com#info
    std::regex trojanRegex(R"(trojan://([^@]+)@([^:]+):(\d+)\??([^#]*)#?(.*))");
    std::smatch match;

    if (!std::regex_match(url, match, trojanRegex)) {
        std::cerr << "不是有效的Trojan URL: " << url << std::endl;
        return nullptr;
    }

    std::string password = match[1].str();
    std::string addr = match[2].str();
    int port = std::stoi(match[3].str());
    std::string params = match[4].str();
    std::string info = match[5].str();

    // 默认SNI使用addr
    std::string sni = addr;
    std::string type = "tcp";  // 默认tcp

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
                } else if (key == "type") {
                    type = value;
                }
                // 存储其他参数
            }
        }
    }

    TrojanNode* node = new TrojanNode(password, addr, port, info, sni, type);
    return node;
}

std::string TrojanNode::getSni() const {
    return sni;
}

std::string TrojanNode::getType() const {
    return type;
}

std::string TrojanNode::getExtraParam(const std::string& key) const {
    auto it = extra_params.find(key);
    if (it != extra_params.end()) {
        return it->second;
    }
    return "";
}

void TrojanNode::setSni(const std::string& sni) {
    this->sni = sni;
}

void TrojanNode::setType(const std::string& type) {
    this->type = type;
}

void TrojanNode::setExtraParam(const std::string& key, const std::string& value) {
    extra_params[key] = value;
}

std::string TrojanNode::toXrayConfig() const {
    json outbound = {
        {"protocol", "trojan"},
        {"settings", {
            {"servers", json::array({
                {
                    {"address", getAddr()},
                    {"port", getPort()},
                    {"password", getUuid()},  // 在trojan中，uuid字段存储的是密码
                    {"level", 0}
                }
            })}
        }},
        {"streamSettings", {
            {"network", getType()},
            {"security", "tls"},
            {"tlsSettings", {
                {"serverName", getSni()}
            }}
        }},
        {"tag", "proxy"}
    };

    // 处理不同的传输方式
    json& streamSettings = outbound["streamSettings"];
    
    if (getType() == "ws") {
        json wsSettings = json::object();
        
        if (!getExtraParam("path").empty()) {
            wsSettings["path"] = getExtraParam("path");
        }
        
        if (!getExtraParam("host").empty()) {
            wsSettings["headers"] = {
                {"Host", getExtraParam("host")}
            };
        }
        
        streamSettings["wsSettings"] = wsSettings;
    } else if (getType() == "grpc") {
        json grpcSettings = json::object();
        
        if (!getExtraParam("serviceName").empty()) {
            grpcSettings["serviceName"] = getExtraParam("serviceName");
        }
        
        streamSettings["grpcSettings"] = grpcSettings;
    }
    
    return outbound.dump(4);
} 