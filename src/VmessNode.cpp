#include "VmessNode.h"
#include <iostream>
#include <regex>
#include <sstream>
#include <nlohmann/json.hpp>
#include "base64.h"

using json = nlohmann::json;

VmessNode::VmessNode(std::string uuid, std::string addr, int port, std::string info,
                     int alterId, std::string security, std::string type, std::string tls)
    : Node("vmess", uuid, addr, port, info), 
      alterId(alterId), 
      security(security),
      type(type),
      tls(tls) {
}

VmessNode* VmessNode::parseFromUrl(const std::string& url) {
    // VMess链接格式：vmess://base64编码的json
    // 首先检查前缀
    if (url.substr(0, 8) != "vmess://") {
        std::cerr << "不是有效的VMess URL: " << url << std::endl;
        return nullptr;
    }
    
    // 提取base64部分并解码
    std::string base64_str = url.substr(8);
    std::string json_str = base64_decode(base64_str);
    
    try {
        // 解析JSON
        json vmess_json = json::parse(json_str);
        
        // 提取必要字段
        std::string uuid = vmess_json.value("id", "");
        std::string addr = vmess_json.value("add", "");
        int port = vmess_json.value("port", 0);
        std::string ps = vmess_json.value("ps", "");
        int aid = vmess_json.value("aid", 0);
        std::string security = vmess_json.value("scy", "auto");  // 默认auto
        std::string net = vmess_json.value("net", "tcp");        // 默认tcp
        std::string tls = vmess_json.value("tls", "");
        
        // 检查必要字段
        if (uuid.empty() || addr.empty() || port == 0) {
            std::cerr << "VMess节点缺少必要字段" << std::endl;
            return nullptr;
        }
        
        // 创建VMess节点
        VmessNode* node = new VmessNode(uuid, addr, port, ps, aid, security, net, tls);
        
        // 设置额外参数
        if (vmess_json.contains("host")) {
            node->setExtraParam("host", vmess_json["host"]);
        }
        
        if (vmess_json.contains("path")) {
            node->setExtraParam("path", vmess_json["path"]);
        }
        
        if (vmess_json.contains("alpn")) {
            node->setExtraParam("alpn", vmess_json["alpn"]);
        }
        
        if (vmess_json.contains("sni")) {
            node->setExtraParam("sni", vmess_json["sni"]);
        }
        
        return node;
    } catch (const std::exception& e) {
        std::cerr << "解析VMess URL失败: " << e.what() << std::endl;
        return nullptr;
    }
}

int VmessNode::getAlterId() const {
    return alterId;
}

std::string VmessNode::getSecurity() const {
    return security;
}

std::string VmessNode::getType() const {
    return type;
}

std::string VmessNode::getTls() const {
    return tls;
}

std::string VmessNode::getExtraParam(const std::string& key) const {
    auto it = extra_params.find(key);
    if (it != extra_params.end()) {
        return it->second;
    }
    return "";
}

void VmessNode::setAlterId(int alterId) {
    this->alterId = alterId;
}

void VmessNode::setSecurity(const std::string& security) {
    this->security = security;
}

void VmessNode::setType(const std::string& type) {
    this->type = type;
}

void VmessNode::setTls(const std::string& tls) {
    this->tls = tls;
}

void VmessNode::setExtraParam(const std::string& key, const std::string& value) {
    extra_params[key] = value;
}

std::string VmessNode::toXrayConfig() const {
    json outbound = {
        {"protocol", "vmess"},
        {"settings", {
            {"vnext", json::array({
                {
                    {"address", getAddr()},
                    {"port", getPort()},
                    {"users", json::array({
                        {
                            {"id", getUuid()},
                            {"alterId", getAlterId()},
                            {"security", getSecurity()}
                        }
                    })}
                }
            })}
        }},
        {"streamSettings", {
            {"network", getType()}
        }},
        {"tag", "proxy"}
    };
    
    // 添加TLS配置
    json& streamSettings = outbound["streamSettings"];
    
    if (!getTls().empty()) {
        streamSettings["security"] = getTls();
        json tlsSettings = json::object();
        
        if (!getExtraParam("sni").empty()) {
            tlsSettings["serverName"] = getExtraParam("sni");
        }
        
        if (!getExtraParam("alpn").empty()) {
            json alpn = json::array();
            std::istringstream iss(getExtraParam("alpn"));
            std::string alpn_item;
            while (std::getline(iss, alpn_item, ',')) {
                alpn.push_back(alpn_item);
            }
            tlsSettings["alpn"] = alpn;
        }
        
        streamSettings["tlsSettings"] = tlsSettings;
    }
    
    // 添加传输方式配置
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
    } else if (getType() == "http") {
        json httpSettings = json::object();
        
        if (!getExtraParam("path").empty()) {
            httpSettings["path"] = getExtraParam("path");
        }
        
        if (!getExtraParam("host").empty()) {
            json hosts = json::array();
            std::istringstream iss(getExtraParam("host"));
            std::string host_item;
            while (std::getline(iss, host_item, ',')) {
                hosts.push_back(host_item);
            }
            httpSettings["host"] = hosts;
        }
        
        streamSettings["httpSettings"] = httpSettings;
    } else if (getType() == "kcp") {
        json kcpSettings = {{"header", {{"type", getExtraParam("headerType")}}}};
        streamSettings["kcpSettings"] = kcpSettings;
    } else if (getType() == "quic") {
        json quicSettings = {
            {"security", getExtraParam("quicSecurity")},
            {"key", getExtraParam("key")},
            {"header", {{"type", getExtraParam("headerType")}}}
        };
        streamSettings["quicSettings"] = quicSettings;
    }
    
    return outbound.dump(4);
} 