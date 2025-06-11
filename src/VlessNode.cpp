#include "VlessNode.h"
#include <iostream>
#include <regex>
#include <sstream>
#include <nlohmann/json.hpp>
#include "base64.h"

using json = nlohmann::json;

VlessNode::VlessNode(std::string uuid, std::string addr, int port, std::string info,
                     std::string type, std::string encryption, std::string security)
    : Node("vless", uuid, addr, port, info), 
      type(type), 
      encryption(encryption), 
      security(security) {
}

VlessNode* VlessNode::parseFromUrl(const std::string& url) {
    // vless://uuid@addr:port?type=tcp&encryption=none&security=none#info
    std::regex vlessRegex(R"(vless://([^@]+)@([^:]+):(\d+)\??([^#]*)(?:#(.*))?)", std::regex::ECMAScript);
    std::smatch match;

    if (!std::regex_match(url, match, vlessRegex)) {
        std::cerr << "不是有效的VLESS URL: " << url << std::endl;
        return nullptr;
    }

    std::string uuid = match[1].str();
    std::string addr = match[2].str();
    int port = std::stoi(match[3].str());
    std::string params = match[4].str();
    std::string info = match[5].str();

    // URL解码info (处理中文和特殊字符)
    info = urlDecode(info);

    // 使用默认值创建节点
    VlessNode* node = new VlessNode(uuid, addr, port, info);

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

                if (key == "type") {
                    node->setType(value);
                } else if (key == "encryption") {
                    node->setEncryption(value);
                } else if (key == "security") {
                    node->setSecurity(value);
                } else if (key == "flow") {
                    node->setExtraParam("flow", value);
                } else if (key == "sni") {
                    node->setExtraParam("sni", value);
                } else if (key == "pbk" || key == "publicKey") {
                    node->setExtraParam("pbk", value);
                } else if (key == "sid" || key == "shortId") {
                    node->setExtraParam("sid", value);
                } else if (key == "fp" || key == "fingerprint") {
                    node->setExtraParam("fp", value);
                } else if (key == "host") {
                    node->setExtraParam("host", value);
                } else if (key == "path") {
                    node->setExtraParam("path", value);
                } else if (key == "alpn") {
                    node->setExtraParam("alpn", value);
                } else if (key == "headerType") {
                    node->setExtraParam("headerType", value);
                } else if (key == "quicSecurity") {
                    node->setExtraParam("quicSecurity", value);
                } else if (key == "serviceName") {
                    node->setExtraParam("serviceName", value);
                } else {
                    // 存储其他参数
                    node->setExtraParam(key, value);
                }
            }
        }
    }

    return node;
}

// URL解码函数
std::string VlessNode::urlDecode(const std::string& encoded) {
    std::string result;
    char ch;
    int i, j, len = encoded.length();
    
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

std::string VlessNode::getType() const {
    return type;
}

std::string VlessNode::getEncryption() const {
    return encryption;
}

std::string VlessNode::getSecurity() const {
    return security;
}

std::string VlessNode::getExtraParam(const std::string& key) const {
    auto it = extra_params.find(key);
    if (it != extra_params.end()) {
        return it->second;
    }
    return "";
}

void VlessNode::setType(const std::string& type) {
    this->type = type;
}

void VlessNode::setEncryption(const std::string& encryption) {
    this->encryption = encryption;
}

void VlessNode::setSecurity(const std::string& security) {
    this->security = security;
}

void VlessNode::setExtraParam(const std::string& key, const std::string& value) {
    extra_params[key] = value;
}

std::string VlessNode::toXrayConfig() const {
    json outbound = {
        {"protocol", "vless"},
        {"settings", {
            {"vnext", json::array({
                {
                    {"address", getAddr()},
                    {"port", getPort()},
                    {"users", json::array({
                        {
                            {"id", getUuid()},
                            {"encryption", getEncryption()}
                        }
                    })}
                }
            })}
        }},
        {"streamSettings", {
            {"network", getType()},
            {"security", getSecurity()}
        }},
        {"tag", "proxy"}
    };

    // 添加传输特定配置
    json& streamSettings = outbound["streamSettings"];
    
    if (getType() == "ws") {
        streamSettings["wsSettings"] = {
            {"path", getExtraParam("path")}
        };
        if (!getExtraParam("host").empty()) {
            streamSettings["wsSettings"]["headers"] = {
                {"Host", getExtraParam("host")}
            };
        }
    } else if (getType() == "grpc") {
        streamSettings["grpcSettings"] = {
            {"serviceName", getExtraParam("serviceName")}
        };
    } else if (getType() == "http") {
        streamSettings["httpSettings"] = {
            {"path", getExtraParam("path")}
        };
        if (!getExtraParam("host").empty()) {
            json hosts = json::array();
            hosts.push_back(getExtraParam("host"));
            streamSettings["httpSettings"]["host"] = hosts;
        }
    }

    // 添加TLS配置
    if (getSecurity() == "tls") {
        streamSettings["tlsSettings"] = json::object();
        if (!getExtraParam("sni").empty()) {
            streamSettings["tlsSettings"]["serverName"] = getExtraParam("sni");
        }
        if (!getExtraParam("alpn").empty()) {
            json alpn = json::array();
            alpn.push_back(getExtraParam("alpn"));
            streamSettings["tlsSettings"]["alpn"] = alpn;
        }
    } else if (getSecurity() == "reality") {
        streamSettings["realitySettings"] = {
            {"publicKey", getExtraParam("pbk")},
            {"shortId", getExtraParam("sid")}
        };
        if (!getExtraParam("sni").empty()) {
            streamSettings["realitySettings"]["serverName"] = getExtraParam("sni");
        }
        if (!getExtraParam("fp").empty()) {
            streamSettings["realitySettings"]["fingerprint"] = getExtraParam("fp");
        }
    }

    return outbound.dump(4);
}
