#ifndef VLESSNODE_H
#define VLESSNODE_H
#include "Node.h"
#include <string>
#include <map>

/* vless协议的节点的实体类
 字段标准按照https://github.com/XTLS/Xray-core/discussions/716设定
 * 父类Node已有以下几个属性...
    int id;  // 数据库的主键 在构造函数中可选 用于与数据库对接
    std::string protocol;  // 协议
    std::string uuid;      // 用户uuid
    std::string addr;      // 地址(ip 域名)
    int port;              // 端口
    std::string info;  // 描述 像"美国凤凰城2-vless"这样的文字信息
 * 所以我们只用写
    <protocol-specific fields>
    <transport-specific fields>
    <tls-specific fields>
 */
class VlessNode : public Node {
   private:
    // 协议相关段
    // 传输方式  有tcp kcp ws http grpc httpupgrade xhttp
    std::string type;

    /* 当协议为 VLESS 时，对应配置文件出站中 settings.encryption，当前可选值只有
     * none。 省略时默认为 none，但不可以为空字符串。
     */
    std::string encryption;

    // 传输层相关段
    /* 底层传输安全 可选none tls reality
     * 如果没有这个字段 默认为none
     */
    std::string security;

    /* 额外参数，存储各种可选的传输层设置，比如：
       - path: WebSocket路径
       - host: HTTP主机头
       - serviceName: gRPC服务名
       - sni: TLS服务器名称指示
       - alpn: 应用层协议协商
       等等
     */
    std::map<std::string, std::string> extra_params;

    // URL解码工具函数
    static std::string urlDecode(const std::string& encoded);

   public:
    // 构造函数
    VlessNode(std::string uuid, std::string addr, int port, std::string info,
             std::string type = "tcp", std::string encryption = "none", 
             std::string security = "none");

    // 从URL解析VlessNode
    static VlessNode* parseFromUrl(const std::string& url);

    // Getter和Setter
    std::string getType() const;
    std::string getEncryption() const;
    std::string getSecurity() const;
    std::string getExtraParam(const std::string& key) const;

    void setType(const std::string& type);
    void setEncryption(const std::string& encryption);
    void setSecurity(const std::string& security);
    void setExtraParam(const std::string& key, const std::string& value);

    // 生成Xray配置的JSON片段
    std::string toXrayConfig() const;
};

#endif
