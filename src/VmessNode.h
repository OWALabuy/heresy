#ifndef VMESSNODE_H
#define VMESSNODE_H
#include "Node.h"
#include <string>
#include <map>

/* vmess协议的节点的实体类
 * 父类Node已有以下几个属性...
    int id;  // 数据库的主键 在构造函数中可选 用于与数据库对接
    std::string protocol;  // 协议
    std::string uuid;      // 用户uuid
    std::string addr;      // 地址(ip 域名)
    int port;              // 端口
    std::string info;  // 描述 像"美国凤凰城2-vmess"这样的文字信息
 */
class VmessNode : public Node {
   private:
    // 协议相关段
    int alterId;  // alterID
    std::string security;  // 加密方式 auto, aes-128-gcm, chacha20-poly1305, none 等

    // 传输方式  有tcp kcp ws http grpc httpupgrade quic 等
    std::string type;

    // 传输层安全
    std::string tls;  // tls 或 空

    // 额外参数
    std::map<std::string, std::string> extra_params;

   public:
    // 构造函数
    VmessNode(std::string uuid, std::string addr, int port, std::string info,
             int alterId = 0, std::string security = "auto", 
             std::string type = "tcp", std::string tls = "");

    // 从URL解析VmessNode (vmess://base64)
    static VmessNode* parseFromUrl(const std::string& url);

    // Getter和Setter
    int getAlterId() const;
    std::string getSecurity() const;
    std::string getType() const;
    std::string getTls() const;
    std::string getExtraParam(const std::string& key) const;

    void setAlterId(int alterId);
    void setSecurity(const std::string& security);
    void setType(const std::string& type);
    void setTls(const std::string& tls);
    void setExtraParam(const std::string& key, const std::string& value);

    // 生成Xray配置的JSON片段
    std::string toXrayConfig() const;
};

#endif 