#ifndef VLESSNODE_H
#define VLESSNODE_H
#include "Node.h"

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

    /* http2/
};

#endif
