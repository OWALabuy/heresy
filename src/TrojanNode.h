#ifndef TROJANNODE_H
#define TROJANNODE_H
#include "Node.h"
#include <string>
#include <map>

/* trojan协议的节点的实体类
 * 父类Node已有以下几个属性...
    int id;  // 数据库的主键 在构造函数中可选 用于与数据库对接
    std::string protocol;  // 协议
    std::string uuid;      // 用户uuid/密码
    std::string addr;      // 地址(ip 域名)
    int port;              // 端口
    std::string info;  // 描述 像"美国凤凰城2-trojan"这样的文字信息
 */
class TrojanNode : public Node {
   private:
    // 额外参数
    std::string sni;  // SNI
    std::string type;  // 传输方式，默认为tcp
    std::map<std::string, std::string> extra_params;

   public:
    // 构造函数
    TrojanNode(std::string password, std::string addr, int port, std::string info,
              std::string sni = "", std::string type = "tcp");

    // 从URL解析TrojanNode
    static TrojanNode* parseFromUrl(const std::string& url);

    // Getter和Setter
    std::string getSni() const;
    std::string getType() const;
    std::string getExtraParam(const std::string& key) const;

    void setSni(const std::string& sni);
    void setType(const std::string& type);
    void setExtraParam(const std::string& key, const std::string& value);

    // 生成Xray配置的JSON片段
    std::string toXrayConfig() const;
};

#endif 