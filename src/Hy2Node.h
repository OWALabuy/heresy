#ifndef HY2NODE_H
#define HY2NODE_H
#include "Node.h"
#include <string>
#include <map>

/* hysteria2协议的节点的实体类
 * 父类Node已有以下几个属性...
    int id;  // 数据库的主键 在构造函数中可选 用于与数据库对接
    std::string protocol;  // 协议
    std::string uuid;      // 用户密码/认证字符串
    std::string addr;      // 地址(ip 域名)
    int port;              // 端口
    std::string info;  // 描述 像"美国凤凰城2-hy2"这样的文字信息
 */
class Hy2Node : public Node {
   private:
    // Hysteria2特有的字段
    std::string sni;
    std::string obfs;  // 混淆密码
    std::string obfs_password;
    bool insecure;  // 是否跳过证书验证

    // 额外参数
    std::map<std::string, std::string> extra_params;

    // URL解码工具函数
    static std::string urlDecode(const std::string& encoded);

   public:
    // 构造函数
    Hy2Node(std::string uuid, std::string addr, int port, std::string info,
           std::string sni = "", std::string obfs = "", std::string obfs_password = "", 
           bool insecure = false);

    // 从URL解析Hy2Node
    static Hy2Node* parseFromUrl(const std::string& url);

    // Getter和Setter
    std::string getSni() const;
    std::string getObfs() const;
    std::string getObfsPassword() const;
    bool getInsecure() const;
    std::string getExtraParam(const std::string& key) const;

    void setSni(const std::string& sni);
    void setObfs(const std::string& obfs);
    void setObfsPassword(const std::string& obfs_password);
    void setInsecure(bool insecure);
    void setExtraParam(const std::string& key, const std::string& value);

    // 生成Xray配置的JSON片段（实际使用Http代理到Hysteria2）
    std::string toXrayConfig() const;
};

#endif 