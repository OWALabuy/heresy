#ifndef NODE_H
#define NODE_H
#include <string>
// 节点信息 与机场提供的链接相对应上
// 这个是抽象类 不能实体化的...各协议的节点信息都有不同的地方
// 这个类只是抽象出了他们共有的属性
// vmess vless hy2 trojan ss/ssr 都要写单独的类 继承这个类
// 每个协议的url内容都不一样 到时候再处理好了 太难了aaa
class Node {
   private:
    int id;  // 数据库的主键 在构造函数中可选 用于与数据库对接
    std::string protocol;  // 协议
    std::string uuid;      // 用户uuid
    std::string addr;      // 地址(ip 域名)
    int port;              // 端口
    std::string info;  // 描述 像"美国凤凰城2-vless"这样的文字信息
   public:
    //构造函数
    Node(std::string protocol, std::string uuid, std::string addr, int port,
         std::string info);

    // getter和setter
    int getId(void) const;
    std::string getProtocol(void) const;
    std::string getUuid(void) const;
    std::string getAddr(void) const;
    int getPort(void) const;
    std::string getInfo(void) const;
    void setId(int id);
    void setProtocol(std::string protocol);
    void setAddr(std::string addr);
    void setPort(int port);
    void setInfo(std::string info);
};
#endif
