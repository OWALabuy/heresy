#include "Node.h"
#include <string>

// 构造函数
// 这里没有id这个参数 从url文本处理产生的节点信息没有这个属性
// 而来自数据库的节点数据则有这个属性 所以构造函数默认是不填入这个参数的
// 来自数据库的节点信息创建的节点对象就再调用一下setId()来把这个数据塞进去...反正这些都是存放在数据库中的
// 这个类(及它的子类)所创建的对象只不过是运送数据的桥梁罢了
Node::Node(std::string protocol, std::string uuid, std::string addr, int port,
           std::string info)
    : protocol(protocol), uuid(uuid), addr(addr), port(port), info(info) {}

//getter和setter
    int Node::getId(void){
        return id;
    }
    std::string Node::getProtocol(void){
        return protocol;
    }
    std::string Node::getUuid(void){
        return uuid;
    }
    std::string Node::getAddr(void){
        return addr;
    }
    int Node::getPort(void){
        return port;
    }
    std::string Node::getInfo(void){
        return info;
    }
    void Node::setId(int id){
        this->id = id;
    }
    void Node::setProtocol(std::string protocol){
        this->protocol = protocol;
    }
    void Node::setAddr(std::string addr){
        this->addr = addr;
    }
    void Node::setPort(int port){
        this->port = port;
    }
    void Node::setInfo(std::string info){
        this->info = info;
    }
