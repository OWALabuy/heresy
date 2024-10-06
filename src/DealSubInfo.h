#ifndef DEALSUBINFO_H
#define DEALSUBINFO_H
#include <string>
#include <vector>

class DealSubInfo {
private:
    //机场订阅链接
    std::string subLink;

    //下载得到的base64节点信息
    std::string base64NodeInfo;

    //base64解码后放在这里 是一个数组 一行为一个节点信息
    std::pmr::vector<std::string> nodeInfo;

public:
    //构造函数
    DealSubInfo();

    //获取订阅链接存放到私有变量中的函数
    void getSubLink();

    //下载订阅信息放在 base64NodeInfo中
    void downloadNodeInfo();

    //解码base64节点信息并将其塞入数组
    void decodeAndPutNodeInfo();

    
};

#endif
