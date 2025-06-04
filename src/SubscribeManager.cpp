#include "SubscribeManager.h"
#include <iostream>
#include <sstream>
#include <string>
#include <regex>
#include "Node.h"
#include "Subscribe.h"
#include "http_util.h"
#include "base64.h"
#include "VlessNode.h"
#include "VmessNode.h"
#include "TrojanNode.h"
#include "Hy2Node.h"
#include "DatabaseManager.h"

//更新订阅的函数
void SubscribeManager::update(Subscribe subscribe) {
    //提取出它的订阅链接
    std::string url = subscribe.getUrl();

    //对链接进行检查 如果它是空 就退出
    if(url.empty()) {
        std::cout << "此订阅分组无法更新：无链接" << std::endl;
        return;
    }

    //用包装好的下载工具下载这个url 得到base64编码后的节点信息
    std::string base64_sub = downloadFromURL(url);
    if(base64_sub.empty()) {
        std::cout << "下载订阅内容失败，请检查网络连接或订阅链接" << std::endl;
        return;
    }

    //用base64解码得到多行字符串
    std::string decode_sub = base64_decode(base64_sub);
    if(decode_sub.empty()) {
        std::cout << "解码订阅内容失败，可能不是有效的base64编码" << std::endl;
        return;
    }

    // 打开数据库连接
    DatabaseManager dbManager;
    if (!dbManager.open()) {
        std::cout << "无法打开数据库，更新订阅失败" << std::endl;
        return;
    }

    // 先删除该订阅下的所有节点
    dbManager.deleteAllNodesInSubscribe(subscribe.getId());

    //对刚刚的字符串进行逐行的解析
    std::istringstream stream(decode_sub);
    std::string line;
    //用来截取协议字段的正则表达式
    std::regex protocolReg(R"(^([a-zA-Z0-9]+)://)");
    std::smatch match;

    int success_count = 0;
    int failed_count = 0;

    //跑个循环把每行东西拎出来 根据它的协议 扔给对应协议的处理器
    while (std::getline(stream, line)) {
        if(std::regex_search(line, match, protocolReg)) {
            //取得协议
            std::string protocol = match[1].str();

            //调用处理器把这一行的节点内容转换成对应协议的节点对象
            Node* node = nullptr;

            if (protocol == "vless") {
                node = VlessNode::parseFromUrl(line);
            } else if (protocol == "vmess") {
                node = VmessNode::parseFromUrl(line);
            } else if (protocol == "trojan") {
                node = TrojanNode::parseFromUrl(line);
            } else if (protocol == "hy2") {
                node = Hy2Node::parseFromUrl(line);
            }

            if (node) {
                // 添加到数据库
                if (dbManager.addNode(node, subscribe.getId())) {
                    success_count++;
                } else {
                    failed_count++;
                }
                
                // 释放内存
                delete node;
            } else {
                std::cout << "无法解析节点: " << line.substr(0, 50) << "..." << std::endl;
                failed_count++;
            }
        }
    }

    std::cout << "订阅更新完成，成功导入节点：" << success_count 
              << "，失败节点：" << failed_count << std::endl;
}
