#include "SubscribeManager.h"
#include <iostream>
#include <sstream>
#include <string>
#include <regex>
#include "Node.h"
#include "Subscribe.h"
#include "http_util.h"
#include "base64.h"

//更新订阅的函数
void SubscribeManager::update(Subscribe subscribe){
    //提取出它的订阅链接
    std::string url = subscribe.getUrl();

    //对链接进行检查 如果它是空 就退出
    if(url.empty())
    {
        std::cout << "此订阅分组无法更新：无链接" << std::endl;
    }

    //用包装好的下载工具下载这个url 得到base64编码后的节点信息
    std::string base64_sub = downloadFromURL(url);

    //用base64解码得到多行字符串
    std::string decode_sub = base64_decode(base64_sub);

    //对刚刚的字符串进行逐行的解析
    std::istringstream stream(decode_sub);
    std::string line;
    //用来截取协议字段的正则表达式
    std::regex protocolReg(R"(^([a-zA-Z0-9]+)://)");
    std::smatch match;

    //跑个循环把每行东西拎出来 根据它的协议 扔给对应协议的处理器（我还没写那处理器）
    while (std::getline(stream, line)) {
        if(std::regex_match(line, match, protocolReg)){
            //取得协议
            std::string protocol = match[1].str();

            //调用处理器把这一行的节点内容转换成对应协议的节点对象
            //当然现在还没写...
        }
    }
}
