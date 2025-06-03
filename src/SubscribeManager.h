/*
 * 我这是要干什么...好好思考一下这个类有什么功能吧
 * 这个类是对订阅分组做的控制类 当然所有的功能都是通过静态的方法来实现的 它们的参数的数据类型是Subscribe 也就是那个实体类
 * 以下是这个类的功能
 * 从url下载base64格式的订阅内容 得到一个string 里面包含所有的节点信息(不需要在这写 因为之前已经写了一个函数)
 * 对那个字符串进行base64解码 得到一行一个的节点信息
 * 对每个节点进行分析 将它们的粗略要素提取出来(协议 地址 端口号 uuid 别名) 根据协议来调用对应的分析方法 把它们弄成一个node对象 然后弄进数据库去
 *
 * 主要就是分析解码的操作 先写更新函数好了
 */
#ifndef SUBSCRIBEMANAGER_H
#define SUBSCRIBEMANAGER_H

#include "Subscribe.h"

class SubscribeManager{
    public:
        static void update(Subscribe subscribe);
};

#endif
