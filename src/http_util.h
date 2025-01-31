#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <string>

//这不是类 只是存放一些普通函数的文件
//通过libcurl(libcurl4-openssl-dev)库来对url里面的文本进行下载
//只是用来下载订阅内容的...
std::string downloadFromURL(const std::string& url);

#endif

