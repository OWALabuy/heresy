#include "Subscribe.h"
#include <string>

// 构造函数初始化列表
Subscribe::Subscribe(int id, const std::string& name, const std::string& url) : id(id), name(name), url(url) {}

// Getter 方法
int Subscribe::getId(void) {
    return id;
}

std::string Subscribe::getName(void) {
    return name;
}

std::string Subscribe::getUrl(void) {
    return url;
}

// Setter 方法
void Subscribe::setId(int id) {
    this->id = id;
}

void Subscribe::setName(std::string name) {
    this->name = name;
}

void Subscribe::setUrl(std::string url) {
    this->url = url;
}

