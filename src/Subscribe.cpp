#include "Subscribe.h"
#include <string>

// 构造函数初始化列表
// 如果当前的订阅分组没有url 就用空字串代替 而不应该是空值
Subscribe::Subscribe(int id, const std::string& name, const std::string& url) : id(id), name(name), url(url) {}

// Getter 方法
int Subscribe::getId(void) const {
    return id;
}

std::string Subscribe::getName(void) const {
    return name;
}

std::string Subscribe::getUrl(void) const {
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

