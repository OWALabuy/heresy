#include "CLI.h"
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <fmt/core.h>
#include <fmt/color.h>
#include "VlessNode.h"
#include "VmessNode.h"
#include "TrojanNode.h"
#include "Hy2Node.h"

#ifdef _WIN32
#include <windows.h>
#endif

CLI::CLI() : currentNodeId(-1) {
    dbManager = std::make_unique<DatabaseManager>();
    configManager = std::make_unique<ConfigManager>();
    
    // 打开数据库连接
    if (!dbManager->open()) {
        fmt::print(fg(fmt::color::red), "无法打开数据库，程序将退出\n");
        exit(1);
    }
    
#ifdef _WIN32
    // 在Windows平台上设置控制台为UTF-8编码
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
}

void CLI::run() {
    while (true) {
        showMainMenu();
        
        int choice = getUserInputNumber("请选择操作：");
        
        switch (choice) {
            case 1:
                showSubscribeMenu();
                break;
            case 2:
                showNodeMenu();
                break;
            case 3:
                showProxyMenu();
                break;
            case 0:
                fmt::print("退出程序...\n");
                return;
            default:
                fmt::print(fg(fmt::color::red), "无效的选择，请重试\n");
                break;
        }
    }
}

void CLI::showMainMenu() {
    fmt::print(fg(fmt::color::cyan), "\n===== HERESY 异端 =====\n");
    fmt::print("1. 订阅管理\n");
    fmt::print("2. 节点管理\n");
    fmt::print("3. 代理控制\n");
    fmt::print("0. 退出程序\n");
    
    // 显示当前状态
    fmt::print(fg(fmt::color::yellow), "\n当前状态：\n");
    
    if (currentNodeId > 0) {
        Node* node = dbManager->getNodeById(currentNodeId);
        if (node) {
            fmt::print("当前节点: {}\n", node->getInfo());
            delete node;
        } else {
            fmt::print("当前节点: 未选择\n");
        }
    } else {
        fmt::print("当前节点: 未选择\n");
    }
    
    fmt::print("Xray状态: {}\n", configManager->isXrayRunning() ? "运行中" : "已停止");
}

void CLI::showSubscribeMenu() {
    while (true) {
        fmt::print(fg(fmt::color::cyan), "\n===== 订阅管理 =====\n");
        fmt::print("1. 添加订阅\n");
        fmt::print("2. 列出所有订阅\n");
        fmt::print("3. 更新订阅\n");
        fmt::print("4. 删除订阅\n");
        fmt::print("0. 返回主菜单\n");
        
        int choice = getUserInputNumber("请选择操作：");
        
        switch (choice) {
            case 1:
                addSubscribe();
                break;
            case 2:
                listSubscribes();
                break;
            case 3:
                updateSubscribe();
                break;
            case 4:
                deleteSubscribe();
                break;
            case 0:
                return;
            default:
                fmt::print(fg(fmt::color::red), "无效的选择，请重试\n");
                break;
        }
    }
}

void CLI::showNodeMenu() {
    while (true) {
        fmt::print(fg(fmt::color::cyan), "\n===== 节点管理 =====\n");
        fmt::print("1. 列出所有节点\n");
        fmt::print("2. 选择节点\n");
        fmt::print("3. 测试节点延迟\n");
        fmt::print("0. 返回主菜单\n");
        
        int choice = getUserInputNumber("请选择操作：");
        
        switch (choice) {
            case 1:
                listNodes();
                break;
            case 2:
                selectNode();
                break;
            case 3:
                testNodeLatency();
                break;
            case 0:
                return;
            default:
                fmt::print(fg(fmt::color::red), "无效的选择，请重试\n");
                break;
        }
    }
}

void CLI::showProxyMenu() {
    while (true) {
        fmt::print(fg(fmt::color::cyan), "\n===== 代理控制 =====\n");
        fmt::print("1. 启动代理\n");
        fmt::print("2. 停止代理\n");
        fmt::print("3. 开启系统代理\n");
        fmt::print("4. 关闭系统代理\n");
        fmt::print("0. 返回主菜单\n");
        
        int choice = getUserInputNumber("请选择操作：");
        
        switch (choice) {
            case 1:
                startProxy();
                break;
            case 2:
                stopProxy();
                break;
            case 3:
                setProxy(true);
                break;
            case 4:
                setProxy(false);
                break;
            case 0:
                return;
            default:
                fmt::print(fg(fmt::color::red), "无效的选择，请重试\n");
                break;
        }
    }
}

void CLI::addSubscribe() {
    std::string name = getUserInput("请输入订阅名称：");
    std::string url = getUserInput("请输入订阅链接：");
    
    // 确保输入不为空
    if (name.empty()) {
        fmt::print(fg(fmt::color::red), "订阅名称不能为空\n");
        return;
    }
    
    if (url.empty()) {
        fmt::print(fg(fmt::color::red), "订阅链接不能为空\n");
        return;
    }
    
    Subscribe subscribe(-1, name, url);
    if (dbManager->addSubscribe(subscribe)) {
        fmt::print(fg(fmt::color::green), "添加订阅成功\n");
        
        // 询问是否立即更新订阅
        std::string choice = getUserInput("是否立即更新订阅？(y/n)：");
        if (choice == "y" || choice == "Y") {
            // 获取刚添加的订阅ID
            auto subscribes = dbManager->getAllSubscribes();
            for (const auto& s : subscribes) {
                if (s.getName() == name && s.getUrl() == url) {
                    SubscribeManager::update(s);
                    break;
                }
            }
        }
    } else {
        fmt::print(fg(fmt::color::red), "添加订阅失败\n");
    }
}

void CLI::listSubscribes() {
    auto subscribes = dbManager->getAllSubscribes();
    
    if (subscribes.empty()) {
        fmt::print(fg(fmt::color::yellow), "没有找到任何订阅\n");
        return;
    }
    
    fmt::print(fg(fmt::color::cyan), "\n===== 订阅列表 =====\n");
    fmt::print("{:<5} {:<20} {:<50}\n", "ID", "名称", "链接");
    
    for (const auto& subscribe : subscribes) {
        // 截断过长的链接，以防止显示问题
        std::string url = subscribe.getUrl();
        if (url.length() > 47) {
            url = url.substr(0, 44) + "...";
        }
        
        fmt::print("{:<5} {:<20} {:<50}\n", 
                 subscribe.getId(), 
                 subscribe.getName(), 
                 url);
    }
}

void CLI::updateSubscribe() {
    listSubscribes();
    
    int id = getUserInputNumber("请输入要更新的订阅ID（0取消）：");
    
    if (id == 0) {
        return;
    }
    
    Subscribe subscribe = dbManager->getSubscribeById(id);
    
    if (subscribe.getId() == 0) {
        fmt::print(fg(fmt::color::red), "未找到该订阅\n");
        return;
    }
    
    fmt::print("正在更新订阅: {}\n", subscribe.getName());
    SubscribeManager::update(subscribe);
    fmt::print(fg(fmt::color::green), "更新订阅完成\n");
}

void CLI::deleteSubscribe() {
    listSubscribes();
    
    int id = getUserInputNumber("请输入要删除的订阅ID（0取消）：");
    
    if (id == 0) {
        return;
    }
    
    if (dbManager->deleteSubscribe(id)) {
        fmt::print(fg(fmt::color::green), "删除订阅成功\n");
    } else {
        fmt::print(fg(fmt::color::red), "删除订阅失败\n");
    }
}

void CLI::listNodes() {
    auto nodes = dbManager->getAllNodes();
    
    if (nodes.empty()) {
        fmt::print(fg(fmt::color::yellow), "没有找到任何节点\n");
        return;
    }
    
    fmt::print(fg(fmt::color::cyan), "\n===== 节点列表 =====\n");
    fmt::print("{:<5} {:<15} {:<25} {:<10} {:<5} {:<15}\n", "ID", "协议", "地址", "端口", "状态", "别名");
    
    for (const auto& node : nodes) {
        std::string status = (node->getId() == currentNodeId) ? "当前" : "";
        fmt::print("{:<5} {:<15} {:<25} {:<10} {:<5} {:<15}\n", 
                 node->getId(), node->getProtocol(), node->getAddr(), 
                 node->getPort(), status, node->getInfo());
    }
    
    // 释放内存
    for (auto node : nodes) {
        delete node;
    }
}

void CLI::selectNode() {
    listNodes();
    
    int id = getUserInputNumber("请输入要选择的节点ID（0取消）：");
    
    if (id == 0) {
        return;
    }
    
    Node* node = dbManager->getNodeById(id);
    
    if (!node) {
        fmt::print(fg(fmt::color::red), "未找到该节点\n");
        return;
    }
    
    // 生成配置文件
    if (configManager->generateXrayConfig(node)) {
        fmt::print(fg(fmt::color::green), "已生成配置文件\n");
        currentNodeId = id;
    } else {
        fmt::print(fg(fmt::color::red), "生成配置文件失败\n");
    }
    
    delete node;
}

void CLI::testNodeLatency() {
    listNodes();
    
    int id = getUserInputNumber("请输入要测试的节点ID（0取消）：");
    
    if (id == 0) {
        return;
    }
    
    Node* node = dbManager->getNodeById(id);
    
    if (!node) {
        fmt::print(fg(fmt::color::red), "未找到该节点\n");
        return;
    }
    
    fmt::print("正在测试节点 {} 的延迟...\n", node->getInfo());
    
    // 简单的ping测试
    std::string command = "ping -c 3 " + node->getAddr();
    
#ifdef _WIN32
    command = "ping -n 3 " + node->getAddr();
#endif
    
    system(command.c_str());
    delete node;
}

void CLI::startProxy() {
    if (currentNodeId < 0) {
        fmt::print(fg(fmt::color::red), "请先选择一个节点\n");
        return;
    }
    
    if (configManager->isXrayRunning()) {
        fmt::print(fg(fmt::color::yellow), "Xray已经在运行中\n");
        return;
    }
    
    if (configManager->startXray()) {
        fmt::print(fg(fmt::color::green), "成功启动Xray\n");
    } else {
        fmt::print(fg(fmt::color::red), "启动Xray失败\n");
    }
}

void CLI::stopProxy() {
    if (!configManager->isXrayRunning()) {
        fmt::print(fg(fmt::color::yellow), "Xray未在运行\n");
        return;
    }
    
    if (configManager->stopXray()) {
        fmt::print(fg(fmt::color::green), "成功停止Xray\n");
    } else {
        fmt::print(fg(fmt::color::red), "停止Xray失败\n");
    }
}

void CLI::setProxy(bool enable) {
    if (enable && !configManager->isXrayRunning()) {
        fmt::print(fg(fmt::color::yellow), "警告：Xray未运行，开启系统代理可能无效\n");
        std::string choice = getUserInput("是否继续？(y/n)：");
        if (choice != "y" && choice != "Y") {
            return;
        }
    }
    
    if (configManager->setSystemProxy(enable)) {
        if (enable) {
            fmt::print(fg(fmt::color::green), "成功开启系统代理\n");
        } else {
            fmt::print(fg(fmt::color::green), "成功关闭系统代理\n");
        }
    } else {
        if (enable) {
            fmt::print(fg(fmt::color::red), "开启系统代理失败\n");
        } else {
            fmt::print(fg(fmt::color::red), "关闭系统代理失败\n");
        }
    }
}

std::string CLI::getUserInput(const std::string& prompt) {
    std::string input;
    fmt::print("{}", prompt);
    std::getline(std::cin, input);
    return input;
}

int CLI::getUserInputNumber(const std::string& prompt) {
    while (true) {
        std::string input = getUserInput(prompt);
        try {
            return std::stoi(input);
        } catch (...) {
            fmt::print(fg(fmt::color::red), "请输入有效的数字\n");
        }
    }
} 
