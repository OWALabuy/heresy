#ifndef CLI_H
#define CLI_H

#include <string>
#include <vector>
#include <memory>
#include "DatabaseManager.h"
#include "ConfigManager.h"
#include "SubscribeManager.h"

class CLI {
private:
    std::unique_ptr<DatabaseManager> dbManager;
    std::unique_ptr<ConfigManager> configManager;
    
    // 当前选中的节点ID
    int currentNodeId;
    
    // 显示主菜单
    void showMainMenu();
    
    // 显示订阅管理菜单
    void showSubscribeMenu();
    
    // 显示节点管理菜单
    void showNodeMenu();
    
    // 显示代理控制菜单
    void showProxyMenu();
    
    // 添加订阅
    void addSubscribe();
    
    // 列出所有订阅
    void listSubscribes();
    
    // 更新订阅
    void updateSubscribe();
    
    // 删除订阅
    void deleteSubscribe();
    
    // 列出所有节点
    void listNodes();
    
    // 选择节点
    void selectNode();
    
    // 测试节点延迟
    void testNodeLatency();
    
    // 启动代理
    void startProxy();
    
    // 停止代理
    void stopProxy();
    
    // 设置系统代理
    void setProxy(bool enable);
    
    // 辅助方法：获取用户输入
    std::string getUserInput(const std::string& prompt);
    
    // 辅助方法：获取用户输入的数字
    int getUserInputNumber(const std::string& prompt);
    
public:
    CLI();
    
    // 运行CLI界面
    void run();
};

#endif 
