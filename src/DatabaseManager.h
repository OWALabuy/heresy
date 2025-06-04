#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include <string>
#include <vector>
#include <sqlite3.h>
#include "Subscribe.h"
#include "Node.h"
#include "VlessNode.h"

class DatabaseManager {
private:
    sqlite3* db;
    std::string dbPath;

    // 初始化数据库表结构
    void initDatabase();

public:
    // 构造函数
    DatabaseManager(const std::string& dbPath = "~/.heresy/heresy.db");
    
    // 析构函数
    ~DatabaseManager();

    // 打开数据库连接
    bool open();
    
    // 关闭数据库连接
    void close();

    // 订阅相关操作
    bool addSubscribe(const Subscribe& subscribe);
    bool updateSubscribe(const Subscribe& subscribe);
    bool deleteSubscribe(int id);
    std::vector<Subscribe> getAllSubscribes();
    Subscribe getSubscribeById(int id);

    // 节点相关操作
    bool addNode(Node* node, int subscribeId);
    bool updateNode(Node* node);
    bool deleteNode(int id);
    bool deleteAllNodesInSubscribe(int subscribeId);
    std::vector<Node*> getAllNodes();
    std::vector<Node*> getNodesBySubscribeId(int subscribeId);
    Node* getNodeById(int id);
    
    // 其他辅助方法
    bool isTableEmpty(const std::string& tableName);
};

#endif 
