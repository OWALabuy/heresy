#include "DatabaseManager.h"
#include <iostream>
#include <filesystem>
#include <cstdlib>
#include "VlessNode.h"
#include "VmessNode.h"
#include "TrojanNode.h"
#include "Hy2Node.h"

namespace fs = std::filesystem;

DatabaseManager::DatabaseManager(const std::string& dbPath) : db(nullptr) {
    // 处理路径中的~符号，指向用户主目录
    if (dbPath.substr(0, 1) == "~") {
        const char* home = std::getenv("HOME");
        if (home) {
            this->dbPath = std::string(home) + dbPath.substr(1);
        } else {
            this->dbPath = dbPath;
        }
    } else {
        this->dbPath = dbPath;
    }
    
    // 确保目录存在
    fs::path dir = fs::path(this->dbPath).parent_path();
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }
}

DatabaseManager::~DatabaseManager() {
    close();
}

bool DatabaseManager::open() {
    int rc = sqlite3_open(dbPath.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "无法打开数据库: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        db = nullptr;
        return false;
    }
    
    // 初始化数据库表结构
    initDatabase();
    
    return true;
}

void DatabaseManager::close() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}

void DatabaseManager::initDatabase() {
    const char* createSubscribeTable = R"(
        CREATE TABLE IF NOT EXISTS subscribes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL
        );
    )";
    
    const char* createNodeTable = R"(
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscribe_id INTEGER,
            protocol TEXT NOT NULL,
            uuid TEXT NOT NULL,
            addr TEXT NOT NULL,
            port INTEGER NOT NULL,
            info TEXT,
            type TEXT,
            encryption TEXT,
            security TEXT,
            extra_params TEXT,
            FOREIGN KEY (subscribe_id) REFERENCES subscribes (id) ON DELETE CASCADE
        );
    )";
    
    char* errMsg = nullptr;
    sqlite3_exec(db, createSubscribeTable, nullptr, nullptr, &errMsg);
    if (errMsg) {
        std::cerr << "创建订阅表错误: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    
    sqlite3_exec(db, createNodeTable, nullptr, nullptr, &errMsg);
    if (errMsg) {
        std::cerr << "创建节点表错误: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

bool DatabaseManager::addSubscribe(const Subscribe& subscribe) {
    const char* sql = "INSERT INTO subscribes (name, url) VALUES (?, ?);";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    // 绑定参数时使用SQLITE_TRANSIENT，确保SQLite会复制字符串
    sqlite3_bind_text(stmt, 1, subscribe.getName().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, subscribe.getUrl().c_str(), -1, SQLITE_TRANSIENT);
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

bool DatabaseManager::updateSubscribe(const Subscribe& subscribe) {
    const char* sql = "UPDATE subscribes SET name = ?, url = ? WHERE id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    // 使用SQLITE_TRANSIENT确保SQLite会复制字符串
    sqlite3_bind_text(stmt, 1, subscribe.getName().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, subscribe.getUrl().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, subscribe.getId());
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

bool DatabaseManager::deleteSubscribe(int id) {
    // 首先删除该订阅下的所有节点
    deleteAllNodesInSubscribe(id);
    
    const char* sql = "DELETE FROM subscribes WHERE id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, id);
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

std::vector<Subscribe> DatabaseManager::getAllSubscribes() {
    std::vector<Subscribe> subscribes;
    const char* sql = "SELECT id, name, url FROM subscribes;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return subscribes;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        // 检查列是否为NULL
        std::string name = "";
        std::string url = "";
        
        if (sqlite3_column_text(stmt, 1) != nullptr) {
            name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        }
        
        if (sqlite3_column_text(stmt, 2) != nullptr) {
            url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        }
        
        subscribes.emplace_back(id, name, url);
    }
    
    sqlite3_finalize(stmt);
    return subscribes;
}

Subscribe DatabaseManager::getSubscribeById(int id) {
    const char* sql = "SELECT id, name, url FROM subscribes WHERE id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return Subscribe(0, "", "");
    }
    
    sqlite3_bind_int(stmt, 1, id);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int dbId = sqlite3_column_int(stmt, 0);
        std::string name = "";
        std::string url = "";
        
        if (sqlite3_column_text(stmt, 1) != nullptr) {
            name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        }
        
        if (sqlite3_column_text(stmt, 2) != nullptr) {
            url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        }
        
        sqlite3_finalize(stmt);
        return Subscribe(dbId, name, url);
    }
    
    sqlite3_finalize(stmt);
    return Subscribe(0, "", "");
}

bool DatabaseManager::addNode(Node* node, int subscribeId) {
    const char* sql = "INSERT INTO nodes (subscribe_id, protocol, uuid, addr, port, info, type, encryption, security, extra_params) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, subscribeId);
    sqlite3_bind_text(stmt, 2, node->getProtocol().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, node->getUuid().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, node->getAddr().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, node->getPort());
    sqlite3_bind_text(stmt, 6, node->getInfo().c_str(), -1, SQLITE_STATIC);
    
    // 针对不同类型节点的额外属性
    if (node->getProtocol() == "vless") {
        VlessNode* vlessNode = static_cast<VlessNode*>(node);
        sqlite3_bind_text(stmt, 7, vlessNode->getType().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, vlessNode->getEncryption().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, vlessNode->getSecurity().c_str(), -1, SQLITE_STATIC);
        
        // 简单处理，后面可以改进为JSON格式
        sqlite3_bind_text(stmt, 10, "", -1, SQLITE_STATIC);
    } else {
        // 其他协议节点的处理
        sqlite3_bind_text(stmt, 7, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 10, "", -1, SQLITE_STATIC);
    }
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    if (result) {
        // 设置节点ID为最后插入的ID
        node->setId(sqlite3_last_insert_rowid(db));
    }
    
    return result;
}

bool DatabaseManager::updateNode(Node* node) {
    const char* sql = "UPDATE nodes SET protocol = ?, uuid = ?, addr = ?, port = ?, info = ?, type = ?, encryption = ?, security = ?, extra_params = ? WHERE id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, node->getProtocol().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node->getUuid().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, node->getAddr().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, node->getPort());
    sqlite3_bind_text(stmt, 5, node->getInfo().c_str(), -1, SQLITE_STATIC);
    
    // 针对不同类型节点的额外属性
    if (node->getProtocol() == "vless") {
        VlessNode* vlessNode = static_cast<VlessNode*>(node);
        sqlite3_bind_text(stmt, 6, vlessNode->getType().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, vlessNode->getEncryption().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, vlessNode->getSecurity().c_str(), -1, SQLITE_STATIC);
        
        // 简单处理，后面可以改进为JSON格式
        sqlite3_bind_text(stmt, 9, "", -1, SQLITE_STATIC);
    } else {
        // 其他协议节点的处理
        sqlite3_bind_text(stmt, 6, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, "", -1, SQLITE_STATIC);
    }
    
    sqlite3_bind_int(stmt, 10, node->getId());
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

bool DatabaseManager::deleteNode(int id) {
    const char* sql = "DELETE FROM nodes WHERE id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, id);
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

bool DatabaseManager::deleteAllNodesInSubscribe(int subscribeId) {
    const char* sql = "DELETE FROM nodes WHERE subscribe_id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, subscribeId);
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

std::vector<Node*> DatabaseManager::getAllNodes() {
    std::vector<Node*> nodes;
    const char* sql = "SELECT id, protocol, uuid, addr, port, info, type, encryption, security, extra_params FROM nodes;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return nodes;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char* protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* uuid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* addr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        int port = sqlite3_column_int(stmt, 4);
        const char* info = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        
        Node* node = nullptr;
        std::string protocolStr(protocol ? protocol : "");
        
        if (protocolStr == "vless") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* encryption = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* security = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            VlessNode* vlessNode = new VlessNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                type ? type : "tcp",
                encryption ? encryption : "none",
                security ? security : "none"
            );
            
            vlessNode->setId(id);
            node = vlessNode;
        } else if (protocolStr == "vmess") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* security = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* tls = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            VmessNode* vmessNode = new VmessNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                0,  // alterId，默认为0
                security ? security : "auto",
                type ? type : "tcp",
                tls ? tls : ""
            );
            
            vmessNode->setId(id);
            node = vmessNode;
        } else if (protocolStr == "trojan") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* sni = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            
            TrojanNode* trojanNode = new TrojanNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                sni ? sni : addr ? addr : "",
                type ? type : "tcp"
            );
            
            trojanNode->setId(id);
            node = trojanNode;
        } else if (protocolStr == "hy2") {
            const char* sni = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* obfs = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* obfs_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            Hy2Node* hy2Node = new Hy2Node(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                sni ? sni : addr ? addr : "",
                obfs ? obfs : "",
                obfs_password ? obfs_password : "",
                false  // insecure
            );
            
            hy2Node->setId(id);
            node = hy2Node;
        } else {
            node = new Node(
                protocolStr,
                uuid ? uuid : "",
                addr ? addr : "",
                port,
                info ? info : ""
            );
            node->setId(id);
        }
        
        nodes.push_back(node);
    }
    
    sqlite3_finalize(stmt);
    return nodes;
}

std::vector<Node*> DatabaseManager::getNodesBySubscribeId(int subscribeId) {
    std::vector<Node*> nodes;
    const char* sql = "SELECT id, protocol, uuid, addr, port, info, type, encryption, security, extra_params FROM nodes WHERE subscribe_id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return nodes;
    }
    
    sqlite3_bind_int(stmt, 1, subscribeId);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char* protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* uuid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* addr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        int port = sqlite3_column_int(stmt, 4);
        const char* info = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        
        Node* node = nullptr;
        std::string protocolStr(protocol ? protocol : "");
        
        if (protocolStr == "vless") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* encryption = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* security = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            VlessNode* vlessNode = new VlessNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                type ? type : "tcp",
                encryption ? encryption : "none",
                security ? security : "none"
            );
            
            vlessNode->setId(id);
            node = vlessNode;
        } else if (protocolStr == "vmess") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* security = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* tls = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            VmessNode* vmessNode = new VmessNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                0,  // alterId，默认为0
                security ? security : "auto",
                type ? type : "tcp",
                tls ? tls : ""
            );
            
            vmessNode->setId(id);
            node = vmessNode;
        } else if (protocolStr == "trojan") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* sni = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            
            TrojanNode* trojanNode = new TrojanNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                sni ? sni : addr ? addr : "",
                type ? type : "tcp"
            );
            
            trojanNode->setId(id);
            node = trojanNode;
        } else if (protocolStr == "hy2") {
            const char* sni = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* obfs = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* obfs_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            Hy2Node* hy2Node = new Hy2Node(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                sni ? sni : addr ? addr : "",
                obfs ? obfs : "",
                obfs_password ? obfs_password : "",
                false  // insecure
            );
            
            hy2Node->setId(id);
            node = hy2Node;
        } else {
            node = new Node(
                protocolStr,
                uuid ? uuid : "",
                addr ? addr : "",
                port,
                info ? info : ""
            );
            node->setId(id);
        }
        
        nodes.push_back(node);
    }
    
    sqlite3_finalize(stmt);
    return nodes;
}

Node* DatabaseManager::getNodeById(int id) {
    const char* sql = "SELECT id, protocol, uuid, addr, port, info, type, encryption, security, extra_params FROM nodes WHERE id = ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return nullptr;
    }
    
    sqlite3_bind_int(stmt, 1, id);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char* protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* uuid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* addr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        int port = sqlite3_column_int(stmt, 4);
        const char* info = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        
        Node* node = nullptr;
        std::string protocolStr(protocol ? protocol : "");
        
        if (protocolStr == "vless") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* encryption = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* security = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            VlessNode* vlessNode = new VlessNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                type ? type : "tcp",
                encryption ? encryption : "none",
                security ? security : "none"
            );
            
            vlessNode->setId(id);
            node = vlessNode;
        } else if (protocolStr == "vmess") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* security = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* tls = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            VmessNode* vmessNode = new VmessNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                0,  // alterId，默认为0
                security ? security : "auto",
                type ? type : "tcp",
                tls ? tls : ""
            );
            
            vmessNode->setId(id);
            node = vmessNode;
        } else if (protocolStr == "trojan") {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* sni = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            
            TrojanNode* trojanNode = new TrojanNode(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                sni ? sni : addr ? addr : "",
                type ? type : "tcp"
            );
            
            trojanNode->setId(id);
            node = trojanNode;
        } else if (protocolStr == "hy2") {
            const char* sni = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* obfs = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const char* obfs_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            
            Hy2Node* hy2Node = new Hy2Node(
                uuid ? uuid : "", 
                addr ? addr : "", 
                port, 
                info ? info : "",
                sni ? sni : addr ? addr : "",
                obfs ? obfs : "",
                obfs_password ? obfs_password : "",
                false  // insecure
            );
            
            hy2Node->setId(id);
            node = hy2Node;
        } else {
            node = new Node(
                protocolStr,
                uuid ? uuid : "",
                addr ? addr : "",
                port,
                info ? info : ""
            );
            node->setId(id);
        }
        
        sqlite3_finalize(stmt);
        return node;
    }
    
    sqlite3_finalize(stmt);
    return nullptr;
}

bool DatabaseManager::isTableEmpty(const std::string& tableName) {
    std::string sql = "SELECT COUNT(*) FROM " + tableName + ";";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "准备SQL语句失败: " << sqlite3_errmsg(db) << std::endl;
        return true; // 假设为空
    }
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return count == 0;
} 