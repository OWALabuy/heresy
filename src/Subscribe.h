#ifndef SUBSCIRBE_H
#define SUBSCIRBE_H
#include <string>

/*订阅分组的实体类
 * 有私有成员和成员方法
 */
class Subscribe {
   private:
    // 接收数据库的主键id
    int id;

    // 名称
    std::string name;

    // 订阅链接
    std::string url;

   public:
    //构造函数
    Subscribe(int id, const std::string& name, const std::string& url);

    // getter和setter
    int getId(void);
    std::string getName(void);
    std::string getUrl(void);
    void setId(int id);
    void setName(std::string name);
    void setUrl(std::string url);
};
#endif
