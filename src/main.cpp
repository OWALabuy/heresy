#include <iostream>
#include "CLI.h"

int main() {
    try {
        CLI cli;
        cli.run();
    } catch (const std::exception& e) {
        std::cerr << "发生错误: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 