#include <iostream>
#include <fstream>
#include "WebSocket.hpp"

int main(int argc, const char * argv[])
{
    std::string port;

    for (int i = 1; i < argc; ++i)
    {
        if (std::string(argv[i]) == "--help")
        {
            std::cout << "test --port <port>" << std::endl;
            return EXIT_SUCCESS;
        }
        else if (std::string(argv[i]) == "--port")
        {
            if (++i < argc) port = argv[i];
        }
    }

    return EXIT_SUCCESS;
}
