#include "ArgParser.hpp"

void ArgParser::printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " --nodeaddr <host_address>" << std::endl;
    std::cout << "Example: " << programName << " --nodeaddr localhost" << std::endl;
    std::cout << "         " << programName << " --nodeaddr 192.168.1.100" << std::endl;
}

std::string ArgParser::parseArgs(int argc, char* argv[]) {
    if (argc != 3) {
        throw std::runtime_error("Invalid number of arguments");
    }

    if (strcmp(argv[1], "--nodeaddr") != 0) {
        throw std::runtime_error("First argument must be --nodeaddr");
    }

    return std::string(argv[2]);
}