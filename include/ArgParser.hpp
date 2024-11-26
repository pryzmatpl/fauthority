#ifndef ARG_PARSER
#define ARG_PARSER

#include<string>
#include<iostream>
#include<cstring>

class ArgParser {
    public:
        std::string parseArgs(int argc, char* argv[]);
        void printUsage(const char* programName);
};

#endif // ARG_PARSER