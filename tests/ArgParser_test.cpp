#include <gtest/gtest.h>
#include "ArgParser.hpp"
#include <stdexcept>
#include <string>

class ArgParserTest : public ::testing::Test {
protected:
    ArgParser parser;
    
    void SetUp() override {
        // Any setup code would go here
    }

    void TearDown() override {
        // Any cleanup code would go here
    }

    // Helper function to create argv array
    char** createArgv(const std::vector<std::string>& args) {
        char** argv = new char*[args.size()];
        for (size_t i = 0; i < args.size(); i++) {
            argv[i] = new char[args[i].length() + 1];
            strcpy(argv[i], args[i].c_str());
        }
        return argv;
    }

    // Helper function to cleanup argv array
    void cleanupArgv(char** argv, int argc) {
        for (int i = 0; i < argc; i++) {
            delete[] argv[i];
        }
        delete[] argv;
    }
};

// Test valid arguments
TEST_F(ArgParserTest, ValidArguments) {
    std::vector<std::string> args = {"program", "--nodeaddr", "localhost"};
    char** argv = createArgv(args);
    int argc = args.size();

    std::string result = parser.parseArgs(argc, argv);
    EXPECT_EQ(result, "localhost");

    cleanupArgv(argv, argc);
}

// Test valid IP address
TEST_F(ArgParserTest, ValidIPAddress) {
    std::vector<std::string> args = {"program", "--nodeaddr", "192.168.1.100"};
    char** argv = createArgv(args);
    int argc = args.size();

    std::string result = parser.parseArgs(argc, argv);
    EXPECT_EQ(result, "192.168.1.100");

    cleanupArgv(argv, argc);
}

// Test incorrect number of arguments
TEST_F(ArgParserTest, InvalidArgumentCount) {
    std::vector<std::string> args = {"program", "--nodeaddr"};
    char** argv = createArgv(args);
    int argc = args.size();

    EXPECT_THROW({
        parser.parseArgs(argc, argv);
    }, std::runtime_error);

    cleanupArgv(argv, argc);
}

// Test incorrect flag
TEST_F(ArgParserTest, InvalidFlag) {
    std::vector<std::string> args = {"program", "--wrongflag", "localhost"};
    char** argv = createArgv(args);
    int argc = args.size();

    EXPECT_THROW({
        parser.parseArgs(argc, argv);
    }, std::runtime_error);

    cleanupArgv(argv, argc);
}

// Test too many arguments
TEST_F(ArgParserTest, TooManyArguments) {
    std::vector<std::string> args = {"program", "--nodeaddr", "localhost", "extra"};
    char** argv = createArgv(args);
    int argc = args.size();

    EXPECT_THROW({
        parser.parseArgs(argc, argv);
    }, std::runtime_error);

    cleanupArgv(argv, argc);
}

// Test empty address
TEST_F(ArgParserTest, EmptyAddress) {
    std::vector<std::string> args = {"program", "--nodeaddr", ""};
    char** argv = createArgv(args);
    int argc = args.size();

    std::string result = parser.parseArgs(argc, argv);
    EXPECT_EQ(result, "");

    cleanupArgv(argv, argc);
}

// Test printUsage output
TEST_F(ArgParserTest, PrintUsage) {
    testing::internal::CaptureStdout();
    parser.printUsage("testprogram");
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_TRUE(output.find("Usage: testprogram --nodeaddr <host_address>") != std::string::npos);
    EXPECT_TRUE(output.find("Example: testprogram --nodeaddr localhost") != std::string::npos);
    EXPECT_TRUE(output.find("testprogram --nodeaddr 192.168.1.100") != std::string::npos);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}