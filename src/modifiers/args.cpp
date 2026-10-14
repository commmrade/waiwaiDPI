//
// Created by klewy on 10/12/26.
//

#include "args.hpp"

Position parse_position(const std::string_view split)
{
    assert(!split.empty());

    Position ret{};

    auto iter = split.begin();
    while (iter != split.end()) {
        if (iter != split.end() && std::isalpha(*iter) != 0) {
            while (iter != split.end() && std::isalpha(*iter) != 0) {
                ret.arg += *iter;
                std::advance(iter, 1);
            }
        }
        if (iter != split.end() && std::isdigit(*iter) != 0) {
            std::string digit;
            while (iter != split.end() && std::isdigit(*iter) != 0) {
                digit += *iter;
                std::advance(iter, 1);
            }
            ret.offset = static_cast<std::size_t>(std::stoi(digit));
        }

        if (iter != split.end()) {
            if (*iter == '+') {
                ret.operation = Position::Operation::Add;
                std::advance(iter, 1);
            } else if (*iter == '-') {
                ret.operation = Position::Operation::Subtract;
                std::advance(iter, 1);
            } else {
                throw std::runtime_error("Unexpected symbol");
            }
        }
    }

    if (ret.operation != Position::Operation::None && ret.arg.empty()) {
        throw std::runtime_error(
            std::format("You specified an operation but didn't specify marker position in '{}'", split));
    }

    return ret;
}
std::vector<char> parse_blob(const std::string_view &str)
{
    if (str.starts_with("0x")) {
        std::string hex{ str.substr(2) };
        if (hex.size() % 2 != 0) { hex.insert(hex.begin(), '0'); }

        std::vector<char> bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            const std::string byteString = hex.substr(i, 2);
            char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }

        return bytes;
    } else {
        if (!std::filesystem::exists(str)) {
            throw std::runtime_error(std::format("Blob at filepath '{}' does not exist", str));
        }

        auto *fp = std::fopen(str.data(), "rb");
        if (!fp) { throw std::runtime_error(std::format("Could not open file '{}'", str)); }
        int ret = std::fseek(fp, 0U, SEEK_END);
        if (ret < 0) { throw std::runtime_error(std::strerror(errno)); }
        const auto size = std::ftell(fp);
        if (size < 0) { throw std::runtime_error(std::strerror(errno)); }
        ret = std::fseek(fp, 0U, SEEK_SET);
        if (ret < 0) { throw std::runtime_error(std::strerror(errno)); }
        std::vector<char> buf(size, 0);
        const auto rd = std::fread(buf.data(), 1U, static_cast<std::size_t>(size), fp);
        if (rd < 0) { throw std::runtime_error(std::strerror(errno)); }
        ret = std::fclose(fp);

        return buf;
    }
}