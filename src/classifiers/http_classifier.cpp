//
// Created by klewy on 8/15/26.
//

#include "http_classifier.hpp"

std::expected<ClassifyResult, std::string> HttpClassifier::classify(const std::vector<char> &payload)
{
    std::string_view payload_str{ payload };
    // First, try to find \r\n (the status line)
    const auto crln_pos = payload_str.find("\r\n");
    if (crln_pos == std::string_view::npos) {
        return std::unexpected{ "HTTP request is malformed: was unable to find \r\n" };
    }

    payload_str = payload_str.substr(0, crln_pos);

    // Now, try to search for "HTTP/"
    const auto http_pos = payload_str.find("HTTP/");
    if (http_pos == std::string_view::npos) {
        return std::unexpected{ "HTTP request is malformed: was unable to find HTTP in status line" };
    }

    std::string_view const full_req{ payload };
    const auto header_end_pos = full_req.find("\r\n\r\n");
    if (header_end_pos == std::string_view::npos) { return { ClassifyResult::REASSEMBLING }; }

    return { ClassifyResult::DONE };
}
