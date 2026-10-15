//
// Created by klewy on 8/15/26.
//

#include "http_classifier.hpp"

#include "../conn_tracker.hpp"
#include "../consts.hpp"
#include "../modifiers/algorithms/common.hpp"
#include "../packet_view.hpp"
#include <netinet/in.h>

std::expected<ParseResult, std::string> HttpClassifier::classify(Connection& conn)
{
    std::vector<char> payload = concat(conn.get_reasm_frags());

    std::string_view payload_str{ payload };
    // First, try to find \r\n (the status line)
    const auto crln_pos = payload_str.find("\r\n");
    if (crln_pos == std::string_view::npos) {
        return std::unexpected{"HTTP request is malformed: was unable to find \r\n"};
    }

    payload_str = payload_str.substr(0, crln_pos);

    // Now, try to search for "HTTP/"
    const auto http_pos = payload_str.find("HTTP/");
    if (http_pos == std::string_view::npos) {
        return std::unexpected{"HTTP request is malformed: was unable to find HTTP in status line"};
    }

    std::string_view const full_req{ payload };
    const auto header_end_pos = full_req.find("\r\n\r\n");
    if (header_end_pos == std::string_view::npos) {
        return { ParseResult::REASSEMBLING };
    }
    // TODO: i guess it is not entirelty correct

    conn.set_payload_proto(L7Proto::HTTP);
    return {ParseResult::SUCCESS};
}
