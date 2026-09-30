//
// Created by klewy on 9/7/26.
//

#include "tls_modifier.hpp"
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "../checksum.hpp"
#include "algorithms/split.hpp"
#include <spdlog/spdlog.h>

#include <cassert>
#include <iostream>
#include <print>

// <new span, success>
static bool safe_subspan(std::span<const char>& span, const std::size_t offset)
{
    if (span.size() < offset) {
        return false;
    }
    span = span.subspan(offset);
    return true;
}

std::optional<std::string_view> TlsHandshakeModifier::get_sni(std::span<const char> payload)
{
    // It is guaranteed to be a TLS handshake (because of the classifier), nothing else is guaranteed besides that
    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    assert(payload.size() >= 5);
    assert(payload[0] == TLS_HANDSHAKE_TYPE);
    assert(payload[1] == 0x03 && (payload[2] == 0x03 || payload[2] == 0x01));

    // content stuff
    payload = payload.subspan(5); // skip header bytes, get to content

    // From now on I need to do all the checks, because Classifier checks just the header (first 5 bytes)
    if (payload[0] != 0x01) { // content type is not ClientHello
        // std::println(std::cerr, "Content type is not ClientHello");
        return std::nullopt;
    }

    if (!safe_subspan(payload, 38)) { // skip type(1) + length(3) + legacyVersion(2) + random(32) fields
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }

    const auto legacy_session_id_len = static_cast<std::uint8_t>(payload[0]);
    if (!safe_subspan(payload, sizeof(legacy_session_id_len) + legacy_session_id_len)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }

    std::uint16_t cipher_suites_len = 0;
    if (payload.size() < sizeof(cipher_suites_len)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }
    std::memcpy(&cipher_suites_len, payload.data(), sizeof(cipher_suites_len));
    cipher_suites_len = ntohs(cipher_suites_len);

    if (!safe_subspan(payload, sizeof(cipher_suites_len) + cipher_suites_len + 2)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }

    // parse extensions (sni is here) (loop)
    std::uint16_t exts_len = 0;
    if (payload.size() < sizeof(exts_len)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }
    std::memcpy(&exts_len, payload.data(), sizeof(exts_len));
    exts_len = ntohs(exts_len);
    payload = payload.subspan(sizeof(exts_len));

    while (!payload.empty()) {
        std::uint16_t ext_type = 0;
        if (payload.size() < sizeof(ext_type)) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }
        std::memcpy(&ext_type, payload.data(), sizeof(ext_type));
        ext_type = ntohs(ext_type);

        payload = payload.subspan(sizeof(ext_type));

        std::uint16_t ext_len = 0;
        if (payload.size() < sizeof(ext_len)) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }
        std::memcpy(&ext_len, payload.data(), sizeof(ext_len));
        ext_len = ntohs(ext_len);

        constexpr auto EXT_SNI_TYPE = 0x00;
        if (ext_type != EXT_SNI_TYPE) {

            if (!safe_subspan(payload, sizeof(ext_len) + ext_len)) {
                std::println(std::cerr, "Ill-formed TLS");
                return std::nullopt;
            }
            continue;
        }

        payload = payload.subspan(sizeof(ext_len));

        std::uint16_t serv_name_list_len = 0;
        if (payload.size() < sizeof(serv_name_list_len) + 1) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }
        std::memcpy(&serv_name_list_len, payload.data(), sizeof(serv_name_list_len));
        serv_name_list_len = ntohs(serv_name_list_len);

        if (payload[2] != 0x00) { // well acyually servname list is a list, but it is ALWAYS 1 element so idc
            return std::nullopt;
        }

        payload = payload.subspan(sizeof(serv_name_list_len) + 1);

        std::uint16_t hostname_len = 0;
        if (payload.size() < sizeof(hostname_len)) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }
        std::memcpy(&hostname_len, payload.data(), sizeof(hostname_len));
        hostname_len = ntohs(hostname_len);

        if (payload.size() < sizeof(hostname_len) + hostname_len) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }

        return std::string_view{std::next(payload.data(), sizeof(hostname_len)), static_cast<std::size_t>(hostname_len)};
    }

    return std::nullopt;
}

static std::size_t calculate_split_offset(const Split& split, const std::size_t sni_len)
{
    std::size_t offset = 0;

    auto do_operation = [](const std::size_t start, const Split::Operation oper, const std::size_t offset) {
        std::size_t ret = start;
        switch (oper) {
        case Split::Operation::Add: {
            ret += offset;
            break;
        }
        case Split::Operation::Subtract: {
            ret -= offset;
            break;
        }
        default:
            break;
        }

        return ret;
    };

    if (split.arg == "hoststart") {
        offset = do_operation(0, split.operation, split.offset);
    } else if (split.arg == "hostend") {
        offset = do_operation(sni_len, split.operation, split.offset);
    } else if (split.arg == "hostmid") {
        offset = do_operation(sni_len / 2, split.operation, split.offset);
    } else {
        offset = split.offset;
    }

    return offset;
}

bool TlsHandshakeModifier::modify(std::vector<Packet> &vec, const Connection& conn)
{
    return split::split(vec, split::SplitConfig{split_at_, std::nullopt}, conn);
}

bool TlsHandshakeModifier::matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const
{
    return l4_proto == IPPROTO_TCP && l7_proto == L7Proto::TLS_HANDSHAKE;
}

void TlsHandshakeModifier::parse_config(const toml::table *table)
{
    const auto split_node = table->get("split_at");
    if (split_node != nullptr) {
        if (split_node->is_number()) {
            split_at_.offset = static_cast<int>(split_node->as_integer()->get());
        } else {
            // Supported values: hoststart, hostend, hostmid, numbers (relative from hoststart start)
            const auto split_str = split_node->as_string()->get();
            split_at_ = parse_split(split_str);
        }
    } else {
        SPDLOG_WARN("'split_at' parameter for {} is not specified, but it defaults to 0", TlsHandshakeModifier::name());
    }
}