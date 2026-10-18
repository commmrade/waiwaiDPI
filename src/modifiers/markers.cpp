//
// Created by klewy on 10/13/26.
//

#include "markers.hpp"
#include "algorithms/split.hpp"
#include <cassert>

std::expected<Markers, std::string> find_markers_http(std::span<const char> payload)
{
    Markers ret;

    const std::string_view payload_str{ payload };

    constexpr std::string_view HOST_HEADER_NAME = "Host:";
    const auto host_subrange = std::ranges::search(payload_str, HOST_HEADER_NAME, [](const auto ch1, const auto ch2) {
        return std::tolower(ch1) == std::tolower(ch2);
    });
    if (host_subrange.empty()) { return std::unexpected{ "Unable to find a host in HTTP" }; }
    const auto host_pos = std::distance(payload_str.begin(), host_subrange.begin());
    const auto host_end = payload_str.find("\r\n", static_cast<std::size_t>(host_pos));
    if (host_end == std::string::npos) { return std::unexpected{ "Kinda malformed http request" }; }

    std::string_view const host{ payload_str.data() + host_pos + HOST_HEADER_NAME.size() + 1,
        payload_str.data() + host_end };
    ret.hoststart.emplace(std::distance(payload_str.data(), host.data()));
    ret.hostend.emplace(ret.hoststart.value() + host.size());
    ret.hostmid.emplace(ret.hoststart.value() + host.size() / 2);

    return { ret };
}

std::expected<Markers, std::string> find_markers_tls(std::span<const char> payload)
{
    Markers ret;
    // it is guaranteed to be a tls handshake (because of the classifier), nothing else is guaranteed besides that
    constexpr auto tls_handshake_type = 0x16;
    const auto initial = payload;

    // content stuff
    payload = payload.subspan(5);// skip header bytes, get to content

    // from now on i need to do all the checks, because classifier checks just the header (first 5 bytes)
    if (payload[0] != 0x01) {// content type is not clienthello
        // std::println(std::cerr, "content type is not clienthello");
        return std::unexpected{ "payload is not client hello" };
    }

    if (!helpers::safe_subspan(payload, 38)) {// skip type(1) + length(3) + legacyversion(2) + random(32) fields
        return std::unexpected{ "malformed tls" };
    }

    const auto legacy_session_id_len = static_cast<std::uint8_t>(payload[0]);
    if (!helpers::safe_subspan(payload, sizeof(legacy_session_id_len) + legacy_session_id_len)) {
        return std::unexpected{ "malformed tls" };
    }

    std::uint16_t cipher_suites_len = 0;
    if (payload.size() < sizeof(cipher_suites_len)) { return std::unexpected{ "malformed tls" }; }
    std::memcpy(&cipher_suites_len, payload.data(), sizeof(cipher_suites_len));
    cipher_suites_len = ntohs(cipher_suites_len);

    if (!helpers::safe_subspan(payload, sizeof(cipher_suites_len) + cipher_suites_len + 2)) {
        return std::unexpected{ "malformed tls" };
    }

    // parse extensions (sni is here) (loop)
    std::uint16_t exts_len = 0;
    if (payload.size() < sizeof(exts_len)) { return std::unexpected{ "malformed tls" }; }
    std::memcpy(&exts_len, payload.data(), sizeof(exts_len));
    exts_len = ntohs(exts_len);
    payload = payload.subspan(sizeof(exts_len));

    while (!payload.empty()) {
        std::uint16_t ext_type = 0;
        if (payload.size() < sizeof(ext_type)) { return std::unexpected{ "malformed tls" }; }

        ret.sniext.emplace(static_cast<std::size_t>(std::distance(initial.data(), payload.data())));
        std::memcpy(&ext_type, payload.data(), sizeof(ext_type));
        ext_type = ntohs(ext_type);

        payload = payload.subspan(sizeof(ext_type));

        std::uint16_t ext_len = 0;
        if (payload.size() < sizeof(ext_len)) { return std::unexpected{ "malformed tls" }; }
        std::memcpy(&ext_len, payload.data(), sizeof(ext_len));
        ext_len = ntohs(ext_len);

        constexpr auto ext_sni_type = 0x00;
        if (ext_type != ext_sni_type) {

            if (!helpers::safe_subspan(payload, sizeof(ext_len) + ext_len)) {
                return std::unexpected{ "malformed tls" };
            }
            continue;
        }

        payload = payload.subspan(sizeof(ext_len));

        std::uint16_t serv_name_list_len = 0;
        if (payload.size() < sizeof(serv_name_list_len) + 1) { return std::unexpected{ "malformed tls" }; }
        std::memcpy(&serv_name_list_len, payload.data(), sizeof(serv_name_list_len));
        serv_name_list_len = ntohs(serv_name_list_len);

        // TODO: fix this?
        if (payload[2] != 0x00) {// well acyually servname list is a list, but it is always 1 element so idc
            return std::unexpected{ "" };
        }

        payload = payload.subspan(sizeof(serv_name_list_len) + 1);

        std::uint16_t hostname_len = 0;
        if (payload.size() < sizeof(hostname_len)) { return std::unexpected{ "malformed tls" }; }
        std::memcpy(&hostname_len, payload.data(), sizeof(hostname_len));
        hostname_len = ntohs(hostname_len);

        if (payload.size() < sizeof(hostname_len) + hostname_len) { return std::unexpected{ "malformed tls" }; }

        const auto hoststart =
            static_cast<std::size_t>(std::distance(initial.data(), payload.data() + sizeof(hostname_len))); //NOLINT
        ret.hoststart.emplace(hoststart);
        ret.hostend.emplace(hoststart + hostname_len);
        ret.hostmid.emplace(hoststart + hostname_len / 2);

        return { ret };
    }

    return std::unexpected{ "Did not find any markers" };
}

std::expected<Markers, std::string> find_markers(std::span<const char> payload, const L7Proto payload_proto)
{
    switch (payload_proto) {
    case L7Proto::TLS: {
        return find_markers_tls(payload);
    }
    case L7Proto::HTTP: {
        return find_markers_http(payload);
    }
    default:
        return Markers{};
    };
}
