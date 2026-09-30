//
// Created by klewy on 10/1/26.
//

#include "splitter_common.hpp"

static unsigned char full_http_req[] = {0x45, 0x0, 0x1, 0xb5, 0xb3, 0xd, 0x40, 0x0, 0x40, 0x6, 0x56, 0xfd, 0xc0, 0xa8, 0x1, 0xa9, 0x68, 0x15, 0x4, 0xd2, 0xe5, 0x50, 0x0, 0x50, 0x99, 0xe, 0xe6, 0x92, 0xa1, 0x48, 0xe4, 0x55, 0x80, 0x18, 0x0, 0x3f, 0x30, 0xe0, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x53, 0xfe, 0xf3, 0x17, 0x6, 0x44, 0x3b, 0xd7, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0xd, 0xa, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28, 0x58, 0x31, 0x31, 0x3b, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x3b, 0x20, 0x72, 0x76, 0x3a, 0x31, 0x35, 0x33, 0x2e, 0x30, 0x29, 0x20, 0x47, 0x65, 0x63, 0x6b, 0x6f, 0x2f, 0x32, 0x30, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x20, 0x46, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78, 0x2f, 0x31, 0x35, 0x33, 0x2e, 0x30, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x6d, 0x6c, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39, 0x2c, 0x2a, 0x2f, 0x2a, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x38, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x2c, 0x65, 0x6e, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x20, 0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65, 0xd, 0xa, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0xd, 0xa, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2d, 0x49, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x3a, 0x20, 0x31, 0xd, 0xa, 0x49, 0x66, 0x2d, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x53, 0x69, 0x6e, 0x63, 0x65, 0x3a, 0x20, 0x57, 0x65, 0x64, 0x2c, 0x20, 0x30, 0x31, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x32, 0x30, 0x32, 0x36, 0x20, 0x31, 0x39, 0x3a, 0x33, 0x39, 0x3a, 0x31, 0x37, 0x20, 0x47, 0x4d, 0x54, 0xd, 0xa, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x3a, 0x20, 0x75, 0x3d, 0x30, 0x2c, 0x20, 0x69, 0xd, 0xa, 0xd, 0xa};
static std::span<const char> bytes_span{reinterpret_cast<const char*>(full_http_req), sizeof(full_http_req)};

static unsigned char full_http_req_case[] = {0x45, 0x0, 0x0, 0x83, 0x5a, 0x67, 0x40, 0x0, 0x40, 0x6, 0xb0, 0xd5, 0xc0, 0xa8, 0x1, 0xa9, 0x68, 0x15, 0x4, 0xd2, 0x8f, 0xdc, 0x0, 0x50, 0x47, 0x3e, 0xf8, 0x7f, 0x1b, 0xce, 0xc5, 0x79, 0x80, 0x18, 0x0, 0x3f, 0x2f, 0xae, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x8, 0x5c, 0x17, 0x4d, 0x48, 0x17, 0x86, 0x4a, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0xd, 0xa, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x38, 0x2e, 0x32, 0x31, 0x2e, 0x30, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0xd, 0xa, 0xd, 0xa};
static std::span<const char> bytes_case_span{reinterpret_cast<const char*>(full_http_req_case), sizeof(full_http_req_case)};

TEST_CASE_METHOD(SplitterTestFixture, "Single Split for HTTP works", "[splitter_modifier]")
{
    constexpr std::string_view config = R"toml(
    [profile.1]
    port = 443
    protocol = "tcp"

    [[profile.1.classifiers]]
    name = "http_classifier"

    [[profile.1.modifiers]]
    name = "splitter"
    split_at = ["2"]
    )toml";
    build_http_splitter(config);

    std::vector<Packet> packets;
    PacketView packet_1_view = parse_packet_view(bytes_span);
    tracker.track(packet_1_view);
    auto &conn = tracker.get_conn(packet_1_view.network_hdr->saddr,
        packet_1_view.get_source_port(),
        packet_1_view.network_hdr->daddr,
        packet_1_view.get_dest_port(),
        packet_1_view.network_hdr->protocol);
    auto res = classifier.classify(packet_1_view);
    REQUIRE(res == ParseResult::SUCCESS);

    packets.push_back(create_packet(packet_1_view));

    modifier.modify(packets, conn);
    REQUIRE(packets.size() == 2);
    REQUIRE(packets.front().payload().size() == 2);
    REQUIRE(packets.back().payload().size() == packet_1_view.payload.size() - 2);

    REQUIRE(packets.front().action.action == PacketAction::Action::DROP_AND_SEND);
    REQUIRE(packets.back().action.action == PacketAction::Action::SEND);
}


TEST_CASE_METHOD(SplitterTestFixture, "Split at Header for HTTP works", "[splitter_modifier]")
{
    constexpr std::string_view config = R"toml(
    [profile.1]
    port = 443
    protocol = "tcp"

    [[profile.1.classifiers]]
    name = "http_classifier"

    [[profile.1.modifiers]]
    name = "splitter"
    split_at = ["hostmid"]
    )toml";
    build_http_splitter(config);

    std::vector<Packet> packets;
    PacketView packet_1_view = parse_packet_view(bytes_span);
    tracker.track(packet_1_view);
    auto &conn = tracker.get_conn(packet_1_view.network_hdr->saddr,
        packet_1_view.get_source_port(),
        packet_1_view.network_hdr->daddr,
        packet_1_view.get_dest_port(),
        packet_1_view.network_hdr->protocol);
    auto res = classifier.classify(packet_1_view);
    REQUIRE(res == ParseResult::SUCCESS);

    packets.push_back(create_packet(packet_1_view));

    modifier.modify(packets, conn);
    REQUIRE(packets.size() == 2);

    REQUIRE(packets.front().action.action == PacketAction::Action::DROP_AND_SEND);
    REQUIRE(packets.back().action.action == PacketAction::Action::SEND);

    REQUIRE(std::string_view{packets.front().payload()}.find("httpforever.com") == std::string_view::npos);
    REQUIRE(std::string_view{packets.back().payload()}.find("httpforever.com") == std::string_view::npos);
}


TEST_CASE_METHOD(SplitterTestFixture, "Split at HEaDeR for HTTP works", "[splitter_modifier]")
{
    constexpr std::string_view config = R"toml(
    [profile.1]
    port = 443
    protocol = "tcp"

    [[profile.1.classifiers]]
    name = "http_classifier"

    [[profile.1.modifiers]]
    name = "splitter"
    split_at = ["hostmid"]
    )toml";
    build_http_splitter(config);

    std::vector<Packet> packets;
    PacketView packet_1_view = parse_packet_view(bytes_case_span);
    tracker.track(packet_1_view);
    auto &conn = tracker.get_conn(packet_1_view.network_hdr->saddr,
        packet_1_view.get_source_port(),
        packet_1_view.network_hdr->daddr,
        packet_1_view.get_dest_port(),
        packet_1_view.network_hdr->protocol);
    auto res = classifier.classify(packet_1_view);
    REQUIRE(res == ParseResult::SUCCESS);

    packets.push_back(create_packet(packet_1_view));

    modifier.modify(packets, conn);
    REQUIRE(packets.size() == 2);

    REQUIRE(packets.front().action.action == PacketAction::Action::DROP_AND_SEND);
    REQUIRE(packets.back().action.action == PacketAction::Action::SEND);

    REQUIRE(std::string_view{packets.front().payload()}.find("httpforever.com") == std::string_view::npos);
    REQUIRE(std::string_view{packets.back().payload()}.find("httpforever.com") == std::string_view::npos);
}

TEST_CASE_METHOD(SplitterTestFixture, "Multiple Split for HTTP works", "[splitter_modifier]")
{
    constexpr std::string_view config = R"toml(
    [profile.1]
    port = 443
    protocol = "tcp"

    [[profile.1.classifiers]]
    name = "http_classifier"

    [[profile.1.modifiers]]
    name = "splitter"
    split_at = ["2", "hostmid"]
    )toml";
    build_http_splitter(config);

    PacketView packet_1_view = parse_packet_view(bytes_span);
    tracker.track(packet_1_view);
    auto &conn = tracker.get_conn(packet_1_view.network_hdr->saddr,
        packet_1_view.get_source_port(),
        packet_1_view.network_hdr->daddr,
        packet_1_view.get_dest_port(),
        packet_1_view.network_hdr->protocol);
    auto res = classifier.classify(packet_1_view);
    REQUIRE(res == ParseResult::SUCCESS);

    packets.push_back(create_packet(packet_1_view));

    modifier.modify(packets, conn);
    REQUIRE(packets.size() == 3);
    REQUIRE(packets.front().payload().size() == 2);

    REQUIRE(packets.front().action.action == PacketAction::Action::DROP_AND_SEND);
    REQUIRE(packets[1].action.action == PacketAction::Action::SEND);
    REQUIRE(packets.back().action.action == PacketAction::Action::SEND);
}

template <typename Container>
Container make_packets(std::size_t count) {
    Container packets;
    if constexpr (requires { packets.reserve(count); }) {
        packets.reserve(count);
    }
    for (std::size_t i = 0; i < count; ++i) {
        std::span<const char> const packet{
            reinterpret_cast<const char*>(full_http_req), sizeof(full_http_req)};
        PacketView pkt = parse_packet_view(packet);
        packets.push_back(create_packet(pkt));
    }
    return packets;
}

template <typename Container>
std::size_t split_and_insert(Container& packets) {
    // find Host: header split point
    std::vector<char> full_payload;
    for (const auto& pkt : packets) {
        const auto payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }
    const std::string_view payload_str{full_payload};

    constexpr std::string_view HOST_HEADER_NAME = "Host:";
    const auto host_subrange = std::ranges::search(payload_str, HOST_HEADER_NAME,
        [](const auto ch1, const auto ch2) { return std::tolower(ch1) == std::tolower(ch2); });
    if (host_subrange.empty()) return 0;

    const auto host_pos = std::distance(payload_str.begin(), host_subrange.begin());
    constexpr auto SPLIT_AT = HOST_HEADER_NAME.size() + 3;
    const auto split_at_global_pos = static_cast<std::size_t>(host_pos) + SPLIT_AT;
    if (split_at_global_pos >= full_payload.size()) return 0;

    auto iter = packets.begin();
    std::size_t offset = 0;
    std::size_t rel = 0;
    for (; iter != packets.end(); ++iter) {
        offset += iter->payload().size();
        if (split_at_global_pos < offset) {
            rel = split_at_global_pos - (offset - iter->payload().size());
            break;
        }
    }
    if (iter == packets.end() || rel == 0) return 0;

    const auto pkt_view = parse_packet_view(*iter);
    const auto pkt_payload = iter->payload();
    const std::ptrdiff_t at = static_cast<std::ptrdiff_t>(rel);
    const std::span<const char> part1{pkt_payload.begin(), std::next(pkt_payload.begin(), at)};
    const std::span<const char> part2{std::next(pkt_payload.begin(), at), pkt_payload.end()};

    Packet first_packet = create_packet_from(pkt_view, part1);
    first_packet.action.action = PacketAction::Action::DROP_AND_SEND;

    Packet second_packet = create_packet_from(pkt_view, part2);
    second_packet.action.action = PacketAction::Action::SEND;
    second_packet.action.packet_id = 0;
    auto* tcp = static_cast<tcphdr*>(second_packet.transport_hdr());
    tcp->seq += htonl(part1.size());

    if constexpr (requires { packets.begin() + 1; }) {
        const auto dist = std::distance(packets.begin(), iter);
        packets.erase(iter);
        packets.insert(packets.begin() + dist, std::move(first_packet));
        packets.insert(packets.begin() + dist + 1, std::move(second_packet));
    } else {
        iter = packets.erase(iter);
        iter = packets.insert(iter, std::move(first_packet));
        ++iter;
        packets.insert(iter, std::move(second_packet));
    }
    return packets.size();
}

template <typename Container>
std::size_t read_all(const Container& packets) {
    std::size_t checksum = 0;
    for (const auto& pkt : packets) {
        checksum += pkt.network_hdr()->protocol;
    }
    return checksum;
}

// The full pipeline, timed as one unit: create -> split/insert -> read.
template <typename Container>
std::size_t full_pipeline(std::size_t count) {
    Container packets = make_packets<Container>(count);
    split_and_insert(packets);
    return read_all(packets);
}

TEST_CASE("Benchmark Vector vs List: full pipeline", "[http_modifier][!benchmark]")
{
    constexpr std::size_t PACKETS_CNT = 2000;

    BENCHMARK("vector: create + split/insert + read") {
        return full_pipeline<std::vector<Packet>>(PACKETS_CNT);
    };

    BENCHMARK("list: create + split/insert + read") {
        return full_pipeline<std::list<Packet>>(PACKETS_CNT);
    };
    // Results:
    // there is no that much of a performance improvement (only about 1.5%)
    // but cache locality is way worse because List is not a contigious container
    // i leave it as it is (use vector)
}

// Benchmark: eager copy-into-vector + string_view::search
// vs. lazy views::join over spans + ranges::search
template <typename Container>
std::size_t find_host_pos_eager_copy(const Container& packets) {
    std::vector<char> full_payload;
    for (const auto& pkt : packets) {
        const auto payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }
    const std::string_view payload_str{full_payload};

    constexpr std::string_view HOST_HEADER_NAME = "Host:";
    const auto host_subrange = std::ranges::search(payload_str, HOST_HEADER_NAME,
        [](const auto ch1, const auto ch2) { return std::tolower(ch1) == std::tolower(ch2); });
    if (host_subrange.empty()) return 0;

    return static_cast<std::size_t>(std::distance(payload_str.begin(), host_subrange.begin()));
}

template <typename Container>
std::size_t find_host_pos_join_view(const Container& packets) {
    std::vector<std::span<const char>> payload_parts;
    payload_parts.reserve(packets.size());
    for (const auto& pkt : packets) {
        payload_parts.push_back(pkt.payload());
    }

    auto payload_str = payload_parts | std::views::join;
    constexpr std::string_view HOST_HEADER_NAME = "Host:";
    const auto host_subrange = std::ranges::search(payload_str, HOST_HEADER_NAME,
        [](const auto ch1, const auto ch2) { return std::tolower(ch1) == std::tolower(ch2); });
    if (host_subrange.empty()) return 0;

    return static_cast<std::size_t>(std::distance(payload_str.begin(), host_subrange.begin()));
}

TEST_CASE("Benchmark: eager copy vs join_view — realistic fragment counts", "[http_modifier][!benchmark]")
{
    for (std::size_t count : {1, 2, 3}) {
        std::vector<Packet> packets = make_packets<std::vector<Packet>>(count);

        BENCHMARK("eager copy, count=" + std::to_string(count)) {
            return find_host_pos_eager_copy(packets);
        };

        BENCHMARK("join_view, count=" + std::to_string(count)) {
            return find_host_pos_join_view(packets);
        };
    }
}
// "Benchmarked candidate optimization (ranges::join_view for zero-copy multi-fragment search) against current implementation; found current approach outperforms by up to 2.6x for the common single-fragment case, validating the existing design over a plausible-looking optimization."
