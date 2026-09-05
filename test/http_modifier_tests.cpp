//
// Created by klewy on 8/28/26.
//

#include "../src/modifiers/http_host_modifier.hpp"
#include "common.hpp"
#include <list>
#include <catch2/catch_all.hpp>

static unsigned char full_http_req[] = {0x45, 0x0, 0x1, 0xb5, 0xb3, 0xd, 0x40, 0x0, 0x40, 0x6, 0x56, 0xfd, 0xc0, 0xa8, 0x1, 0xa9, 0x68, 0x15, 0x4, 0xd2, 0xe5, 0x50, 0x0, 0x50, 0x99, 0xe, 0xe6, 0x92, 0xa1, 0x48, 0xe4, 0x55, 0x80, 0x18, 0x0, 0x3f, 0x30, 0xe0, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x53, 0xfe, 0xf3, 0x17, 0x6, 0x44, 0x3b, 0xd7, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0xd, 0xa, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28, 0x58, 0x31, 0x31, 0x3b, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x3b, 0x20, 0x72, 0x76, 0x3a, 0x31, 0x35, 0x33, 0x2e, 0x30, 0x29, 0x20, 0x47, 0x65, 0x63, 0x6b, 0x6f, 0x2f, 0x32, 0x30, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x20, 0x46, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78, 0x2f, 0x31, 0x35, 0x33, 0x2e, 0x30, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x6d, 0x6c, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39, 0x2c, 0x2a, 0x2f, 0x2a, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x38, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x2c, 0x65, 0x6e, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x20, 0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65, 0xd, 0xa, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0xd, 0xa, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2d, 0x49, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x3a, 0x20, 0x31, 0xd, 0xa, 0x49, 0x66, 0x2d, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x53, 0x69, 0x6e, 0x63, 0x65, 0x3a, 0x20, 0x57, 0x65, 0x64, 0x2c, 0x20, 0x30, 0x31, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x32, 0x30, 0x32, 0x36, 0x20, 0x31, 0x39, 0x3a, 0x33, 0x39, 0x3a, 0x31, 0x37, 0x20, 0x47, 0x4d, 0x54, 0xd, 0xa, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x3a, 0x20, 0x75, 0x3d, 0x30, 0x2c, 0x20, 0x69, 0xd, 0xa, 0xd, 0xa};
static unsigned char full_http_req_case[] = {0x45, 0x0, 0x0, 0x83, 0x5a, 0x67, 0x40, 0x0, 0x40, 0x6, 0xb0, 0xd5, 0xc0, 0xa8, 0x1, 0xa9, 0x68, 0x15, 0x4, 0xd2, 0x8f, 0xdc, 0x0, 0x50, 0x47, 0x3e, 0xf8, 0x7f, 0x1b, 0xce, 0xc5, 0x79, 0x80, 0x18, 0x0, 0x3f, 0x2f, 0xae, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x8, 0x5c, 0x17, 0x4d, 0x48, 0x17, 0x86, 0x4a, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0xd, 0xa, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x38, 0x2e, 0x32, 0x31, 0x2e, 0x30, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0xd, 0xa, 0xd, 0xa};

static unsigned char split_http_req_1[] = {0x45, 0x0, 0x0, 0x5b, 0x9d, 0x8a, 0x40, 0x0, 0x40, 0x6, 0xaa, 0xa, 0xc0, 0xa8, 0x1, 0xa9, 0xac, 0x43, 0x84, 0x73, 0x85, 0x20, 0x0, 0x50, 0x23, 0x3b, 0x2e, 0x1e, 0x82, 0x69, 0xde, 0x87, 0x80, 0x18, 0x0, 0x3f, 0xf3, 0x55, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x64, 0x5d, 0xcc, 0xe3, 0xb8, 0x55, 0x8b, 0x6b, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0xd, 0xa};
static unsigned char split_http_req_2[] = {0x45, 0x0, 0x0, 0x5c, 0x9d, 0x8b, 0x40, 0x0, 0x40, 0x6, 0xaa, 0x8, 0xc0, 0xa8, 0x1, 0xa9, 0xac, 0x43, 0x84, 0x73, 0x85, 0x20, 0x0, 0x50, 0x23, 0x3b, 0x2e, 0x45, 0x82, 0x69, 0xde, 0x87, 0x80, 0x18, 0x0, 0x3f, 0xf3, 0x56, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x64, 0x5d, 0xce, 0x48, 0xb8, 0x55, 0x8b, 0xef, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x38, 0x2e, 0x32, 0x31, 0x2e, 0x30, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0xd, 0xa, 0xd, 0xa};

class HttpModifierTestFixture
{
protected:
    ConnTracker tracker;
    Classifier classifier{tracker};
    Modifier modifier;

    std::vector<Packet> packets;
public:
    HttpModifierTestFixture()
    {
        modifier.add(std::make_unique<HttpHostModifier>());
        classifier.add(std::make_unique<HttpClassifier>());
    }
};

TEST_CASE_METHOD(HttpModifierTestFixture, "Whole HTTP request is split at Host header", "[http_modifier]")
{
    std::span<const char> const packet{reinterpret_cast<const char*>(full_http_req), sizeof(full_http_req)};
    PacketView pkt = parse_packet_view(packet);
    std::string_view const pkt_payload{pkt.payload};
    REQUIRE(pkt_payload.find("httpforever.com") != std::string_view::npos);

    tracker.track(pkt);
    auto& conn = tracker.get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port(), pkt.network_hdr->protocol);
    auto res = classifier.classify(pkt);

    REQUIRE(res == ParseResult::SUCCESS);

    packets.emplace_back(create_packet(pkt));

    REQUIRE(pkt.payload_proto == L7Proto::HTTP);
    REQUIRE(modifier.modify(packets, conn));

    auto& pkt_1 = packets[0];
    REQUIRE(((pkt_1.action.action == PacketAction::Action::DROP_AND_SEND) && (pkt_1.action.packet_id > 0)));
    std::string_view const pkt_1_payload{pkt_1.payload()};
    REQUIRE(pkt_1_payload.find("httpforever.com") == std::string_view::npos);
    REQUIRE(pkt_1.payload_proto == L7Proto::HTTP);

    auto& pkt_2 = packets[1];
    REQUIRE(pkt_2.action.action == PacketAction::Action::SEND);
    std::string_view const pkt_2_payload{pkt_2.payload()};
    REQUIRE(pkt_2_payload.find("httpforever.com") == std::string_view::npos);
    REQUIRE(pkt_2.payload_proto == L7Proto::HTTP);
}

TEST_CASE_METHOD(HttpModifierTestFixture, "Case Insensitive searchf or Host Header", "[http_modifier]")
{
    std::span<const char> const packet{reinterpret_cast<const char*>(full_http_req_case), sizeof(full_http_req_case)};
    PacketView pkt = parse_packet_view(packet);
    std::string_view const pkt_payload{pkt.payload};
    REQUIRE(pkt_payload.find("httpforever.com") != std::string_view::npos);

    tracker.track(pkt);
    auto& conn = tracker.get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port(), pkt.network_hdr->protocol);
    auto res = classifier.classify(pkt);

    REQUIRE(res == ParseResult::SUCCESS);

    packets.emplace_back(create_packet(pkt));

    REQUIRE(pkt.payload_proto == L7Proto::HTTP);
    REQUIRE(modifier.modify(packets, conn));

    auto& pkt_1 = packets[0];
    REQUIRE(((pkt_1.action.action == PacketAction::Action::DROP_AND_SEND) && (pkt_1.action.packet_id > 0)));
    std::string_view const pkt_1_payload{pkt_1.payload()};
    REQUIRE(pkt_1_payload.find("httpforever.com") == std::string_view::npos);
    REQUIRE(pkt_1.payload_proto == L7Proto::HTTP);

    auto& pkt_2 = packets[1];
    REQUIRE(pkt_2.action.action == PacketAction::Action::SEND);
    std::string_view const pkt_2_payload{pkt_2.payload()};
    REQUIRE(pkt_2_payload.find("httpforever.com") == std::string_view::npos);
    REQUIRE(pkt_2.payload_proto == L7Proto::HTTP);
}

TEST_CASE_METHOD(HttpModifierTestFixture, "Split HTTP request is correctly separated at Host header", "[http_modifier]")
{
    std::span<const char> const packet1{reinterpret_cast<const char*>(split_http_req_1), sizeof(split_http_req_1)};
    // Contains host header
    PacketView pkt1 = parse_packet_view(packet1);
    std::string_view const packet1_payload{pkt1.payload};
    REQUIRE(packet1_payload.find("httpforever.com") != std::string_view::npos);

    std::span<const char> const packet2{reinterpret_cast<const char*>(split_http_req_2), sizeof(split_http_req_2)};
    // Contains the rest of http request
    PacketView pkt2 = parse_packet_view(packet2);
    std::string_view const packet2_payload{pkt2.payload};
    REQUIRE(packet2_payload.find("httpforever.com") == std::string_view::npos);

    tracker.track(pkt1);
    auto& conn = tracker.get_conn(pkt1.network_hdr->saddr, pkt1.get_source_port(), pkt1.network_hdr->daddr, pkt1.get_dest_port(), pkt1.network_hdr->protocol);
    auto res = classifier.classify(pkt1);
    REQUIRE(res == ParseResult::REASSEMBLING);

    tracker.track(pkt2);
    res = classifier.classify(pkt2);
    REQUIRE(res == ParseResult::SUCCESS);

    packets.push_back(create_packet(pkt1));
    packets.push_back(create_packet(pkt2));

    REQUIRE(modifier.modify(packets, conn));
    REQUIRE(packets.size() == 3);

    auto& pkt_1 = packets[0];
    REQUIRE(((pkt_1.action.action == PacketAction::Action::DROP_AND_SEND) && (pkt_1.action.packet_id > 0)));
    std::string_view const pkt_1_payload{pkt_1.payload()};
    REQUIRE(pkt_1_payload.find("httpforever.com") == std::string_view::npos);

    auto& pkt_2 = packets[1];
    REQUIRE(pkt_2.action.action == PacketAction::Action::SEND);
    std::string_view const pkt_2_payload{pkt_2.payload()};
    REQUIRE(pkt_2_payload.find("httpforever.com") == std::string_view::npos);

    auto& pkt_3 = packets[2];
    REQUIRE(pkt_3.action.action == PacketAction::Action::ACCEPT);
    std::string_view const pkt_3_payload{pkt_3.payload()};
    REQUIRE(pkt_3_payload.find("httpforever.com") == std::string_view::npos);
}

static unsigned char http_packet_part_1[] = {0x45, 0x0, 0x0, 0x46, 0x97, 0xa8, 0x40, 0x0, 0x40, 0x6, 0xb0, 0x1, 0xc0, 0xa8, 0x1, 0xa9, 0xac, 0x43, 0x84, 0x73, 0x8c, 0xde, 0x0, 0x50, 0x40, 0x12, 0x12, 0xad, 0xbb, 0x5f, 0xfc, 0x1f, 0x80, 0x18, 0x0, 0x3f, 0xf3, 0x40, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xc2, 0x13, 0x1d, 0xe4, 0x6b, 0xe4, 0x2d, 0xf0, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x48, 0x6f};
static unsigned char http_packet_part_2[] = {0x45, 0x0, 0x0, 0x43, 0x97, 0xa9, 0x40, 0x0, 0x40, 0x6, 0xb0, 0x3, 0xc0, 0xa8, 0x1, 0xa9, 0xac, 0x43, 0x84, 0x73, 0x8c, 0xde, 0x0, 0x50, 0x40, 0x12, 0x12, 0xbf, 0xbb, 0x5f, 0xfc, 0x1f, 0x80, 0x18, 0x0, 0x3f, 0xf3, 0x3d, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xc2, 0x13, 0x1f, 0xd9, 0x6b, 0xe4, 0x2e, 0x77, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65, 0x72};
static unsigned char http_packet_part_3[] = {0x45, 0x0, 0x0, 0x62, 0x97, 0xaa, 0x40, 0x0, 0x40, 0x6, 0xaf, 0xe3, 0xc0, 0xa8, 0x1, 0xa9, 0xac, 0x43, 0x84, 0x73, 0x8c, 0xde, 0x0, 0x50, 0x40, 0x12, 0x12, 0xce, 0xbb, 0x5f, 0xfc, 0x1f, 0x80, 0x18, 0x0, 0x3f, 0xf3, 0x5c, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xc2, 0x13, 0x21, 0xcd, 0x6b, 0xe4, 0x30, 0x6b, 0x2e, 0x63, 0x6f, 0x6d, 0xd, 0xa, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x38, 0x2e, 0x32, 0x31, 0x2e, 0x30, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0xd, 0xa, 0xd, 0xa};

TEST_CASE_METHOD(HttpModifierTestFixture, "Triply split HTTP request is correctly handled", "[http_modifier]")
{
    std::span<const char> const packet1{reinterpret_cast<const char*>(http_packet_part_1), sizeof(http_packet_part_1)};
    std::span<const char> const packet2{reinterpret_cast<const char*>(http_packet_part_2), sizeof(http_packet_part_2)};
    std::span<const char> const packet3{reinterpret_cast<const char*>(http_packet_part_3), sizeof(http_packet_part_3)};

    PacketView pkt1 = parse_packet_view(packet1);
    PacketView pkt2 = parse_packet_view(packet2);
    PacketView pkt3 = parse_packet_view(packet3);

    std::string_view const pkt1_payload{pkt1.payload};
    std::string_view const pkt2_payload{pkt2.payload};
    std::string_view const pkt3_payload{pkt3.payload};
    REQUIRE(pkt1_payload.find("httpforever.com") == std::string_view::npos);
    REQUIRE(pkt2_payload.find("httpforever.com") == std::string_view::npos);
    REQUIRE(pkt3_payload.find("httpforever.com") == std::string_view::npos);
    REQUIRE(pkt1_payload.ends_with("Ho"));
    REQUIRE(pkt2_payload.starts_with("st: httpforever"));
    REQUIRE(pkt3_payload.starts_with(".com"));

    tracker.track(pkt1);
    auto& conn = tracker.get_conn(pkt1.network_hdr->saddr, pkt1.get_source_port(), pkt1.network_hdr->daddr, pkt1.get_dest_port(), pkt1.network_hdr->protocol);
    auto res = classifier.classify(pkt1);
    REQUIRE(res == ParseResult::REASSEMBLING);

    tracker.track(pkt2);
    res = classifier.classify(pkt2);
    REQUIRE(res == ParseResult::REASSEMBLING);

    tracker.track(pkt3);
    res = classifier.classify(pkt3);
    REQUIRE(res == ParseResult::SUCCESS);
    REQUIRE(pkt3.payload_proto == L7Proto::HTTP);

    packets.push_back(create_packet(pkt1));
    packets.push_back(create_packet(pkt2));
    packets.push_back(create_packet(pkt3));

    REQUIRE(modifier.modify(packets, conn));
    REQUIRE(packets.size() == 4);

    // Packet 1: doesn't contain the Host boundary, untouched.
    auto& out_1 = packets[0];
    REQUIRE(out_1.action.action == PacketAction::Action::ACCEPT);
    std::string_view const out_1_payload{out_1.payload()};
    REQUIRE(out_1_payload.find("httpforever.com") == std::string_view::npos);

    // Packet 2 (original) is split in two around the Host boundary.
    auto& out_2 = packets[1];
    REQUIRE(((out_2.action.action == PacketAction::Action::DROP_AND_SEND) && (out_2.action.packet_id > 0)));
    std::string_view const out_2_payload{out_2.payload()};
    REQUIRE(out_2_payload.find("httpforever.com") == std::string_view::npos);

    auto& out_3 = packets[2];
    REQUIRE(out_3.action.action == PacketAction::Action::SEND);
    std::string_view const out_3_payload{out_3.payload()};
    REQUIRE(out_3_payload.find("httpforever.com") == std::string_view::npos);

    // Packet 3 (original) is untouched.
    auto& out_4 = packets[3];
    REQUIRE(out_4.action.action == PacketAction::Action::ACCEPT);
    std::string_view const out_4_payload{out_4.payload()};
    REQUIRE(out_4_payload.find("httpforever.com") == std::string_view::npos);
}

static unsigned char http_req_no_host_hdr[] = {0x45, 0x0, 0x0, 0x6c, 0xd5, 0xd9, 0x40, 0x0, 0x40, 0x6, 0x35, 0x7a, 0xc0, 0xa8, 0x1, 0xa9, 0x68, 0x15, 0x4, 0xd2, 0xc0, 0x30, 0x0, 0x50, 0x16, 0x25, 0xd0, 0xb, 0xf5, 0x79, 0x48, 0x50, 0x80, 0x18, 0x0, 0x3f, 0x2f, 0x97, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x88, 0x93, 0xf, 0x47, 0x12, 0xc7, 0x73, 0xee, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x38, 0x2e, 0x32, 0x31, 0x2e, 0x30, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0xd, 0xa, 0xd, 0xa};
TEST_CASE_METHOD(HttpModifierTestFixture, "No Host header in HTTP request", "[http_modifier]")
{
    std::span<const char> const packet{reinterpret_cast<const char*>(http_req_no_host_hdr), sizeof(http_req_no_host_hdr)};
    PacketView pkt = parse_packet_view(packet);
    std::string_view const pkt_payload{pkt.payload};

    tracker.track(pkt);
    auto& conn = tracker.get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port(), pkt.network_hdr->protocol);
    auto res = classifier.classify(pkt);

    REQUIRE(res == ParseResult::SUCCESS);

    packets.emplace_back(create_packet(pkt));

    REQUIRE(pkt.payload_proto == L7Proto::HTTP);
    REQUIRE_FALSE(modifier.modify(packets, conn));
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

TEST_CASE_METHOD(HttpModifierTestFixture, "Benchmark Vector vs List: full pipeline", "[http_modifier][!benchmark]")
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

TEST_CASE_METHOD(HttpModifierTestFixture, "Benchmark: eager copy vs join_view — realistic fragment counts", "[http_modifier][!benchmark]")
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