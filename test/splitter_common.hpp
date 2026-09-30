//
// Created by klewy on 10/1/26.
//

#ifndef WAIWAIDPI_SPLITTER_COMMON_HPP
#define WAIWAIDPI_SPLITTER_COMMON_HPP

#include "../src/checksum.hpp"
#include "../src/modifiers/splitter.hpp"
#include "common.hpp"

#include <catch2/catch_all.hpp>
#include <list>
#include <toml++/toml.hpp>

class SplitterTestFixture
{
protected:
    ConnTracker tracker{};
    Classifier classifier{tracker};
    Modifier modifier;

    std::vector<Packet> packets;
public:
    SplitterTestFixture()
    {
    }

    toml::table get_profile(const std::string_view str)
    {
        auto result = toml::parse(str);
        auto* p = result.as_table()->at_path("profile.1").as_table();
        if (!p) {
            throw std::runtime_error("profile.1 not found or not a table");
        }
        return std::move(*p);
    }

    void build_tls_splitter(const std::string_view str)
    {
        auto profile = get_profile(str);


        classifier.add(std::make_unique<TlsHandshakeClassifier>());
        const auto* modifiers = profile.get("modifiers")->as_array();

        for (const auto& modifier_node : *modifiers) {
            auto* modifier_tbl = modifier_node.as_table();
            auto splitter = std::make_unique<Splitter>();
            splitter->parse_config(modifier_tbl);

            modifier.add(std::move(splitter));
        }
    }

    void build_http_splitter(const std::string_view str)
    {
        auto profile = get_profile(str);


        classifier.add(std::make_unique<HttpClassifier>());
        const auto* modifiers = profile.get("modifiers")->as_array();

        for (const auto& modifier_node : *modifiers) {
            auto* modifier_tbl = modifier_node.as_table();
            auto splitter = std::make_unique<Splitter>();
            splitter->parse_config(modifier_tbl);

            modifier.add(std::move(splitter));
        }
    }
};

#endif// WAIWAIDPI_SPLITTER_COMMON_HPP
