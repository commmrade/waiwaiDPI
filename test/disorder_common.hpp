//
// Created by klewy on 10/12/26.
//

#ifndef WAIWAIDPI_DISORDER_COMMON_HPP
#define WAIWAIDPI_DISORDER_COMMON_HPP
#include "../src/classifier.hpp"
#include "../src/classifiers/tls_classifier.hpp"
#include "../src/conntrack/conn_tracker.hpp"
#include "../src/modify/disorder.hpp"
#include "../src/modify/modifier.hpp"
#include <catch2/catch_all.hpp>
#include <toml++/impl/parser.hpp>

class DisorderTestFixture
{
protected:
    ConnTracker tracker{};
    Classifier classifier{tracker};
    Modifier modifier;

    std::vector<Packet> packets;
public:
    DisorderTestFixture()
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

    void build_disorder(const std::string_view str)
    {
        auto profile = get_profile(str);
        classifier.add(std::make_unique<TlsHandshakeClassifier>());
        const auto* modifiers = profile.get("modifiers")->as_array();

        for (const auto& modifier_node : *modifiers) {
            auto* modifier_tbl = modifier_node.as_table();
            auto disorder = std::make_unique<Disorder>();
            disorder->parse_config(modifier_tbl);

            modifier.add(std::move(disorder));
        }
    }
};

#endif// WAIWAIDPI_DISORDER_COMMON_HPP
