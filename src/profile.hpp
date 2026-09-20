//
// Created by klewy on 9/21/26.
//

#ifndef WAIWAIDPI_PROFILE_HPP
#define WAIWAIDPI_PROFILE_HPP
#include "classifier.hpp"
#include "modifiers/dumbass_modifier.hpp"
#include "modifiers/http_host_modifier.hpp"
#include "modifiers/modifier.hpp"
#include "modifiers/tls_modifier.hpp"

#include <print>
#include <toml++/impl/parser.hpp>
#include <toml++/impl/table.hpp>

struct Profile
{
    Classifier classifier;
    Modifier modifier;
};

struct pair_hash
{
    template<typename T, typename U>
    std::size_t operator()(const std::pair<T, U>& pair) const
    {
        return std::hash<T>()(pair.first) ^ std::hash<U>()(pair.second);
    }
};

inline std::unique_ptr<PayloadClassifier> create_classifier(const std::string_view name, const toml::table* table)
{
    if (name == TlsHandshakeClassifier::name()) {
        auto ret = std::make_unique<TlsHandshakeClassifier>();
        ret->parse_config(table);
        return ret;
    } else if (name == HttpClassifier::name()) {
        auto ret = std::make_unique<HttpClassifier>();
        ret->parse_config(table);
        return ret;
    } else {
        throw std::runtime_error(std::format("Unknown classifier name: '{}'", name)) ;
    }
}

inline std::unique_ptr<IModifier> create_modifier(const std::string_view name, const toml::table* table)
{
    if (name == TlsHandshakeModifier::name()) {
        auto ret = std::make_unique<TlsHandshakeModifier>();
        ret->parse_config(table);
        return ret;
    } else if (name == HttpHostModifier::name()) {
        auto ret = std::make_unique<HttpHostModifier>();
        ret->parse_config(table);
        return ret;
    } else if (name == DumbassModifier::name()) {
        auto ret = std::make_unique<DumbassModifier>();
        ret->parse_config(table);
        return ret;
    } else {
        throw std::runtime_error(std::format("Unknown modifier name: '{}'", name));
    }
}

inline std::unordered_map<std::pair<std::uint16_t, int>, Profile, pair_hash> build_profiles(const std::string_view cfg_path, ConnTracker& tracker)
{
    toml::table tbl = toml::parse_file(cfg_path);
    const toml::table* profiles = tbl["profile"].as_table();
    if (profiles == nullptr) {
        throw std::runtime_error("At least 1 profile must be defined");
    }

    std::unordered_map<std::pair<std::uint16_t, int>, Profile, pair_hash> ret;

    for (const auto& profile : *profiles) {
        const auto *const port_node = profile.second.as_table()->get("port");
        if (port_node == nullptr) {
            throw std::runtime_error(std::format("Port is not defined for profile '{}'", profile.first.str()));
        }
        const auto *const protocol_node = profile.second.as_table()->get("protocol");
        if (protocol_node == nullptr) {
            throw std::runtime_error(std::format("Protocol is not defined for profile '{}'", profile.first.str()));
        }

        const auto port = port_node->value<int>().value();
        const auto protocol_str = protocol_node->value<std::string>().value();
        int protocol = 0;
        if (protocol_str == "tcp") {
            protocol = IPPROTO_TCP;
        } else if (protocol_str == "udp") {
            protocol = IPPROTO_UDP;
        } else {
            throw std::runtime_error(std::format("Unknown protocol specified for profile '{}'", profile.first.str()));
        }
        auto [iter, inserted] = ret.insert({{port, protocol}, Profile{.classifier = {tracker}}});
        if (!inserted) { // duplicate
            throw std::runtime_error("Duplicate port,protocol pair");
        }

        const auto *const classifiers_node = profile.second.as_table()->get("classifiers");
        if (classifiers_node == nullptr) {
            throw std::runtime_error(std::format("At least 1 classifier must be defined for a profile '{}'", profile.first.str()));
        }

        for (const auto& classifier : *classifiers_node->as_array()) {
            const auto *const classifier_tbl = classifier.as_table();
            const auto name_opt = classifier_tbl->get("name")->as_string()->value_exact<std::string>();
            if (!name_opt.has_value()) {
                throw std::runtime_error(std::format("Classifier name is not defined in profile '{}'", profile.first.str()));
            }

            auto clf = create_classifier(name_opt.value(), classifier_tbl);
            iter->second.classifier.add(std::move(clf));
            // TODO: add to classifier
        }

        const auto modifiers_node = profile.second.as_table()->get("modifiers");
        if (modifiers_node == nullptr) {
            throw std::runtime_error(std::format("Modifier nae not not defined in profile '{}'", profile.first.str()));
        }

        for (const auto& modifier : *modifiers_node->as_array()) {
            const auto modifier_tbl = modifier.as_table();
            const auto name_opt = modifier_tbl->get("name")->as_string()->value_exact<std::string>();
            if (!name_opt.has_value()) {
                throw std::runtime_error(std::format("Classifier name is not defined in profile '{}'", profile.first.str()));
            }

            // TODO: Build modifier
            auto mdf = create_modifier(name_opt.value(), modifier_tbl);
            iter->second.modifier.add(std::move(mdf));
        }
    }

    return ret;
}

#endif// WAIWAIDPI_PROFILE_HPP
