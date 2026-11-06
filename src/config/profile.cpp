//
// Created by klewy on 9/21/26.
//

#include "profile.hpp"
#include "../classify/tcp/http_classifier.hpp"
#include "../classify/tcp/tls_classifier.hpp"
#include "../modify/tcp/disorder.hpp"
#include "../modify/tcp/splitter.hpp"
#include "../classify/udp/quic_classifier.hpp"
#include "sys/iptables.hpp"

#include <arpa/inet.h>

#define LIST_CLASSIFIER_TYPES TlsHandshakeClassifier, HttpClassifier, QuicClassifier
#define LIST_MODIFIER_TYPES Splitter, Disorder

template<typename ... Ts>
std::unique_ptr<PayloadClassifier> create_classifier_impl(const std::string_view name, const int transport_proto)
{
    std::unique_ptr<PayloadClassifier> ret;

    auto try_one = [&]<typename T> {
        if (ret || name != T::name()) {
            return;
        }
        if (transport_proto != T::transport_protocol()) {
            throw std::runtime_error(std::format("{} protocol is not supported for {}", transport_proto, name));
        }

        ret = std::make_unique<T>();
    };

    (try_one.template operator()<Ts>(), ...);
    return ret;
}

std::unique_ptr<PayloadClassifier> create_classifier(const std::string_view name, const int transport_proto, const toml::table *table)
{
    auto ret = create_classifier_impl<LIST_CLASSIFIER_TYPES>(name, transport_proto);

    if (!ret) {
        throw std::runtime_error(std::format("There is no '{}' classifier", name));
    }

    ret->parse_config(table);
    return ret;
}


template<typename ... Ts>
std::unique_ptr<IModifier> create_modifier_impl(const std::string_view name, const int transport_proto)
{
    std::unique_ptr<IModifier> ret;

    auto try_one = [&]<typename T> {
        if (ret || name != T::name()) {
            return;
        }
        if (transport_proto != T::transport_protocol()) {
            throw std::runtime_error(std::format("{} protocol is not supported for {}", transport_proto, name));
        }

        ret = std::make_unique<T>();
    };

    (try_one.template operator()<Ts>(), ...);

    return ret;
}

std::unique_ptr<IModifier> create_modifier(const std::string_view name, const int transport_proto, const toml::table *table)
{
    auto ret = create_modifier_impl<LIST_MODIFIER_TYPES>(name, transport_proto);

    if (!ret) {
        throw std::runtime_error(std::format("There is no '{}' modifier", name));
    }

    ret->parse_config(table);
    return ret;
}

std::unordered_map<std::pair<std::uint16_t, int>, Profile, pair_hash>
    build_profiles(const std::string_view cfg_path, [[maybe_unused]] const ConnTracker &tracker, const std::uint32_t queue_number)
{
    toml::table tbl = toml::parse_file(cfg_path);
    const toml::table *profiles = tbl["profile"].as_table();
    if (profiles == nullptr) { throw std::runtime_error("At least 1 profile must be defined"); }

    std::unordered_map<std::pair<std::uint16_t, int>, Profile, pair_hash> ret;


    for (const auto &profile : *profiles) {
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
        auto [iter, inserted] = ret.insert({ { port, protocol }, Profile{} });
        if (!inserted) {// duplicate
            throw std::runtime_error("Duplicate port,protocol pair");
        }

        const auto* const allowed_ips_node = profile.second.as_table()->get("allowed_ips");
        if (allowed_ips_node != nullptr) {
            std::unordered_set<std::uint32_t> allowed_ips;
            if (!allowed_ips_node->is_array()) { throw std::runtime_error("allowed_ips must be an array"); }

            const auto *ips_array = allowed_ips_node->as_array();
            auto& ips = allowed_ips;
            ips.reserve(ips_array->size());

            for (const auto &node : *ips_array) {
                if (!node.is_string()) { throw std::runtime_error("All ips must be strings"); }

                const auto addr_str = node.as_string()->get();
                std::uint32_t addr = 0;
                int ret = inet_pton(AF_INET, addr_str.data(), &addr);
                if (ret != 1) { throw std::runtime_error(std::format("Could not convert address '{}'", addr_str)); }

                ips.insert(addr);
            }

            iter->second.modifier.set_allowed_ips(allowed_ips);
        }

        const auto *hosts_node = profile.second.as_table()->get("allowed_hosts");
        if (hosts_node != nullptr) {
            std::unordered_set<std::string> allowed_hosts;
            if (!hosts_node->is_array()) { throw std::runtime_error("allowed_hosts must be an array"); }

            const auto *hosts_array = hosts_node->as_array();
            allowed_hosts.reserve(hosts_array->size());
            for (const auto &node : *hosts_array) {
                if (!node.is_string()) { throw std::runtime_error("All hosts must be strings"); }

                allowed_hosts.insert(node.as_string()->get());
            }

            iter->second.modifier.set_allowed_hosts(allowed_hosts);
        }

        const auto *const classifiers_node = profile.second.as_table()->get("classifiers");
        if (classifiers_node == nullptr) {
            throw std::runtime_error(
                std::format("At least 1 classifier must be defined for a profile '{}'", profile.first.str()));
        }

        for (const auto &classifier : *classifiers_node->as_array()) {
            const auto *const classifier_tbl = classifier.as_table();
            const auto name_opt = classifier_tbl->get("name")->as_string()->value_exact<std::string>();
            if (!name_opt.has_value()) {
                throw std::runtime_error(
                    std::format("Classifier name is not defined in profile '{}'", profile.first.str()));
            }

            auto clf = create_classifier(name_opt.value(), protocol, classifier_tbl);
            iter->second.classifier.add(std::move(clf));
        }

        const auto modifiers_node = profile.second.as_table()->get("modifiers");
        if (modifiers_node == nullptr) {
            // throw std::runtime_error(std::format("Modifier nae not not defined in profile '{}'", profile.first.str()));
        }

        // for (const auto &modifier : *modifiers_node->as_array()) {
        //     const auto modifier_tbl = modifier.as_table();
        //     const auto name_opt = modifier_tbl->get("name")->as_string()->value_exact<std::string>();
        //     if (!name_opt.has_value()) {
        //         throw std::runtime_error(
        //             std::format("Classifier name is not defined in profile '{}'", profile.first.str()));
        //     }
        //
        //     auto mdf = create_modifier(name_opt.value(), protocol, modifier_tbl);
        //     iter->second.modifier.add(std::move(mdf));
        // }


        // set up a rule
        if (!rule_exists(std::format("-A OUTPUT -p {} -m {} --dport {} "
                                     "-m connbytes --connbytes 0:{} --connbytes-dir original --connbytes-mode packets "
                                     "-j NFQUEUE --queue-num {}",
                protocol_str,
                protocol_str,
                port,
                Connection::MAX_REASM_SEGMENTS(),
                queue_number))) {
            rule_add(
                std::format("iptables -A OUTPUT -p {} --dport {} "
                            "-m connbytes --connbytes 0:{} --connbytes-dir original --connbytes-mode packets "
                            "-j NFQUEUE --queue-num {}",
                    protocol_str,
                    port,
                    Connection::MAX_REASM_SEGMENTS(),
                    queue_number));
        }
    }

    return ret;
}