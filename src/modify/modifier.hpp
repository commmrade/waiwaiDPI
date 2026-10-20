//
// Created by klewy on 8/24/26.
//

#ifndef WAIWAIDPI_MODIFIER_HPP
#define WAIWAIDPI_MODIFIER_HPP

#include "conntrack/conn_tracker.hpp"
#include "markers.hpp"
#include "net/packet_view.hpp"
#include <toml++/impl/table.hpp>
#include <vector>

struct ModifyContext
{
    std::vector<char> full_payload;
    Markers markers;
    std::reference_wrapper<const Connection> conn;
};

class IModifier
{
public:
    virtual ~IModifier() = default;

    virtual void modify(std::vector<Packet>& packets, ModifyContext& ctx) = 0;
    [[nodiscard]] virtual bool matches(const std::vector<Packet> &packets,
        const Connection &conn) const = 0;// used to make sure that these packets can be processed by this modifier
    virtual void parse_config([[maybe_unused]] const toml::table *table) {}
    // [[nodiscard]] virtual constexpr std::string_view name() const = 0;
};

class Modifier
{
    std::vector<std::unique_ptr<IModifier>> modifiers_;

public:
    void modify(std::vector<Packet> &vec, const Connection &conn);
    void add(std::unique_ptr<IModifier> modifier) { modifiers_.push_back(std::move(modifier)); }
};

#endif// WAIWAIDPI_MODIFIER_HPP
