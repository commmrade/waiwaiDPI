//
// Created by klewy on 9/21/26.
//

#ifndef WAIWAIDPI_PROFILE_HPP
#define WAIWAIDPI_PROFILE_HPP
#include "classifier.hpp"
#include "iptables.hpp"
#include "modifiers/modifier.hpp"
#include "modifiers/splitter.hpp"
#include <print>
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

std::unique_ptr<PayloadClassifier> create_classifier(const std::string_view name, const toml::table* table);
std::unique_ptr<IModifier> create_modifier(const std::string_view name, const toml::table* table);
std::unordered_map<std::pair<std::uint16_t, int>, Profile, pair_hash> build_profiles(const std::string_view cfg_path, ConnTracker& tracker, const std::uint32_t queue_number);

#endif// WAIWAIDPI_PROFILE_HPP
