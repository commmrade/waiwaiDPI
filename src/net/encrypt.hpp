//
// Created by klewy on 11/6/26.
//

#ifndef WAIWAIDPI_ENCRYPT_HPP
#define WAIWAIDPI_ENCRYPT_HPP

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

std::vector<std::uint8_t> hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> keyring);
std::vector<std::uint8_t> hkdf_expand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> info, const std::uint16_t length);
std::vector<std::uint8_t> hkdf_expand_label(std::span <const std::uint8_t> secret, const std::string_view label, std::span<const std::uint8_t> context, const std::uint16_t length);

std::vector<std::uint8_t> header_protection(std::span<const std::uint8_t> hp_key, std::span<const std::uint8_t> sample);

std::vector<std::uint8_t> aead(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> header, std::span<const std::uint8_t> ciphertext);

#endif// WAIWAIDPI_ENCRYPT_HPP
