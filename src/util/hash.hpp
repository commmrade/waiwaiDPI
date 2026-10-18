//
// Created by klewy on 9/5/26.
//

#ifndef WAIWAIDPI_HASH_HPP
#define WAIWAIDPI_HASH_HPP
#include <climits>
#include <cstddef>
#include <functional>
#include <cstdint>

template<std::size_t Bits> struct hash_mix_impl;

template<> struct hash_mix_impl<64>
{
    inline static std::uint64_t fn( std::uint64_t x )
    {
        std::uint64_t const m = 0xe9846af9b1a615d;

        x ^= x >> 32;
        x *= m;
        x ^= x >> 32;
        x *= m;
        x ^= x >> 28;

        return x;
    }
};

template<> struct hash_mix_impl<32>
{
    inline static std::uint32_t fn( std::uint32_t x )
    {
        std::uint32_t const m1 = 0x21f0aaad;
        std::uint32_t const m2 = 0x735a2d97;

        x ^= x >> 16;
        x *= m1;
        x ^= x >> 15;
        x *= m2;
        x ^= x >> 15;

        return x;
    }
};

inline std::size_t hash_mix( std::size_t v )
{
    return hash_mix_impl<sizeof(std::size_t) * CHAR_BIT>::fn( v );
}

template <class T>
    inline void hash_combine( std::size_t& seed, T const& v )
{
    seed = hash_mix( seed + 0x9e3779b9 + std::hash<T>()( v ) );
}

#endif// WAIWAIDPI_HASH_HPP
