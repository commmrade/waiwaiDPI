//
// Created by klewy on 10/19/26.
//

#ifndef WAIWAIDPI_SAFESPAN_HPP
#define WAIWAIDPI_SAFESPAN_HPP

#include <span>

template<typename T>
static bool safe_subspan(std::span<const T> &span, const std::size_t offset)
{
    if (span.size() < offset) { return false; }
    span = span.subspan(offset);
    return true;
}

#endif// WAIWAIDPI_SAFESPAN_HPP
