//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_PROTOCOL_HPP
#define WAIWAIDPI_PROTOCOL_HPP

enum class L7Proto
{
    UNKNOWN, // Unknown payload, but packets may be modified
    REASSEMBLING, // In this case payload isn't assembled and packets should be held, packets can't be modified
    HTTP,
    TLS_HANDSHAKE,
};

#endif// WAIWAIDPI_PROTOCOL_HPP
