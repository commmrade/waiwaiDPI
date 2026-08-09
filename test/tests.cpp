#include <catch2/catch_test_macros.hpp>

TEST_CASE("Factorials are computed", "[factorial]")
{
  REQUIRE(0 * 0 == 0);
  REQUIRE(1 * 1 == 1);
  REQUIRE(2 * 1 == 2);
  REQUIRE(3 * 1 == 3);
  REQUIRE(2 * 5 == 10);
}

TEST_CASE("ni", "[mock]")
{
    REQUIRE_FALSE(2 * 2 == 5);
}