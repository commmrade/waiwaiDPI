include(cmake/CPM.cmake)

# Done as a function so that updates to variables like
# CMAKE_CXX_FLAGS don't propagate out to other
# targets
function(waiwaiDPI_setup_dependencies)

  # For each dependency, see if it's
  # already been provided to us by a parent project

  if(NOT TARGET spdlog::spdlog)
    cpmaddpackage(
      NAME
      spdlog
      VERSION
      1.17.0
      GITHUB_REPOSITORY
      "gabime/spdlog"
      SYSTEM
      YES
      OPTIONS
      "SPDLOG_FMT_EXTERNAL ON")
  endif()

  set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
  if (NOT TARGET argh::argh)
    cpmaddpackage(
      NAME
      argh
      VERSION
      1.3.2
      GITHUB_REPOSITORY
      "adishavit/argh"
      SYSTEM
      YES
    )
  endif()

  if (NOT TARGET tomlplusplus::tomlplusplus)
    cpmaddpackage(
      NAME
      tomlplusplus
      GIT_TAG master
      GITHUB_REPOSITORY
      "marzer/tomlplusplus"
      SYSTEM
      YES
    )
  endif ()

  if(NOT TARGET Catch2::Catch2WithMain)
    cpmaddpackage(
      NAME
      Catch2
      VERSION
      3.12.0
      GITHUB_REPOSITORY
      "catchorg/Catch2"
      SYSTEM
      YES)
  endif()

  if(NOT TARGET tools::tools)
    cpmaddpackage(
      NAME
      tools
      GITHUB_REPOSITORY
      "lefticus/tools"
      GIT_TAG
      "main")
  endif()

endfunction()
