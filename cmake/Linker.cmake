macro(waiwaiDPI_configure_linker project_name)
  set(waiwaiDPI_USER_LINKER_OPTION
    "DEFAULT"
      CACHE STRING "Linker to be used")
    set(waiwaiDPI_USER_LINKER_OPTION_VALUES "DEFAULT" "SYSTEM" "LLD" "GOLD" "BFD" "MOLD" "SOLD" "APPLE_CLASSIC" "MSVC")
  set_property(CACHE waiwaiDPI_USER_LINKER_OPTION PROPERTY STRINGS ${waiwaiDPI_USER_LINKER_OPTION_VALUES})
  list(
    FIND
    waiwaiDPI_USER_LINKER_OPTION_VALUES
    ${waiwaiDPI_USER_LINKER_OPTION}
    waiwaiDPI_USER_LINKER_OPTION_INDEX)

  if(${waiwaiDPI_USER_LINKER_OPTION_INDEX} EQUAL -1)
    message(
      STATUS
        "Using custom linker: '${waiwaiDPI_USER_LINKER_OPTION}', explicitly supported entries are ${waiwaiDPI_USER_LINKER_OPTION_VALUES}")
  endif()

  set_target_properties(${project_name} PROPERTIES LINKER_TYPE "${waiwaiDPI_USER_LINKER_OPTION}")
endmacro()
