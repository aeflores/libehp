SET(PROJECT_NAME ehp)


set(${PROJECT_NAME}_H
  ehp_dwarf2.hpp
  ehp_priv.hpp
  scoop_replacement.hpp
)

set(${PROJECT_NAME}_SRC
  ehp.cpp
)

option(EHP_BUILD_SHARED_LIBS "Build shared library." ON)
if(EHP_BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
else()
  set(BUILD_SHARED_LIBS OFF)
endif()

add_library(${PROJECT_NAME}
		${${PROJECT_NAME}_H}
		${${PROJECT_NAME}_SRC}
	)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(PUBLIC_HEADERS
  ${CMAKE_SOURCE_DIR}/include/ehp.hpp
  )

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E remove_directory "${CMAKE_BINARY_DIR}/include")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/include")
add_custom_command(
        TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy
                ${PUBLIC_HEADERS}
                "${CMAKE_BINARY_DIR}/include/")

install(TARGETS ${PROJECT_NAME} EXPORT ehpTargets
  INCLUDES DESTINATION include
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(FILES ${PUBLIC_HEADERS} DESTINATION include)
