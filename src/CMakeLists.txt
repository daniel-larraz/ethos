file(GLOB_RECURSE ethos_SRC CONFIGURE_DEPENDS "*.h" "*.cpp")

add_executable(ethos ${ethos_SRC})

if(APPLE AND NOT BUILD_SHARED_LIBS)
  set_target_properties(cvc5-bin PROPERTIES LINK_FLAGS -static)
  set_target_properties(cvc5-bin PROPERTIES LINK_SEARCH_START_STATIC ON)
  set_target_properties(cvc5-bin PROPERTIES LINK_SEARCH_END_STATIC ON)
endif()

target_link_libraries(ethos ${LIBRARIES})
