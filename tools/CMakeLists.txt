SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)



###########################
#      Hypervote test     #
###########################

add_executable(hypervote_setup
    hypervote_setup.cpp
)

target_link_libraries(hypervote_setup
    connection_with_grpc_flatbuffer
)

###########################
#      Sumeragi test      #
###########################

add_executable(test_sumeragi
    test_sumeragi.cpp
)

target_link_libraries(test_sumeragi
    connection_with_grpc_flatbuffer
)

###########################
#      Ametsuchi test      #
###########################

add_executable(check_ametsuchi
    check_ametsuchi.cpp
)

target_link_libraries(check_ametsuchi
    connection_with_grpc_flatbuffer
)

###########################
#      Makesumeragi test  #
###########################

add_executable(make_sumeragi
  make_sumeragi.cpp
)

target_link_libraries(make_sumeragi
  json
  hash
  signature
)


###########################
#      Add peer           #
###########################

add_executable(add_peer
    add_peer.cpp
)

target_link_libraries(add_peer
    membership_service
)
