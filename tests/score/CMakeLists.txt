## ****************************************************************************
## DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
##
## Copyright 2022 Tino Jungebloud <tino@jungebloud.de>
## 
##
## This confidential and proprietary software may be disclosed,
## used, or copied only as authorized by a license agreement from
## the copyright owner
## ****************************************************************************

add_executable(test__io.mbse.mora.score.cvss 
    test.cvss.cpp
)

target_link_libraries(test__io.mbse.mora.score.cvss
    Boost::filesystem
    Boost::system
    Boost::unit_test_framework
)

if(WIN32)
    target_link_libraries(test__io.mbse.mora.score.cvss
        wsock32 
        ws2_32
    )
endif()

