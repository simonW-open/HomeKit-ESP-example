if(CONFIG_SOFTAPCONFIG_ENABLED)
set(include_dirs
                include
)
set (priv_include_dirs
                              context
)
set(srcs
        "src/softAPConfig.c"
)

endif()

# requirements can't depend on config
idf_component_register( SRCS "${srcs}"
                INCLUDE_DIRS "${include_dirs}"
                PRIV_INCLUDE_DIRS "${priv_include_dirs}"
                PRIV_REQUIRES esp_http_server)

