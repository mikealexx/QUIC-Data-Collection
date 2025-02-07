event_type = [
    "CANCELLED",
    "FAILED",
    "REQUEST_ALIVE",
    "HOST_RESOLVER_MANAGER_REQUEST",
    "HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK",
    "HOST_RESOLVER_MANAGER_CACHE_HIT",
    "HOST_RESOLVER_MANAGER_HOSTS_HIT",
    "HOST_RESOLVER_MANAGER_CONFIG_PRESET_MATCH",
    "HOST_RESOLVER_MANAGER_CREATE_JOB",
    "HOST_RESOLVER_MANAGER_JOB",
    "HOST_RESOLVER_MANAGER_JOB_EVICTED",
    "HOST_RESOLVER_MANAGER_JOB_STARTED",
    "HOST_RESOLVER_MANAGER_ATTEMPT_STARTED",
    "HOST_RESOLVER_MANAGER_ATTEMPT_FINISHED",
    "HOST_RESOLVER_MANAGER_JOB_ATTACH",
    "HOST_RESOLVER_MANAGER_JOB_REQUEST_ATTACH",
    "HOST_RESOLVER_MANAGER_JOB_REQUEST_DETACH",
    "HOST_RESOLVER_SYSTEM_TASK",
    "HOST_RESOLVER_DNS_TASK",
    "HOST_RESOLVER_DNS_TASK_EXTRACTION_FAILURE",
    "HOST_RESOLVER_DNS_TASK_EXTRACTION_RESULTS",
    "HOST_RESOLVER_DNS_TASK_TIMEOUT",
    "HOST_RESOLVER_SERVICE_ENDPOINTS_UPDATED",
    "HOST_RESOLVER_SERVICE_ENDPOINTS_STALE_RESULTS",
    "HOST_RESOLVER_SERVICE_ENDPOINTS_RESOLUTION_DELAY",
    "PAC_FILE_DECIDER",
    "PAC_FILE_DECIDER_WAIT",
    "PAC_FILE_DECIDER_FETCH_PAC_SCRIPT",
    "PAC_FILE_DECIDER_HAS_NO_FETCHER",
    "PAC_FILE_DECIDER_FALLING_BACK_TO_NEXT_PAC_SOURCE",
    "PROXY_RESOLUTION_SERVICE",
    "PROXY_RESOLUTION_SERVICE_WAITING_FOR_INIT_PAC",
    "PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST",
    "PROXY_RESOLUTION_SERVICE_DEPRIORITIZED_BAD_PROXIES",
    "PROXY_CONFIG_CHANGED",
    "BAD_PROXY_LIST_REPORTED",
    "PROXY_LIST_FALLBACK",
    "PAC_JAVASCRIPT_ERROR",
    "PAC_JAVASCRIPT_ALERT",
    "WAITING_FOR_PROXY_RESOLVER_THREAD",
    "SUBMITTED_TO_RESOLVER_THREAD",
    "SOCKET_ALIVE",
    "SOCKET_OPEN",
    "SOCKET_CONNECT",
    "SOCKET_BIND_TO_NETWORK",
    "BROKERED_SOCKET_ALIVE",
    "BROKERED_CREATE_SOCKET",
    "TCP_CONNECT",
    "TCP_CONNECT_ATTEMPT",
    "TCP_ACCEPT",
    "SOCKET_IN_USE",
    "SOCKS_CONNECT",
    "SOCKS5_CONNECT",
    "SOCKS_HOSTNAME_TOO_BIG",
    "SOCKS_UNEXPECTEDLY_CLOSED_DURING_GREETING",
    "SOCKS_UNEXPECTEDLY_CLOSED_DURING_HANDSHAKE",
    "SOCKS_UNEXPECTED_VERSION",
    "SOCKS_SERVER_ERROR",
    "SOCKS_UNEXPECTED_AUTH",
    "SOCKS_UNKNOWN_ADDRESS_TYPE",
    "SSL_CONNECT",
    "SSL_ECH_CONFIG_LIST",
    "SSL_SERVER_HANDSHAKE",
    "SSL_CLIENT_CERT_REQUESTED",
    "SSL_PRIVATE_KEY_OP",
    "SSL_CLIENT_CERT_PROVIDED",
    "SSL_HANDSHAKE_ERROR",
    "SSL_READ_ERROR",
    "SSL_WRITE_ERROR",
    "SSL_VERIFICATION_MERGED",
    "SSL_ALERT_RECEIVED",
    "SSL_ALERT_SENT",
    "SSL_CONFIRM_HANDSHAKE",
    "SSL_HANDSHAKE_MESSAGE_RECEIVED",
    "SSL_HANDSHAKE_MESSAGE_SENT",
    "SSL_ENCRYPTED_CLIENT_HELLO",
    "SSL_HANDSHAKE_EARLY_DATA_REASON",
    "SOCKET_BYTES_SENT",
    "SSL_SOCKET_BYTES_SENT",
    "SOCKET_BYTES_RECEIVED",
    "SSL_SOCKET_BYTES_RECEIVED",
    "SOCKET_READ_ERROR",
    "SOCKET_WRITE_ERROR",
    "SOCKET_CLOSED",
    "SSL_CERTIFICATES_RECEIVED",
    "SIGNED_CERTIFICATE_TIMESTAMPS_RECEIVED",
    "SIGNED_CERTIFICATE_TIMESTAMPS_CHECKED",
    "CERT_CT_COMPLIANCE_CHECKED",
    "CT_LOG_ENTRY_AUDITED",
    "UDP_CONNECT",
    "UDP_LOCAL_ADDRESS",
    "UDP_BYTES_RECEIVED",
    "UDP_BYTES_SENT",
    "UDP_RECEIVE_ERROR",
    "UDP_SEND_ERROR",
    "CONNECT_JOB",
    "CONNECT_JOB_SET_SOCKET",
    "CONNECT_JOB_TIMED_OUT",
    "TRANSPORT_CONNECT_JOB_CONNECT",
    "SSL_CONNECT_JOB_CONNECT",
    "SOCKS_CONNECT_JOB_CONNECT",
    "HTTP_PROXY_CONNECT_JOB_CONNECT",
    "SSL_CONNECT_JOB_RESTART_WITH_ECH_CONFIG_LIST",
    "TRANSPORT_CONNECT_JOB_IPV6_FALLBACK",
    "TRANSPORT_CONNECT_JOB_CONNECT_ATTEMPT",
    "SSL_CONNECT_JOB_SSL_CONNECT",
    "SOCKET_POOL",
    "SOCKET_POOL_STALLED_MAX_SOCKETS",
    "SOCKET_POOL_STALLED_MAX_SOCKETS_PER_GROUP",
    "SOCKET_POOL_REUSED_AN_EXISTING_SOCKET",
    "TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET",
    "TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKETS",
    "SOCKET_POOL_CONNECT_JOB_CREATED",
    "SOCKET_POOL_BOUND_TO_CONNECT_JOB",
    "SOCKET_POOL_BOUND_TO_SOCKET",
    "SOCKET_POOL_CONNECTING_N_SOCKETS",
    "SOCKET_POOL_CLOSING_SOCKET",
    "STREAM_ATTEMPT_BOUND_TO_POOL",
    "TCP_STREAM_ATTEMPT_ALIVE",
    "TCP_STREAM_ATTEMPT_CONNECT",
    "TLS_STREAM_ATTEMPT_ALIVE",
    "TLS_STREAM_ATTEMPT_WAIT_FOR_SSL_CONFIG",
    "TLS_STREAM_ATTEMPT_CONNECT",
    "URL_REQUEST_START_JOB",
    "URL_REQUEST_REDIRECTED",
    "URL_REQUEST_RETRY_WITH_STORAGE_ACCESS",
    "NETWORK_DELEGATE_BEFORE_START_TRANSACTION",
    "NETWORK_DELEGATE_BEFORE_URL_REQUEST",
    "NETWORK_DELEGATE_HEADERS_RECEIVED",
    "URL_REQUEST_DELEGATE_CERTIFICATE_REQUESTED",
    "URL_REQUEST_DELEGATE_RECEIVED_REDIRECT",
    "URL_REQUEST_DELEGATE_RESPONSE_STARTED",
    "URL_REQUEST_DELEGATE_SSL_CERTIFICATE_ERROR",
    "URL_REQUEST_DELEGATE_CONNECTED",
    "DELEGATE_INFO",
    "URL_REQUEST_JOB_BYTES_READ",
    "URL_REQUEST_JOB_FILTERED_BYTES_READ",
    "URL_REQUEST_SET_PRIORITY",
    "URL_REQUEST_REDIRECT_JOB",
    "URL_REQUEST_FAKE_RESPONSE_HEADERS_CREATED",
    "URL_REQUEST_FILTERS_SET",
    "HTTP_CACHE_GET_BACKEND",
    "HTTP_CACHE_OPEN_OR_CREATE_ENTRY",
    "HTTP_CACHE_OPEN_ENTRY",
    "HTTP_CACHE_CREATE_ENTRY",
    "HTTP_CACHE_ADD_TO_ENTRY",
    "HTTP_CACHE_DOOM_ENTRY",
    "HTTP_CACHE_READ_INFO",
    "HTTP_CACHE_WRITE_INFO",
    "HTTP_CACHE_READ_DATA",
    "HTTP_CACHE_WRITE_DATA",
    "HTTP_CACHE_CALLER_REQUEST_HEADERS",
    "HTTP_CACHE_RESTART_PARTIAL_REQUEST",
    "HTTP_CACHE_RE_SEND_PARTIAL_REQUEST",
    "HTTP_CACHE_USING_NO_VARY_SEARCH_CACHE_URL",
    "DISK_CACHE_ENTRY_IMPL",
    "DISK_CACHE_MEM_ENTRY_IMPL",
    "ENTRY_READ_DATA",
    "ENTRY_WRITE_DATA",
    "SPARSE_READ",
    "SPARSE_WRITE",
    "SPARSE_READ_CHILD_DATA",
    "SPARSE_WRITE_CHILD_DATA",
    "SPARSE_GET_RANGE",
    "SPARSE_DELETE_CHILDREN",
    "ENTRY_CLOSE",
    "ENTRY_DOOM",
    "HTTP_STREAM_REQUEST",
    "HTTP_STREAM_JOB",
    "HTTP_STREAM_JOB_WAITING",
    "HTTP_STREAM_REQUEST_STARTED_JOB",
    "HTTP_STREAM_JOB_THROTTLED",
    "HTTP_STREAM_JOB_RESUME_INIT_CONNECTION",
    "HTTP_STREAM_JOB_INIT_CONNECTION",
    "HTTP_STREAM_REQUEST_BOUND_TO_JOB",
    "HTTP_STREAM_JOB_BOUND_TO_REQUEST",
    "HTTP_STREAM_REQUEST_PROTO",
    "HTTP_STREAM_JOB_ORPHANED",
    "HTTP_STREAM_JOB_DELAYED",
    "HTTP_STREAM_JOB_RESUMED",
    "HTTP_STREAM_JOB_CONTROLLER",
    "HTTP_STREAM_JOB_CONTROLLER_BOUND",
    "HTTP_STREAM_JOB_CONTROLLER_PROXY_SERVER_RESOLVED",
    "HTTP_STREAM_JOB_CONTROLLER_ALT_SVC_FOUND",
    "HTTP_STREAM_POOL_CONSISTENCY_CHECK_OK",
    "HTTP_STREAM_POOL_CONSISTENCY_CHECK_FAIL",
    "HTTP_STREAM_POOL_CLOSING_SOCKET",
    "HTTP_STREAM_POOL_JOB_CONTROLLER_ALIVE",
    "HTTP_STREAM_POOL_JOB_CONTROLLER_FOUND_EXISTING_SPDY_SESSION",
    "HTTP_STREAM_POOL_JOB_CONTROLLER_FOUND_EXISTING_QUIC_SESSION",
    "HTTP_STREAM_POOL_JOB_CONTROLLER_JOB_BOUND",
    "HTTP_STREAM_POOL_JOB_CONTROLLER_PRECONNECT_BOUND",
    "HTTP_STREAM_POOL_JOB_ALIVE",
    "HTTP_STREAM_POOL_GROUP_ALIVE",
    "HTTP_STREAM_POOL_GROUP_ATTEMPT_MANAGER_CREATED",
    "HTTP_STREAM_POOL_GROUP_HANDLE_CREATED",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_START_JOB",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_JOB_BOUND",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_PRECONNECT",
    "HTTP_STREAM_POOL_GROUP_ATTEMPT_MANAGER_DESTROYED",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_ALIVE",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_ATTEMPT_START",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_ATTEMPT_END",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_NOTIFY_FAILURE",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_DNS_RESOLUTION_UPDATED",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_DNS_RESOLUTION_FINISHED",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_EXISTING_SPDY_SESSION_MATCHED",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_EXISTING_QUIC_SESSION_MATCHED",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_STREAM_ATTEMPT_DELAY_PASSED",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_QUIC_TASK_BOUND",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_QUIC_TASK_MAYBE_ATTEMPT",
    "HTTP_STREAM_POOL_ATTEMPT_MANAGER_QUIC_TASK_COMPLETED",
    "HTTP_STREAM_POOL_QUIC_TASK_ALIVE",
    "HTTP_STREAM_POOL_QUIC_ATTEMPT_START",
    "HTTP_STREAM_POOL_QUIC_ATTEMPT_END",
    "HTTP_TRANSACTION_TUNNEL_SEND_REQUEST",
    "HTTP_TRANSACTION_SEND_TUNNEL_HEADERS",
    "HTTP_TRANSACTION_TUNNEL_READ_HEADERS",
    "HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS",
    "HTTP_TRANSACTION_SEND_REQUEST",
    "HTTP_TRANSACTION_SEND_REQUEST_HEADERS",
    "HTTP_TRANSACTION_SEND_REQUEST_BODY",
    "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS",
    "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS",
    "HTTP_TRANSACTION_READ_HEADERS",
    "HTTP_TRANSACTION_READ_RESPONSE_HEADERS",
    "HTTP_TRANSACTION_READ_EARLY_HINTS_RESPONSE_HEADERS",
    "HTTP_TRANSACTION_READ_BODY",
    "HTTP_TRANSACTION_DRAIN_BODY_FOR_AUTH_RESTART",
    "HTTP_TRANSACTION_RESTART_AFTER_ERROR",
    "HTTP_TRANSACTION_RESTART_MISDIRECTED_REQUEST",
    "BIDIRECTIONAL_STREAM_ALIVE",
    "BIDIRECTIONAL_STREAM_READ_DATA",
    "BIDIRECTIONAL_STREAM_SENDV_DATA",
    "BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED",
    "BIDIRECTIONAL_STREAM_BYTES_SENT",
    "BIDIRECTIONAL_STREAM_BYTES_RECEIVED",
    "BIDIRECTIONAL_STREAM_RECV_HEADERS",
    "BIDIRECTIONAL_STREAM_RECV_TRAILERS",
    "BIDIRECTIONAL_STREAM_READY",
    "BIDIRECTIONAL_STREAM_FAILED",
    "BIDIRECTIONAL_STREAM_BOUND_TO_QUIC_SESSION",
    "HTTP2_SESSION",
    "HTTP2_SESSION_INITIALIZED",
    "HTTP2_SESSION_SEND_HEADERS",
    "HTTP2_SESSION_RECV_HEADERS",
    "HTTP2_SESSION_SEND_SETTINGS",
    "HTTP2_SESSION_SEND_SETTINGS_ACK",
    "HTTP2_SESSION_RECV_ACCEPT_CH",
    "HTTP2_SESSION_RECV_SETTINGS",
    "HTTP2_SESSION_RECV_SETTING",
    "HTTP2_SESSION_RECV_SETTINGS_ACK",
    "HTTP2_SESSION_RECV_RST_STREAM",
    "HTTP2_SESSION_SEND_RST_STREAM",
    "HTTP2_SESSION_PING",
    "HTTP2_SESSION_RECV_GOAWAY",
    "HTTP2_SESSION_RECV_WINDOW_UPDATE",
    "HTTP2_SESSION_SEND_WINDOW_UPDATE",
    "HTTP2_SESSION_UPDATE_SEND_WINDOW",
    "HTTP2_SESSION_UPDATE_RECV_WINDOW",
    "HTTP2_SESSION_RECV_INVALID_HEADER",
    "HTTP2_SESSION_SEND_DATA",
    "HTTP2_SESSION_RECV_DATA",
    "HTTP2_SESSION_STREAM_STALLED_BY_SESSION_SEND_WINDOW",
    "HTTP2_SESSION_STREAM_STALLED_BY_STREAM_SEND_WINDOW",
    "HTTP2_SESSION_CLOSE",
    "HTTP2_SESSION_STALLED_MAX_STREAMS",
    "HTTP2_SESSION_INITIAL_WINDOW_SIZE_OUT_OF_RANGE",
    "HTTP2_SESSION_UPDATE_STREAMS_SEND_WINDOW_SIZE",
    "HTTP2_SESSION_SEND_GREASED_FRAME",
    "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION",
    "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION_FROM_IP_POOL",
    "HTTP2_SESSION_POOL_CREATED_NEW_SESSION",
    "HTTP2_SESSION_POOL_IMPORTED_SESSION_FROM_SOCKET",
    "HTTP2_SESSION_POOL_REMOVE_SESSION",
    "HTTP2_STREAM",
    "HTTP2_STREAM_FLOW_CONTROL_UNSTALLED",
    "HTTP2_STREAM_UPDATE_SEND_WINDOW",
    "HTTP2_STREAM_UPDATE_RECV_WINDOW",
    "HTTP2_STREAM_ERROR",
    "HTTP2_STREAM_SEND_PRIORITY",
    "HTTP2_PROXY_CLIENT_SESSION",
    "QUIC_SESSION_POOL_USE_EXISTING_SESSION",
    "QUIC_SESSION_POOL_ATTACH_HTTP_STREAM_JOB_TO_EXISTING_SESSION",
    "QUIC_SESSION_POOL_PLATFORM_NOTIFICATION",
    "QUIC_SESSION_POOL_ON_IP_ADDRESS_CHANGED",
    "QUIC_SESSION_POOL_MATCHING_IP_SESSION_FOUND",
    "QUIC_SESSION_POOL_POOLED_WITH_DIFFERENT_IP_SESSION",
    "QUIC_SESSION_POOL_CAN_POOL_BUT_DIFFERENT_IP",
    "QUIC_SESSION_POOL_CANNOT_POOL_WITH_EXISTING_SESSIONS",
    "QUIC_SESSION_POOL_CLOSE_ALL_SESSIONS",
    "QUIC_SESSION_POOL_MARK_ALL_ACTIVE_SESSIONS_GOING_AWAY",
    "QUIC_SESSION_POOL_JOB",
    "QUIC_SESSION_POOL_JOB_BOUND_TO",
    "BOUND_TO_QUIC_SESSION_POOL_JOB",
    "QUIC_SESSION_POOL_JOB_CONNECT",
    "QUIC_SESSION_POOL_PROXY_JOB_CONNECT",
    "QUIC_SESSION_POOL_PROXY_JOB_CREATE_PROXY_SESSION",
    "QUIC_SESSION_POOL_JOB_RETRY_ON_ALTERNATE_NETWORK",
    "QUIC_SESSION_POOL_JOB_STALE_HOST_TRIED_ON_CONNECTION",
    "QUIC_SESSION_POOL_JOB_STALE_HOST_NOT_USED_ON_CONNECTION",
    "QUIC_SESSION_POOL_JOB_STALE_HOST_RESOLUTION_NO_MATCH",
    "QUIC_SESSION_POOL_JOB_STALE_HOST_RESOLUTION_MATCHED",
    "QUIC_SESSION_POOL_JOB_RESULT",
    "QUIC_SESSION",
    "QUIC_SESSION_CREATED",
    "QUIC_SESSION_CLOSE_ON_ERROR",
    "QUIC_SESSION_CERTIFICATE_VERIFY_FAILED",
    "QUIC_SESSION_CERTIFICATE_VERIFIED",
    "QUIC_SESSION_PACKET_RECEIVED",
    "QUIC_SESSION_PACKET_SENT",
    "QUIC_SESSION_PACKET_RETRANSMITTED",
    "QUIC_SESSION_PACKET_LOST",
    "QUIC_CONGESTION_CONTROL_CONFIGURED",
    "QUIC_SESSION_DUPLICATE_PACKET_RECEIVED",
    "QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED",
    "QUIC_SESSION_PACKET_AUTHENTICATED",
    "QUIC_SESSION_STREAM_FRAME_RECEIVED",
    "QUIC_SESSION_STREAM_FRAME_SENT",
    "QUIC_SESSION_STREAM_FRAME_COALESCED",
    "QUIC_SESSION_ACK_FRAME_RECEIVED",
    "QUIC_SESSION_ACK_FRAME_SENT",
    "QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED",
    "QUIC_SESSION_WINDOW_UPDATE_FRAME_SENT",
    "QUIC_SESSION_BLOCKED_FRAME_RECEIVED",
    "QUIC_SESSION_BLOCKED_FRAME_SENT",
    "QUIC_SESSION_GOAWAY_FRAME_RECEIVED",
    "QUIC_SESSION_GOAWAY_FRAME_SENT",
    "QUIC_SESSION_PING_FRAME_RECEIVED",
    "QUIC_SESSION_PING_FRAME_SENT",
    "QUIC_SESSION_MTU_DISCOVERY_FRAME_SENT",
    "QUIC_SESSION_STOP_WAITING_FRAME_RECEIVED",
    "QUIC_SESSION_STOP_WAITING_FRAME_SENT",
    "QUIC_SESSION_RST_STREAM_FRAME_RECEIVED",
    "QUIC_SESSION_RST_STREAM_FRAME_SENT",
    "QUIC_SESSION_CONNECTION_CLOSE_FRAME_RECEIVED",
    "QUIC_SESSION_CONNECTION_CLOSE_FRAME_SENT",
    "QUIC_SESSION_PUBLIC_RESET_PACKET_RECEIVED",
    "QUIC_SESSION_VERSION_NEGOTIATION_PACKET_RECEIVED",
    "QUIC_SESSION_VERSION_NEGOTIATED",
    "QUIC_SESSION_PACKET_HEADER_REVIVED",
    "QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_RECEIVED",
    "QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_SENT",
    "QUIC_SESSION_TRANSPORT_PARAMETERS_RECEIVED",
    "QUIC_SESSION_TRANSPORT_PARAMETERS_SENT",
    "QUIC_SESSION_TRANSPORT_PARAMETERS_RESUMED",
    "QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE",
    "QUIC_SESSION_WEBTRANSPORT_CLIENT_STATE_CHANGED",
    "QUIC_SESSION_WEBTRANSPORT_SESSION_READY",
    "QUIC_SESSION_ZERO_RTT_REJECTED",
    "QUIC_SESSION_ZERO_RTT_STATE",
    "QUIC_SESSION_NETWORK_MADE_DEFAULT",
    "QUIC_SESSION_NETWORK_DISCONNECTED",
    "QUIC_SESSION_NETWORK_CONNECTED",
    "QUIC_SESSION_CLOSED",
    "QUIC_SESSION_CONNECTIVITY_PROBING_FINISHED",
    "QUIC_SESSION_PATH_CHALLENGE_FRAME_SENT",
    "QUIC_SESSION_PATH_CHALLENGE_FRAME_RECEIVED",
    "QUIC_SESSION_PATH_RESPONSE_FRAME_SENT",
    "QUIC_SESSION_PATH_RESPONSE_FRAME_RECEIVED",
    "QUIC_SESSION_CRYPTO_FRAME_SENT",
    "QUIC_SESSION_CRYPTO_FRAME_RECEIVED",
    "QUIC_SESSION_STOP_SENDING_FRAME_SENT",
    "QUIC_SESSION_STOP_SENDING_FRAME_RECEIVED",
    "QUIC_SESSION_STREAMS_BLOCKED_FRAME_SENT",
    "QUIC_SESSION_STREAMS_BLOCKED_FRAME_RECEIVED",
    "QUIC_SESSION_MAX_STREAMS_FRAME_SENT",
    "QUIC_SESSION_MAX_STREAMS_FRAME_RECEIVED",
    "QUIC_SESSION_PADDING_FRAME_SENT",
    "QUIC_SESSION_PADDING_FRAME_RECEIVED",
    "QUIC_SESSION_NEW_CONNECTION_ID_FRAME_SENT",
    "QUIC_SESSION_NEW_CONNECTION_ID_FRAME_RECEIVED",
    "QUIC_SESSION_NEW_TOKEN_FRAME_SENT",
    "QUIC_SESSION_NEW_TOKEN_FRAME_RECEIVED",
    "QUIC_SESSION_RETIRE_CONNECTION_ID_FRAME_SENT",
    "QUIC_SESSION_RETIRE_CONNECTION_ID_FRAME_RECEIVED",
    "QUIC_SESSION_MESSAGE_FRAME_SENT",
    "QUIC_SESSION_MESSAGE_FRAME_RECEIVED",
    "QUIC_SESSION_HANDSHAKE_DONE_FRAME_RECEIVED",
    "QUIC_ACCEPT_CH_FRAME_RECEIVED",
    "QUIC_SESSION_COALESCED_PACKET_SENT",
    "QUIC_SESSION_BUFFERED_UNDECRYPTABLE_PACKET",
    "QUIC_SESSION_DROPPED_UNDECRYPTABLE_PACKET",
    "QUIC_SESSION_ATTEMPTING_TO_PROCESS_UNDECRYPTABLE_PACKET",
    "QUIC_SESSION_KEY_UPDATE",
    "QUIC_SESSION_ORIGIN_FRAME_RECEIVED",
    "HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION",
    "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS",
    "QUIC_CHROMIUM_CLIENT_STREAM_READ_EARLY_HINTS_RESPONSE_HEADERS",
    "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS",
    "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_TRAILERS",
    "QUIC_CONNECTION_MIGRATION_MODE",
    "QUIC_CONNECTION_MIGRATION_TRIGGERED",
    "QUIC_CONNECTION_MIGRATION_FAILURE",
    "QUIC_CONNECTION_MIGRATION_SUCCESS",
    "QUIC_CONNECTION_MIGRATION_ON_NETWORK_CONNECTED",
    "QUIC_CONNECTION_MIGRATION_ON_NETWORK_MADE_DEFAULT",
    "QUIC_CONNECTION_MIGRATION_ON_NETWORK_DISCONNECTED",
    "QUIC_CONNECTION_MIGRATION_ON_WRITE_ERROR",
    "QUIC_CONNECTION_MIGRATION_WAITING_FOR_NEW_NETWORK",
    "QUIC_CONNECTION_MIGRATION_ON_PATH_DEGRADING",
    "QUIC_CONNECTION_MIGRATION_ON_MIGRATE_BACK",
    "QUIC_CONNECTION_MIGRATION_FAILURE_AFTER_PROBING",
    "QUIC_CONNECTION_MIGRATION_SUCCESS_AFTER_PROBING",
    "QUIC_CONNECTION_MIGRATION_FAILURE_WAITING_FOR_NETWORK",
    "QUIC_CONNECTION_MIGRATION_SUCCESS_WAITING_FOR_NETWORK",
    "QUIC_CONNECTIVITY_PROBING_MANAGER_START_PROBING",
    "QUIC_CONNECTIVITY_PROBING_MANAGER_CANCEL_PROBING",
    "QUIC_CONNECTIVITY_PROBING_MANAGER_PROBE_SENT",
    "QUIC_CONNECTIVITY_PROBING_MANAGER_PROBE_RECEIVED",
    "QUIC_CONNECTIVITY_PROBING_MANAGER_STATELESS_RESET_RECEIVED",
    "QUIC_PORT_MIGRATION_TRIGGERED",
    "QUIC_PORT_MIGRATION_FAILURE",
    "QUIC_PORT_MIGRATION_SUCCESS",
    "QUIC_ON_SERVER_PREFERRED_ADDRESS_AVAILABLE",
    "QUIC_START_VALIDATING_SERVER_PREFERRED_ADDRESS",
    "QUIC_FAILED_TO_VALIDATE_SERVER_PREFERRED_ADDRESS",
    "QUIC_SUCCESSFULLY_MIGRATED_TO_SERVER_PREFERRED_ADDRESS",
    "QUIC_READ_ERROR",
    "HTTP_STREAM_PARSER_READ_HEADERS",
    "SOCKS5_GREET_WRITE",
    "SOCKS5_GREET_READ",
    "SOCKS5_HANDSHAKE_WRITE",
    "SOCKS5_HANDSHAKE_READ",
    "AUTH_CONTROLLER",
    "AUTH_BOUND_TO_CONTROLLER",
    "AUTH_HANDLER_CREATE_RESULT",
    "AUTH_HANDLER_INIT",
    "AUTH_GENERATE_TOKEN",
    "AUTH_HANDLE_CHALLENGE",
    "AUTH_LIBRARY_LOAD",
    "AUTH_LIBRARY_BIND_FAILED",
    "AUTH_LIBRARY_IMPORT_NAME",
    "AUTH_LIBRARY_ACQUIRE_CREDS",
    "AUTH_LIBRARY_INIT_SEC_CTX",
    "AUTH_CHANNEL_BINDINGS",
    "NETWORK_IP_ADDRESSES_CHANGED",
    "NETWORK_CONNECTIVITY_CHANGED",
    "NETWORK_CHANGED",
    "NETWORK_MAC_OS_CONFIG_CHANGED",
    "DNS_CONFIG_CHANGED",
    "SPECIFIC_NETWORK_CONNECTED",
    "SPECIFIC_NETWORK_DISCONNECTED",
    "SPECIFIC_NETWORK_SOON_TO_DISCONNECT",
    "SPECIFIC_NETWORK_MADE_DEFAULT",
    "CERTIFICATE_DATABASE_TRUST_STORE_CHANGED",
    "CERTIFICATE_DATABASE_CLIENT_CERT_STORE_CHANGED",
    "CLEAR_CACHED_CLIENT_CERT",
    "CLEAR_MATCHING_CACHED_CLIENT_CERT",
    "THROTTLING_DISABLED_FOR_HOST",
    "THROTTLING_REJECTED_REQUEST",
    "DNS_TRANSACTION",
    "DNS_TRANSACTION_QUERY",
    "DNS_TRANSACTION_ATTEMPT",
    "DNS_TRANSACTION_TCP_ATTEMPT",
    "DNS_TRANSACTION_HTTPS_ATTEMPT",
    "DNS_TRANSACTION_RESPONSE",
    "DOH_URL_REQUEST",
    "CERT_VERIFIER_REQUEST",
    "CERT_VERIFIER_JOB",
    "CERT_VERIFIER_REQUEST_BOUND_TO_JOB",
    "CERT_VERIFIER_TASK",
    "CERT_VERIFIER_TASK_BOUND",
    "CERT_VERIFY_PROC_CREATED",
    "CERT_VERIFY_PROC",
    "CERT_VERIFY_PROC_TARGET_CERT",
    "CERT_VERIFY_PROC_INPUT_CERT",
    "CERT_VERIFY_PROC_CHROME_ROOT_STORE_VERSION",
    "CERT_VERIFY_PROC_ADDITIONAL_CERT",
    "CERT_VERIFY_PROC_PATH_BUILD_ATTEMPT",
    "CERT_VERIFY_PROC_PATH_BUILT",
    "CERT_VERIFY_PROC_PATH_BUILDER_DEBUG",
    "FTP_COMMAND_SENT",
    "FTP_CONTROL_CONNECTION",
    "FTP_DATA_CONNECTION",
    "FTP_CONTROL_RESPONSE",
    "SIMPLE_CACHE_ENTRY",
    "SIMPLE_CACHE_ENTRY_SET_KEY",
    "SIMPLE_CACHE_ENTRY_OPEN_CALL",
    "SIMPLE_CACHE_ENTRY_OPEN_BEGIN",
    "SIMPLE_CACHE_ENTRY_OPEN_END",
    "SIMPLE_CACHE_ENTRY_CREATE_CALL",
    "SIMPLE_CACHE_ENTRY_CREATE_OPTIMISTIC",
    "SIMPLE_CACHE_ENTRY_CREATE_BEGIN",
    "SIMPLE_CACHE_ENTRY_CREATE_END",
    "SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_CALL",
    "SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_BEGIN",
    "SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_END",
    "SIMPLE_CACHE_ENTRY_READ_CALL",
    "SIMPLE_CACHE_ENTRY_READ_BEGIN",
    "SIMPLE_CACHE_ENTRY_READ_END",
    "SIMPLE_CACHE_ENTRY_CHECKSUM_BEGIN",
    "SIMPLE_CACHE_ENTRY_CHECKSUM_END",
    "SIMPLE_CACHE_ENTRY_WRITE_CALL",
    "SIMPLE_CACHE_ENTRY_WRITE_OPTIMISTIC",
    "SIMPLE_CACHE_ENTRY_WRITE_BEGIN",
    "SIMPLE_CACHE_ENTRY_WRITE_END",
    "SIMPLE_CACHE_ENTRY_READ_SPARSE_CALL",
    "SIMPLE_CACHE_ENTRY_READ_SPARSE_BEGIN",
    "SIMPLE_CACHE_ENTRY_READ_SPARSE_END",
    "SIMPLE_CACHE_ENTRY_WRITE_SPARSE_CALL",
    "SIMPLE_CACHE_ENTRY_WRITE_SPARSE_BEGIN",
    "SIMPLE_CACHE_ENTRY_WRITE_SPARSE_END",
    "SIMPLE_CACHE_ENTRY_DOOM_CALL",
    "SIMPLE_CACHE_ENTRY_DOOM_BEGIN",
    "SIMPLE_CACHE_ENTRY_DOOM_END",
    "SIMPLE_CACHE_ENTRY_CLOSE_CALL",
    "SIMPLE_CACHE_ENTRY_CLOSE_BEGIN",
    "SIMPLE_CACHE_ENTRY_CLOSE_END",
    "UPLOAD_DATA_STREAM_INIT",
    "UPLOAD_DATA_STREAM_READ",
    "RESOURCE_SCHEDULER_REQUEST_STARTED",
    "IN_MEMORY_CACHE_READ_REQUEST_HEADERS",
    "IN_MEMORY_CACHE_READ_RESPONSE_HEADERS",
    "IN_MEMORY_CACHE_BYTES_READ",
    "NETWORK_QUALITY_CHANGED",
    "HTTP_SERVER_PROPERTIES_INITIALIZATION",
    "HTTP_SERVER_PROPERTIES_UPDATE_CACHE",
    "HTTP_SERVER_PROPERTIES_UPDATE_PREFS",
    "HOST_CACHE_PREF_READ",
    "HOST_CACHE_PREF_WRITE",
    "HOST_CACHE_PERSISTENCE_START_TIMER",
    "WPAD_DHCP_WIN_FETCH",
    "WPAD_DHCP_WIN_GET_ADAPTERS",
    "WPAD_DHCP_WIN_ON_FETCHER_DONE",
    "WPAD_DHCP_WIN_START_WAIT_TIMER",
    "WPAD_DHCP_WIN_ON_WAIT_TIMER",
    "COOKIE_STORE_ALIVE",
    "COOKIE_STORE_COOKIE_ADDED",
    "COOKIE_STORE_COOKIE_DELETED",
    "COOKIE_STORE_COOKIE_REJECTED_SECURE",
    "COOKIE_STORE_COOKIE_REJECTED_HTTPONLY",
    "COOKIE_STORE_COOKIE_PRESERVED_SKIPPED_SECURE",
    "COOKIE_STORE_SESSION_PERSISTENCE",
    "COOKIE_PERSISTENT_STORE_ORIGIN_FILTERED",
    "COOKIE_PERSISTENT_STORE_LOAD",
    "COOKIE_PERSISTENT_STORE_KEY_LOAD_STARTED",
    "COOKIE_PERSISTENT_STORE_KEY_LOAD_COMPLETED",
    "COOKIE_PERSISTENT_STORE_CLOSED",
    "COOKIE_GET_BLOCKED_BY_NETWORK_DELEGATE",
    "COOKIE_SET_BLOCKED_BY_NETWORK_DELEGATE",
    "COOKIE_INCLUSION_STATUS",
    "HTTP3_LOCAL_CONTROL_STREAM_CREATED",
    "HTTP3_LOCAL_QPACK_ENCODER_STREAM_CREATED",
    "HTTP3_LOCAL_QPACK_DECODER_STREAM_CREATED",
    "HTTP3_PEER_CONTROL_STREAM_CREATED",
    "HTTP3_PEER_QPACK_ENCODER_STREAM_CREATED",
    "HTTP3_PEER_QPACK_DECODER_STREAM_CREATED",
    "HTTP3_CANCEL_PUSH_RECEIVED",
    "HTTP3_SETTINGS_RECEIVED",
    "HTTP3_GOAWAY_RECEIVED",
    "HTTP3_MAX_PUSH_ID_RECEIVED",
    "HTTP3_PRIORITY_UPDATE_RECEIVED",
    "HTTP3_DATA_FRAME_RECEIVED",
    "HTTP3_HEADERS_RECEIVED",
    "HTTP3_HEADERS_DECODED",
    "HTTP3_UNKNOWN_FRAME_RECEIVED",
    "HTTP3_SETTINGS_SENT",
    "HTTP3_SETTINGS_RESUMED",
    "HTTP3_GOAWAY_SENT",
    "HTTP3_MAX_PUSH_ID_SENT",
    "HTTP3_PRIORITY_UPDATE_SENT",
    "HTTP3_DATA_SENT",
    "HTTP3_HEADERS_SENT",
    "HTTP3_PUSH_PROMISE_SENT",
    "TRUST_TOKEN_OPERATION_REQUESTED",
    "TRUST_TOKEN_OPERATION_BEGIN_ISSUANCE",
    "TRUST_TOKEN_OPERATION_FINALIZE_ISSUANCE",
    "TRUST_TOKEN_OPERATION_BEGIN_REDEMPTION",
    "TRUST_TOKEN_OPERATION_FINALIZE_REDEMPTION",
    "TRUST_TOKEN_OPERATION_BEGIN_SIGNING",
    "CORS_REQUEST",
    "CHECK_CORS_PREFLIGHT_REQUIRED",
    "CHECK_CORS_PREFLIGHT_CACHE",
    "CORS_PREFLIGHT_RESULT",
    "CORS_PREFLIGHT_ERROR",
    "CORS_PREFLIGHT_URL_REQUEST",
    "CORS_PREFLIGHT_CACHED_RESULT",
    "PRIVATE_NETWORK_ACCESS_CHECK",
    "CREATED_BY",
    "COMPUTED_PRIVACY_MODE",
    "WEBSOCKET_UPGRADE_FAILURE",
    "WEBSOCKET_READ_BUFFER_SIZE_CHANGED",
    "WEBSOCKET_RECV_FRAME_HEADER",
    "WEBSOCKET_SENT_FRAME_HEADER",
    "WEBSOCKET_CLOSE_TIMEOUT",
    "WEBSOCKET_INVALID_FRAME",
    "TRANSPORT_SECURITY_STATE_SHOULD_UPGRADE_TO_SSL",
    "OBLIVIOUS_HTTP_REQUEST",
    "OBLIVIOUS_HTTP_REQUEST_DATA",
    "OBLIVIOUS_HTTP_RESPONSE_DATA",
    "OBLIVIOUS_HTTP_RESPONSE_HEADERS",
    "FIRST_PARTY_SETS_METADATA",
    "DBSC_REQUEST",
    "CHECK_DBSC_REFRESH_REQUIRED",
    "DBSC_REFRESH_REQUEST",
    "DBSC_REGISTRATION_REQUEST",
    "DBSC_REFRESH_RESULT"
]