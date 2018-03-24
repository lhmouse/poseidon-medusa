#ifndef MEDUSA2_PROTOCOL_ERROR_CODES_HPP_
#define MEDUSA2_PROTOCOL_ERROR_CODES_HPP_

namespace Medusa2 {
namespace Protocol {

namespace ErrorCodes {
	enum {
		error_success                           =    0,
		error_internal_error                    =   -1,
		error_end_of_stream                     =   -2,
		error_not_found                         =   -3,
		error_request_too_large                 =   -4,
		error_bad_request                       =   -5,
		error_junk_after_packet                 =   -6,
		error_forbidden                         =   -7,
		error_authorization_failure             =   -8,
		error_length_error                      =   -9,
		error_unknown_control_code              =  -10,
		error_data_corrupted                    =  -11,
		error_gone_away                         =  -12,
		error_invalid_argument                  =  -13,
		error_unsupported                       =  -14,

		error_dns_failure                       = 9001,
		error_private_address_disallowed        = 9002,
		error_connection_lost_unspecified       = 9003,
		error_connection_refused                = 9004,
		error_connection_timed_out              = 9005,
		error_connection_reset_by_peer          = 9006,
		error_connection_cancelled              = 9007,
		error_secondary_server_connection_lost  = 9008,
		error_origin_invalid_http_response      = 9009,
		error_origin_empty_response             = 9010,
	};
}

using namespace ErrorCodes;

}
}

#endif
