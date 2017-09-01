#ifndef MEDUSA2_PROTOCOL_ERROR_CODES_HPP_
#define MEDUSA2_PROTOCOL_ERROR_CODES_HPP_

namespace Medusa2 {
namespace Protocol {

namespace ErrorCodes {
	enum {
		ERR_INTERNAL_ERROR                    =   -1,
		ERR_END_OF_STREAM                     =   -2,
		ERR_NOT_FOUND                         =   -3,
		ERR_REQUEST_TOO_LARGE                 =   -4,
		ERR_JUNK_AFTER_PACKET                 =   -6,
		ERR_AUTHORIZATION_FAILURE             =   -8,
		ERR_LENGTH_ERROR                      =   -9,
		ERR_DATA_CORRUPTED                    =  -11,

		ERR_SECONDARY_SERVER_UNREACHABLE      = 9000,
		ERR_DNS_FAILURE                       = 9001,
		ERR_CONNECTION_REFUSED                = 9002,
		ERR_CONNECTION_TIMED_OUT              = 9003,
		ERR_CONNECTION_RESET_BY_PEER          = 9004,
		ERR_CONNECTION_LOST_UNSPECIFIED       = 9005,
	};
}
using namespace ErrorCodes;

}
}

#endif
