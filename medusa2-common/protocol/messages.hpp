#ifndef MEDUSA2_PROTOCOL_MESSAGES_HPP_
#define MEDUSA2_PROTOCOL_MESSAGES_HPP_

#include <poseidon/cbpp/message_base.hpp>
#include "messages_fwd.hpp"

namespace Medusa2 {
namespace Protocol {

#define MESSAGE_NAME   PS_Open
#define MESSAGE_ID     3000
#define MESSAGE_FIELDS \
	FIELD_STRING       (connect)	\
	FIELD_VUINT        (port)	\
	FIELD_VUINT        (use_ssl)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   PS_Send
#define MESSAGE_ID     3001
#define MESSAGE_FIELDS \
	FIELD_FIXED        (fetch_uuid, 16)	\
	FIELD_FLEXIBLE     (segment)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   PS_Acknowledge
#define MESSAGE_ID     3002
#define MESSAGE_FIELDS \
	FIELD_FIXED        (fetch_uuid, 16)	\
	FIELD_VUINT        (bytes_acknowledged)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   PS_Close
#define MESSAGE_ID     3003
#define MESSAGE_FIELDS \
	FIELD_FIXED        (fetch_uuid, 16)	\
	FIELD_VINT         (err_code)	\
	FIELD_STRING       (err_msg)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   SP_Opened
#define MESSAGE_ID     4000
#define MESSAGE_FIELDS \
	FIELD_FIXED        (fetch_uuid, 16)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   SP_Received
#define MESSAGE_ID     4001
#define MESSAGE_FIELDS \
	FIELD_FIXED        (fetch_uuid, 16)	\
	FIELD_FLEXIBLE     (segment)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   SP_Closed
#define MESSAGE_ID     4002
#define MESSAGE_FIELDS \
	FIELD_FIXED        (fetch_uuid, 16)	\
	FIELD_VINT         (err_code)	\
	FIELD_STRING       (err_msg)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

}
}

#endif