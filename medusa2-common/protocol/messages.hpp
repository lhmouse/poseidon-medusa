#ifndef MEDUSA2_PROTOCOL_MESSAGES_HPP_
#define MEDUSA2_PROTOCOL_MESSAGES_HPP_

#include <poseidon/cbpp/message_base.hpp>
#include "messages_fwd.hpp"

namespace Medusa2 {
namespace Protocol {

#define MESSAGE_NAME   PS_Connect
#define MESSAGE_ID     3001
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	FIELD_STRING       (host)	\
	FIELD_VUINT        (port)	\
	FIELD_VUINT        (use_ssl)	\
	FIELD_VUINT        (no_delay)	\
	FIELD_FLEXIBLE     (opaque)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   PS_Send
#define MESSAGE_ID     3002
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	FIELD_FLEXIBLE     (segment)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   PS_Acknowledge
#define MESSAGE_ID     3003
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	FIELD_VUINT        (bytes_to_acknowledge)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   PS_Shutdown
#define MESSAGE_ID     3004
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	FIELD_VUINT        (no_linger)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   SP_Opened
#define MESSAGE_ID     4001
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	FIELD_FLEXIBLE     (opaque)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   SP_Established
#define MESSAGE_ID     4002
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   SP_Received
#define MESSAGE_ID     4003
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	FIELD_FLEXIBLE     (segment)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME   SP_Closed
#define MESSAGE_ID     4004
#define MESSAGE_FIELDS \
	FIELD_FIXED        (channel_uuid, 16)	\
	FIELD_VINT         (err_code)	\
	FIELD_STRING       (err_msg)	\
	//
#include <poseidon/cbpp/message_generator.hpp>

}
}

#endif
