// 这个文件是 Medusa 服务器应用程序的一部分。
// Copyleft 2017 - 2018, LH_Mouse. All wrongs reserved.

#ifndef MEDUSA2_PRIMARY_SINGLETONS_SECONDARY_CONNECTOR_HPP_
#define MEDUSA2_PRIMARY_SINGLETONS_SECONDARY_CONNECTOR_HPP_

#include "../secondary_channel.hpp"
#include <poseidon/ip_port.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryConnector {
public:
	static boost::shared_ptr<SecondaryChannel> get_attached_channel(const Poseidon::Uuid &channel_uuid);
	static void attach_channel(const boost::shared_ptr<SecondaryChannel> &channel);

	static const Poseidon::IpPort &get_remote_info();
	static bool send(const Poseidon::Cbpp::MessageBase &msg);
	static bool shutdown(long err_code, const char *what) NOEXCEPT;

private:
	SecondaryConnector();
};

}
}

#endif
