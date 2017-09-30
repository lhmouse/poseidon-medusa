#ifndef MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/flat_map.hpp>

namespace Medusa2 {
namespace Primary {

class ProxySession;

class SecondaryClient : public Poseidon::Cbpp::Client {
private:
	class Channel;
	class CloseJob;

private:
	boost::container::flat_multimap<Poseidon::Uuid, boost::shared_ptr<Channel> > m_channels;

public:
	SecondaryClient(const Poseidon::SockAddr &sock_addr, bool use_ssl);
	~SecondaryClient();

protected:
	void on_close(int err_code) OVERRIDE;
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

	bool send(const Poseidon::Cbpp::MessageBase &msg);

public:
	void channel_connect(const boost::shared_ptr<ProxySession> &proxy_session, std::string host, unsigned port, bool use_ssl, bool no_delay, std::basic_string<unsigned char> opaque);
	void channel_send(const Poseidon::Uuid &session_uuid, std::basic_string<unsigned char> segment);
	void channel_acknowledge(const Poseidon::Uuid &session_uuid, boost::uint64_t bytes_to_acknowledge);
	void channel_shutdown(const Poseidon::Uuid &session_uuid, bool no_linger) NOEXCEPT;
};

}
}

#endif
