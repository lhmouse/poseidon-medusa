#ifndef MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CLIENT_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/flat_map.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryClient : public Poseidon::Cbpp::Client {
private:
	class CloseJob;

public:
	class ChannelBase;

private:
	mutable Poseidon::Mutex m_establishment_mutex;
	boost::container::flat_multimap<Poseidon::Uuid, boost::shared_ptr<ChannelBase> > m_channels_pending;

	boost::container::flat_multimap<Poseidon::Uuid, boost::shared_ptr<ChannelBase> > m_channels_established;

public:
	SecondaryClient(const Poseidon::SockAddr &sock_addr, bool use_ssl);
	~SecondaryClient();

protected:
	void on_close(int err_code) OVERRIDE;
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

	bool send(const Poseidon::Cbpp::MessageBase &msg);

public:
	void attach_channel(const boost::shared_ptr<ChannelBase> &channel, std::string host, unsigned port, bool use_ssl, bool no_delay);
};

class SecondaryClient::ChannelBase : NONCOPYABLE, public Poseidon::VirtualSharedFromThis {
	friend SecondaryClient;

private:
	boost::weak_ptr<SecondaryClient> m_weak_parent;
	Poseidon::Uuid m_channel_uuid;

public:
	ChannelBase();
	~ChannelBase();

public:
	virtual void on_sync_established() = 0;
	virtual void on_sync_received(Poseidon::StreamBuffer data) = 0;
	virtual void on_sync_closed(long err_code, std::string err_msg) = 0;

public:
	const Poseidon::Uuid &get_channel_uuid() const {
		return m_channel_uuid;
	}

	bool send(Poseidon::StreamBuffer data);
	void shutdown(bool no_linger) NOEXCEPT;
};

}
}

#endif
