#ifndef MEDUSA2_PRIMARY_SECONDARY_CHANNEL_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CHANNEL_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryClient;

class SecondaryChannel : NONCOPYABLE, public Poseidon::VirtualSharedFromThis {
	friend SecondaryClient;

private:
	boost::weak_ptr<SecondaryClient> m_weak_parent;
	Poseidon::Uuid m_channel_uuid;

public:
	SecondaryChannel();
	~SecondaryChannel();

private:
	void activate(const boost::shared_ptr<SecondaryClient> &parent, const Poseidon::Uuid &channel_uuid);

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
