#ifndef MEDUSA2_PRIMARY_SECONDARY_CHANNEL_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CHANNEL_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/virtual_shared_from_this.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa2 {
namespace Primary {

class SecondaryChannel : NONCOPYABLE, public Poseidon::VirtualSharedFromThis {
private:
	const Poseidon::Uuid m_channel_uuid;

	const std::string m_host;
	const unsigned m_port;
	const bool m_use_ssl;
	const bool m_no_delay;

	volatile bool m_shutdown;

public:
	SecondaryChannel(std::string host, unsigned port, bool use_ssl, bool no_delay);
	~SecondaryChannel();

public:
	virtual void on_sync_opened() = 0;
	virtual void on_sync_established() = 0;
	virtual void on_sync_received(Poseidon::StreamBuffer data) = 0;
	virtual void on_sync_closed(long err_code, std::string err_msg) = 0;

public:
	const Poseidon::Uuid get_channel_uuid() const {
		return m_channel_uuid;
	}
	const std::string &get_host() const {
		return m_host;
	}
	unsigned get_port() const {
		return m_port;
	}
	bool is_using_ssl() const {
		return m_use_ssl;
	}
	bool is_no_delay() const {
		return m_no_delay;
	}

	bool has_been_shutdown() const NOEXCEPT;
	bool shutdown(bool no_linger) NOEXCEPT;

	bool send(Poseidon::StreamBuffer data);
};

}
}

#endif
