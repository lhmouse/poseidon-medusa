#include "precompiled.hpp"
#include "proxy_session.hpp"
#include "singletons/proxy_server.hpp"
#include "singletons/secondary_connector.hpp"
#include <poseidon/http/status_codes.hpp>
#include <poseidon/http/exception.hpp>
#include <poseidon/http/server_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/server_writer.hpp>

namespace Medusa2 {
namespace Primary {

class ProxySession::RequestRewriter : public Poseidon::Http::ServerReader, public Poseidon::Http::ClientWriter {
private:
	ProxySession *const m_parent;

public:
	explicit RequestRewriter(ProxySession *parent)
		: m_parent(parent)
	{ }
	~RequestRewriter(){ }

public:
	ProxySession *get_parent() const {
		return m_parent;
	}
};

class ProxySession::ResponseRewriter : public Poseidon::Http::ClientReader, public Poseidon::Http::ServerWriter {
private:
	ProxySession *const m_parent;

public:
	explicit ResponseRewriter(ProxySession *parent)
		: m_parent(parent)
	{ }
	~ResponseRewriter(){ }

public:
	ProxySession *get_parent() const {
		return m_parent;
	}
};


ProxySession::ProxySession(Poseidon::Move<Poseidon::UniqueFile> socket, boost::shared_ptr<const Poseidon::Http::AuthInfo> auth_info)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_session_uuid(Poseidon::Uuid::random()), m_auth_info(STD_MOVE(auth_info))
{
	LOG_MEDUSA2_INFO("ProxySession constructor: remote = ", get_remote_info());
}
ProxySession::~ProxySession(){
	LOG_MEDUSA2_INFO("ProxySession destructor: remote = ", get_remote_info());
	ProxyServer::remove_session(this);
}

void ProxySession::on_connect(){
	PROFILE_ME;

}
void ProxySession::on_read_hup(){
	PROFILE_ME;

}
void ProxySession::on_close(int err_code){
	PROFILE_ME;

}
void ProxySession::on_receive(Poseidon::StreamBuffer data){
	PROFILE_ME;

	const auto client = SecondaryConnector::get_client();
	if(client){
		auto uuid = client->channel_connect(virtual_shared_from_this<ProxySession>(), "www.baidu.com", 80, false);
		client->channel_send(uuid, (const unsigned char *)"GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: Keep-Alive\r\n\r\n");
		client->channel_shutdown(uuid, false);
	}
}

void ProxySession::on_sync_opened(const Poseidon::Uuid &channel_uuid){
	PROFILE_ME;

	LOG_POSEIDON_FATAL("OPENED: ", channel_uuid);
}
void ProxySession::on_sync_established(const Poseidon::Uuid &channel_uuid){
	PROFILE_ME;

	LOG_POSEIDON_FATAL("ESTABLISHED: ", channel_uuid);
}
void ProxySession::on_sync_received(const Poseidon::Uuid &channel_uuid, std::basic_string<unsigned char> segment){
	PROFILE_ME;

	LOG_POSEIDON_ERROR("RECEIVED: ", channel_uuid, ": ", (const char *)segment.c_str());
}
void ProxySession::on_sync_closed(const Poseidon::Uuid &channel_uuid, long err_code, std::string err_msg){
	PROFILE_ME;

	LOG_POSEIDON_FATAL("CLOSED: ", channel_uuid, ": ", err_code, " (", err_msg, ")");
}

}
}
