#ifndef MEDUSA2_PRIMARY_SECONDARY_CONNECTOR_HPP_
#define MEDUSA2_PRIMARY_SECONDARY_CONNECTOR_HPP_

#include "../secondary_client.hpp"

namespace Medusa2 {
namespace Primary {

class SecondaryConnector {
public:
	static boost::shared_ptr<SecondaryClient> get_client();

private:
	SecondaryConnector();
};

}
}

#endif
