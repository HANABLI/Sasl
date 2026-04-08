/**
 * @file Mechanism.hpp
 * @brief This is the interface to be implemented to eash Sasl Mechanism.
 * @copyright © 2026 by Hatem Nabli
 */
#include <SystemUtils/DiagnosticsSender.hpp>
namespace Sasl::Client
{
    class Mechanism
    {
    public:
        /**
         *
         */
        virtual SystemUtils::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnosticsSender(
            SystemUtils::DiagnosticsSender::DiagnosticMessageDelegate messageDelegate,
            size_t level = 0) = 0;

        /**
         * This returns the initial response that the clinet have to send to
         * the server on an authentication request.
         *
         * @return The initial response that the client have to send to
         *         the server in an authentication request is returned.
         * @retval ""
         *         an empty string is returned if the mechanism does not
         *         sent an initial response in an authentication request.
         */
        virtual std::string InitialResponse() = 0;

        /**
         * This set the credentials to use in the authentication exchange.
         *
         * @param[in] credentials
         *            Credential form used to authenticate the client.
         * @param[in] authenticationIdentity
         *            This is the authentication identity to associate with
         *            crentials
         * @param[in] authorizationIdentity
         *            This is the authorization identity to "act as" in
         *            the authentication. if empty the client request to act
         *            as the identity the server associates with the client's.
         */
        virtual void SetCredentials(const std::string& credentials,
                                    const std::string& authenticationIdentity,
                                    const std::string& authorizationIdentity = "") = 0;

        /**
         * This is a mechanism specific exchange authentication that handle the
         * challenge message received from the server and return the message response
         * to send to the server.
         *
         * @param[in] message
         *            This is the challenge message received from the server.
         *
         * @return  The response message to send to the server is returned.
         *
         * @retval ""
         *         An empty message is rturned if the exchange is completed.
         */
        virtual std::string ExchangeAuthentication(const std::string& message) = 0;
    };

}  // namespace Sasl::Client