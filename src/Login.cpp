/**
 * @file Login.cpp
 * @brief this is the implemetation of the Sasl::Client::Login class.
 * @copyright © 2026 by Hatem Nabli.
 */
#include <Sasl/Login.hpp>
#include <queue>
namespace Sasl::Client
{
    struct Login::Impl
    {
        /**
         * This is the diagnosticsSender attribut.
         */
        SystemUtils::DiagnosticsSender diagnosticSender;
        /**
         * This is the encodedCredentials to
         */
        std::queue<std::string> credentials;
        /**
         * This flag indicate whether or not the credentials was sent
         * to the server.
         */
        bool isCredentialWasSent = false;
        /**
         * This is the number of challenges proceeded by the server.
         */
        int challenges = 0;

        Impl() : diagnosticSender("Sasl::Client::Login") {}
        ~Impl() noexcept = default;
    };

    Login::Login() : impl_(std::make_unique<Impl>()) {}

    Login::~Login() noexcept = default;
    Login::Login(Login&& other) noexcept = default;
    Login& Login::operator=(Login&& other) noexcept = default;

    SystemUtils::DiagnosticsSender::UnsubscribeDelegate Login::SubscribeToDiagnosticsSender(
        SystemUtils::DiagnosticsSender::DiagnosticMessageDelegate messageDelegate, size_t level) {
        return impl_->diagnosticSender.SubscribeToDiagnostics(messageDelegate, level);
    }

    void Login::Reset() { impl_->isCredentialWasSent = false; }

    bool Login::Succeeded() { return false; }

    std::string Login::InitialResponse() { return ""; }

    void Login::SetCredentials(const std::string& credentials,
                               const std::string& authenticationIdentity,
                               const std::string& authorizationIdentity) {
        impl_->credentials.push(authenticationIdentity);
        impl_->credentials.push(credentials);
    }

    std::string Login::ExchangeAuthentication(const std::string& message) {
        switch (++impl_->challenges)
        {
        case 1:
            /* code */
            return impl_->credentials.front();
        case 2:
            impl_->credentials.pop();
            return impl_->credentials.front();
        default:
            return "";
        }
    }

}  // namespace Sasl::Client