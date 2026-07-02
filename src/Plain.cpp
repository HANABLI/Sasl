/**
 * @file Plain.cpp
 * @brief this is the implemetation of the Sasl::Client::Plain class.
 * @copyright © 2026 by Hatem Nabli.
 */
#include <Sasl/Plain.hpp>
#include <sstream>
namespace Sasl::Client
{
    struct Plain::Impl
    {
        /**
         * This is the diagnosticsSender attribut.
         */
        SystemUtils::DiagnosticsSender diagnosticSender;
        /**
         * This is the encodedCredentials to send to the server.
         */
        std::string encodedCredentials;
        /**
         * This flag indicate whether or not the credentials was sent
         * to the server.
         */
        bool isCredentialWasSent = false;

        Impl() : diagnosticSender("Sasl::Client::Plain") {}
        ~Impl() noexcept = default;
    };

    Plain::Plain() : impl_(std::make_unique<Impl>()) {}

    Plain::~Plain() noexcept = default;
    Plain::Plain(Plain&& other) noexcept = default;
    Plain& Plain::operator=(Plain&& other) noexcept = default;

    SystemUtils::DiagnosticsSender::UnsubscribeDelegate Plain::SubscribeToDiagnosticsSender(
        SystemUtils::DiagnosticsSender::DiagnosticMessageDelegate messageDelegate, size_t level) {
        return impl_->diagnosticSender.SubscribeToDiagnostics(messageDelegate, level);
    }

    void Plain::Reset() { impl_->isCredentialWasSent = false; }

    bool Plain::Succeeded() { return false; }

    std::string Plain::InitialResponse() { return impl_->encodedCredentials; }

    void Plain::SetCredentials(const std::string& credentials,
                               const std::string& authenticationIdentity,
                               const std::string& authorizationIdentity) {
        std::ostringstream credentialsBuilderl;
        credentialsBuilderl << authorizationIdentity;
        credentialsBuilderl << '\0';
        credentialsBuilderl << authenticationIdentity;
        credentialsBuilderl << '\0';
        credentialsBuilderl << credentials;
        impl_->encodedCredentials = credentialsBuilderl.str();
    }

    std::string Plain::ExchangeAuthentication(const std::string& message) {
        if (impl_->isCredentialWasSent)
        {
            return "";
        } else
        {
            impl_->isCredentialWasSent = true;
            return impl_->encodedCredentials;
        }
    }

}  // namespace Sasl::Client