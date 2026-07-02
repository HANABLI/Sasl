#ifndef SASL_CLIENT_LOGIN_HPP
#define SASL_CLIENT_LOGIN_HPP
/**
 * @file Login.hpp
 * @brief This is the dclaration of the Sasl::Client::Login Mechanism.
 * @copyright © 2026 by Hatem Nabli
 */
#include <Sasl/Mechanism.hpp>
#include <memory>
namespace Sasl::Client
{
    class Login : public Mechanism
    {
    public:
        // rule of 5
        ~Login() noexcept;
        Login(const Login&) = delete;
        Login(Login&&) noexcept;
        Login& operator=(const Login&) = delete;
        Login& operator=(Login&&) noexcept;

    public:
        // Methods
        Login();

    public:
        // overrided mechanism methods
        SystemUtils::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnosticsSender(
            SystemUtils::DiagnosticsSender::DiagnosticMessageDelegate messageDelegate,
            size_t level = 0) override;

        void Reset() override;

        bool Succeeded() override;

        std::string InitialResponse() override;

        void SetCredentials(const std::string& credentials,
                            const std::string& authenticationIdentity,
                            const std::string& authorizationIdentity = "") override;

        std::string ExchangeAuthentication(const std::string& message) override;

    private:
        struct Impl;

        std::unique_ptr<Impl> impl_;
    };
}  // namespace Sasl::Client

#endif /* SASL_CLIENT_LOGIN_HPP */