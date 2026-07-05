/**
 * @file LoginTests.cpp
 * @brief This module contains the unit test of the Sasl::Client::Login class.
 * @copyright © 2026 by Hatem Nabli.
 */

#include <gtest/gtest.h>
#include <Sasl/Login.hpp>

TEST(SaslTests, Login_NoCredentialsAtInitialResponseWithoutServerChallenge) {
    Sasl::Client::Login login;
    login.SetCredentials("tanstaaftanstaaf", "tim");
    const auto response = login.InitialResponse();
    EXPECT_EQ("", response);
}

TEST(SaslTests, Login_CredentialsAfterUserNameServerChallenge) {
    Sasl::Client::Login login;
    login.SetCredentials("tanstaaftanstaaf", "tim");
    const auto message = login.ExchangeAuthentication("User Name");
    EXPECT_EQ("tim", message);
}

TEST(SaslTests, Login_CredentialsAfterTwiceExchange) {
    Sasl::Client::Login login;
    login.SetCredentials("tanstaaftanstaaf", "tim");
    (void)login.ExchangeAuthentication("User Name");
    const auto message = login.ExchangeAuthentication("Password");
    EXPECT_EQ("tanstaaftanstaaf", message);
}

TEST(SaslTests, Login_CredentialsAfterEmptyExchange) {
    Sasl::Client::Login login;
    login.SetCredentials("tanstaaftanstaaf", "tim");
    (void)login.ExchangeAuthentication("User Name");
    (void)login.ExchangeAuthentication("Password");
    const auto message = login.ExchangeAuthentication("");
    EXPECT_EQ("", message);
}