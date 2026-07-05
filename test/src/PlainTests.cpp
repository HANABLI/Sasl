/**
 * @file PlainTests.cpp
 * @brief This module contains the unit test of the Sasl::Client::Plain class.
 * @copyright © 2026 by Hatem Nabli.
 */

#include <gtest/gtest.h>
#include <Sasl/Plain.hpp>

TEST(SaslTests, Plain_CredentialsAtInitialResponse) {
    Sasl::Client::Plain plain;
    plain.SetCredentials("toto", "titi");

    const auto response = plain.InitialResponse();
    EXPECT_EQ(std::string("\0titi\0toto", 10), response);
}

TEST(SaslTests, Plain_CredentialsAfterEmptyServerResponse) {
    Sasl::Client::Plain plain;
    plain.SetCredentials("toto", "titi");
    const auto message = plain.ExchangeAuthentication("");
    EXPECT_EQ(std::string("\0titi\0toto", 10), message);
}

TEST(SaslTests, Plain_CredentialsAfterTwiceExchange) {
    Sasl::Client::Plain plain;
    plain.SetCredentials("toto", "titi");
    (void)plain.ExchangeAuthentication("");
    const auto message = plain.ExchangeAuthentication("");
    EXPECT_EQ("", message);
}