from __future__ import annotations

import pytest

from blackbar.validators import (
    base58check_ok,
    card_brand,
    iban_checksum_ok,
    is_credit_card,
    is_routable_ip,
    is_uk_nino,
    is_us_ssn,
    luhn_checksum_ok,
)


class TestLuhn:
    @pytest.mark.parametrize(
        "digits",
        [
            "4111111111111111",  # Visa
            "5555555555554444",  # Mastercard
            "378282246310005",  # Amex (odd length)
            "6011111111111117",  # Discover
            "3530111333300000",  # JCB
        ],
    )
    def test_accepts_known_good(self, digits: str) -> None:
        assert luhn_checksum_ok(digits)

    @pytest.mark.parametrize(
        "digits",
        ["4111111111111112", "5555555555554443", "378282246310006", ""],
    )
    def test_rejects_bad_checksum(self, digits: str) -> None:
        assert not luhn_checksum_ok(digits)

    def test_rejects_non_digits(self) -> None:
        assert not luhn_checksum_ok("4111-1111-1111-1111")

    def test_odd_and_even_lengths_use_correct_parity(self) -> None:
        # Amex is 15 digits, Visa 16 -- a parity bug passes one and fails the other.
        assert luhn_checksum_ok("378282246310005")
        assert luhn_checksum_ok("4111111111111111")


class TestCardBrand:
    @pytest.mark.parametrize(
        ("digits", "expected"),
        [
            ("4111111111111111", "Visa"),
            ("5555555555554444", "Mastercard"),
            ("378282246310005", "American Express"),
            ("6011111111111117", "Discover"),
            ("2223003122003222", "Mastercard"),  # 2-series range
            ("1234567812345670", None),  # valid Luhn, unknown issuer
        ],
    )
    def test_brand_detection(self, digits: str, expected: str | None) -> None:
        assert card_brand(digits) == expected

    def test_unknown_issuer_is_not_a_card_even_with_valid_luhn(self) -> None:
        assert luhn_checksum_ok("1234567812345670")
        assert not is_credit_card("1234567812345670")

    def test_wrong_length_for_brand_is_rejected(self) -> None:
        assert not is_credit_card("41111111111111")  # 14 digits, invalid for Visa


class TestIban:
    @pytest.mark.parametrize(
        "iban",
        [
            "GB82WEST12345698765432",
            "DE89370400440532013000",
            "FR1420041010050500013M02606",
            "NL91ABNA0417164300",
            "SA0380000000608010167519",
        ],
    )
    def test_accepts_valid(self, iban: str) -> None:
        assert iban_checksum_ok(iban)

    def test_tolerates_grouping_spaces(self) -> None:
        assert iban_checksum_ok("GB82 WEST 1234 5698 7654 32")

    def test_rejects_transposed_digits(self) -> None:
        assert not iban_checksum_ok("GB82WEST12345698765423")

    def test_rejects_wrong_length_for_country(self) -> None:
        assert not iban_checksum_ok("GB82WEST123456987654")

    def test_rejects_unknown_country(self) -> None:
        assert not iban_checksum_ok("ZZ82WEST12345698765432")


class TestSsn:
    @pytest.mark.parametrize("digits", ["574382914", "123456789"])
    def test_accepts_structurally_valid(self, digits: str) -> None:
        assert is_us_ssn(digits)

    @pytest.mark.parametrize(
        "digits",
        [
            "000123456",  # area 000
            "666123456",  # area 666
            "900123456",  # 900-999 never issued
            "574002914",  # group 00
            "574380000",  # serial 0000
            "078051120",  # the famous Woolworth card
            "12345678",  # too short
        ],
    )
    def test_rejects_impossible(self, digits: str) -> None:
        assert not is_us_ssn(digits)


class TestNino:
    @pytest.mark.parametrize("value", ["AB123456C", "AB 12 34 56 C", "ab123456c"])
    def test_accepts_valid(self, value: str) -> None:
        assert is_uk_nino(value)

    @pytest.mark.parametrize(
        "value",
        [
            "BG123456A",  # forbidden prefix
            "DA123456A",  # D not allowed first
            "AO123456A",  # O not allowed second
            "AB123456E",  # suffix must be A-D
            "AB12345C",  # too short
        ],
    )
    def test_rejects_invalid(self, value: str) -> None:
        assert not is_uk_nino(value)


class TestIp:
    @pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_routable(self, value: str) -> None:
        assert is_routable_ip(value)

    @pytest.mark.parametrize(
        "value",
        ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "0.0.0.0", "::1", "999.1.1.1"],
    )
    def test_not_routable_or_not_an_ip(self, value: str) -> None:
        assert not is_routable_ip(value)


class TestBase58Check:
    def test_accepts_genesis_address(self) -> None:
        assert base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def test_rejects_single_character_corruption(self) -> None:
        assert not base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")

    def test_rejects_out_of_alphabet_characters(self) -> None:
        assert not base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7Div0Na")
