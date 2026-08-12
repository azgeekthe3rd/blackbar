from __future__ import annotations

from itertools import pairwise

import pytest

from blackbar import Entity, HashStrategy, MaskStrategy, RemoveStrategy, Scrubber, scan, scrub


def entities(text: str, **kwargs: object) -> list[Entity]:
    return [m.entity for m in scan(text, **kwargs)]


class TestEmail:
    def test_detects_and_labels(self) -> None:
        assert scrub("write to ops@acme.io today") == "write to [EMAIL] today"

    def test_handles_plus_addressing_and_subdomains(self) -> None:
        text = "a.b+tag@mail.corp.co.uk"
        assert scrub(text) == "[EMAIL]"

    def test_ignores_reserved_documentation_domains(self) -> None:
        assert scrub("see user@example.com") == "see user@example.com"

    def test_does_not_match_bare_domain(self) -> None:
        assert entities("visit acme.io for details") == []


class TestCreditCard:
    def test_luhn_valid_card_is_redacted(self) -> None:
        assert scrub("card 4111 1111 1111 1111 ok") == "card [CREDIT_CARD] ok"

    def test_luhn_invalid_lookalike_is_left_alone(self) -> None:
        # One digit different. This is the headline behaviour of the library.
        assert Entity.CREDIT_CARD not in entities("ref 4111 1111 1111 1112")

    def test_order_id_is_not_a_card(self) -> None:
        assert Entity.CREDIT_CARD not in entities("order 1234567890123456")

    def test_annotates_issuer(self) -> None:
        (match,) = [m for m in scan("378282246310005") if m.entity is Entity.CREDIT_CARD]
        assert match.note == "American Express"

    @pytest.mark.parametrize("sep", ["", " ", "-"])
    def test_separator_variants(self, sep: str) -> None:
        raw = sep.join(["4111", "1111", "1111", "1111"]) if sep else "4111111111111111"
        assert scrub(raw) == "[CREDIT_CARD]"


class TestIbanDetector:
    def test_redacts_valid_iban(self) -> None:
        assert scrub("pay GB82WEST12345698765432 now") == "pay [IBAN] now"

    def test_ignores_failed_checksum(self) -> None:
        assert Entity.IBAN not in entities("code GB82WEST12345698765423")


class TestNetwork:
    def test_public_ip_redacted(self) -> None:
        assert scrub("from 8.8.8.8") == "from [IPV4]"

    def test_private_and_loopback_preserved(self) -> None:
        text = "upstream 10.0.0.7 via 127.0.0.1"
        assert scrub(text) == text

    def test_ipv6_redacted(self) -> None:
        assert Entity.IPV6 in entities("peer 2606:4700:4700::1111")

    def test_mac_redacted(self) -> None:
        assert scrub("nic 00:1B:44:11:3A:B7") == "nic [MAC]"

    def test_version_string_is_not_an_ip(self) -> None:
        assert entities("version 1.2.3.4000") == []


class TestCredentials:
    def test_aws_key(self) -> None:
        assert scrub("AKIAIOSFODNN7EXAMPLE") == "[API_KEY]"

    def test_jwt(self) -> None:
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert scrub(f"Bearer {token}") == "Bearer [JWT]"

    def test_url_credentials_keep_the_host_visible(self) -> None:
        assert (
            scrub("postgres://app:hunter2@db.internal:5432/main")
            == "postgres://[URL_CREDENTIALS]@db.internal:5432/main"
        )

    def test_pem_block_matched_across_lines(self) -> None:
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA1234\nabcd\n"
            "-----END RSA PRIVATE KEY-----"
        )
        assert scrub(f"key:\n{pem}\ndone") == "key:\n[PRIVATE_KEY]\ndone"


class TestGovernmentIds:
    def test_ssn_with_separators(self) -> None:
        assert scrub("ssn 574-38-2914") == "ssn [US_SSN]"

    def test_unpunctuated_nine_digits_ignored(self) -> None:
        assert Entity.US_SSN not in entities("zip 574382914")

    def test_nino(self) -> None:
        assert scrub("NI AB123456C") == "NI [UK_NINO]"


class TestOverlapResolution:
    def test_iban_beats_phone_shaped_fragment(self) -> None:
        found = entities("GB82WEST12345698765432")
        assert found == [Entity.IBAN]

    def test_card_beats_phone(self) -> None:
        found = entities("4111 1111 1111 1111")
        assert Entity.PHONE not in found
        assert Entity.CREDIT_CARD in found

    def test_matches_are_returned_in_document_order(self) -> None:
        found = scan("a@b.co then 8.8.8.8 then c@d.io")
        assert [m.start for m in found] == sorted(m.start for m in found)

    def test_no_two_matches_overlap(self) -> None:
        found = scan("ops@acme.io 4111111111111111 postgres://u:p@h/db")
        for earlier, later in pairwise(found):
            assert earlier.end <= later.start


class TestStrategies:
    def test_hash_is_deterministic_within_a_run(self) -> None:
        scrubber = Scrubber(strategy=HashStrategy(key="secret"))
        out = scrubber.scrub("ops@acme.io and ops@acme.io").text
        first, second = out.split(" and ")
        assert first == second
        assert first.startswith("[EMAIL:")

    def test_hash_distinguishes_different_values(self) -> None:
        scrubber = Scrubber(strategy=HashStrategy(key="secret"))
        a = scrubber.scrub("ops@acme.io").text
        b = scrubber.scrub("dev@acme.io").text
        assert a != b

    def test_hash_normalises_formatting_variants(self) -> None:
        scrubber = Scrubber(strategy=HashStrategy(key="secret"))
        spaced = scrubber.scrub("4111 1111 1111 1111").text
        dashed = scrubber.scrub("4111-1111-1111-1111").text
        assert spaced == dashed

    def test_different_keys_give_different_tokens(self) -> None:
        a = Scrubber(strategy=HashStrategy(key="k1")).scrub("ops@acme.io").text
        b = Scrubber(strategy=HashStrategy(key="k2")).scrub("ops@acme.io").text
        assert a != b

    def test_mask_keeps_card_tail(self) -> None:
        out = Scrubber(strategy=MaskStrategy()).scrub("4111 1111 1111 1111").text
        assert out == "**** **** **** 1111"

    def test_mask_keeps_email_domain(self) -> None:
        out = Scrubber(strategy=MaskStrategy()).scrub("ops@acme.io").text
        assert out == "o**@acme.io"

    def test_remove_deletes_the_span(self) -> None:
        out = Scrubber(strategy=RemoveStrategy()).scrub("hi ops@acme.io!").text
        assert out == "hi !"


class TestConfiguration:
    def test_only_restricts_detectors(self) -> None:
        text = "ops@acme.io from 8.8.8.8"
        assert scrub(text, only=[Entity.EMAIL]) == "[EMAIL] from 8.8.8.8"

    def test_exclude_skips_detectors(self) -> None:
        text = "ops@acme.io from 8.8.8.8"
        assert scrub(text, exclude=[Entity.IPV4]) == "[EMAIL] from 8.8.8.8"

    def test_allowlist_preserves_literals(self) -> None:
        out = scrub("ops@acme.io and noreply@acme.io", allowlist=["noreply@acme.io"])
        assert out == "[EMAIL] and noreply@acme.io"


class TestResult:
    def test_counts_are_tallied(self) -> None:
        result = Scrubber().scrub("a@b.co c@d.io 8.8.8.8")
        assert result.counts == {"EMAIL": 2, "IPV4": 1}

    def test_report_hides_values_by_default(self) -> None:
        report = Scrubber().scrub("ops@acme.io").report()
        assert "text" not in report["matches"][0]

    def test_report_can_include_values_on_request(self) -> None:
        report = Scrubber().scrub("ops@acme.io").report(include_text=True)
        assert report["matches"][0]["text"] == "ops@acme.io"

    def test_offsets_map_back_to_the_original_text(self) -> None:
        text = "contact ops@acme.io please"
        for match in Scrubber().scan(text):
            assert text[match.start : match.end] == match.text

    def test_clean_text_is_returned_unchanged(self) -> None:
        text = "nothing sensitive here at all"
        result = Scrubber().scrub(text)
        assert result.text == text
        assert not result.found_anything


class TestEdgeCases:
    def test_empty_input(self) -> None:
        assert scrub("") == ""

    def test_idempotent_second_pass_finds_nothing(self) -> None:
        once = scrub("ops@acme.io 4111111111111111")
        assert scrub(once) == once

    def test_unicode_offsets_are_correct(self) -> None:
        assert scrub("日本語 ops@acme.io テスト") == "日本語 [EMAIL] テスト"

    def test_adjacent_matches(self) -> None:
        assert scrub("a@b.co,c@d.io") == "[EMAIL],[EMAIL]"
