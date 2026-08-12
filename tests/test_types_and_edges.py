from __future__ import annotations

import pytest

from blackbar import Entity, HashStrategy, MaskStrategy, Match, Scrubber, scan, scrub
from blackbar.detectors import all_detectors, get_detector


class TestPhone:
    @pytest.mark.parametrize(
        "value",
        [
            "+44 20 7946 0958",
            "+1 (555) 019-2345",
            "(020) 7946 0958",
            "555-019-2345",
            "0161 496 0122",
        ],
    )
    def test_formatted_numbers_detected(self, value: str) -> None:
        assert scrub(value) == "[PHONE]"

    @pytest.mark.parametrize("value", ["call 1234567890 now", "order 9876543210"])
    def test_bare_digit_runs_ignored(self, value: str) -> None:
        # No formatting signal -- far likelier to be an identifier than a number.
        assert scrub(value) == value

    def test_repeated_digit_placeholder_ignored(self) -> None:
        assert scrub("+1111111111") == "+1111111111"

    def test_too_short_for_e164(self) -> None:
        assert Entity.PHONE not in [m.entity for m in scan("12-34-56")]


class TestCryptoWallet:
    def test_bitcoin_genesis_address(self) -> None:
        assert scrub("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "[CRYPTO_WALLET]"

    def test_corrupted_bitcoin_address_rejected(self) -> None:
        # Final character changed; Base58Check catches it.
        bad = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
        assert scrub(bad) == bad

    def test_bech32_address(self) -> None:
        assert scrub("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == "[CRYPTO_WALLET]"

    def test_evm_address_annotated_as_unverified(self) -> None:
        (match,) = scan("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        assert match.entity is Entity.CRYPTO_WALLET
        assert match.note is not None and "unverified" in match.note


class TestMatchInvariants:
    def test_rejects_negative_start(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            Match(entity=Entity.EMAIL, start=-1, end=4, text="test")

    def test_rejects_non_positive_length(self) -> None:
        with pytest.raises(ValueError, match="greater than"):
            Match(entity=Entity.EMAIL, start=5, end=5, text="")

    def test_length_and_span(self) -> None:
        match = Match(entity=Entity.EMAIL, start=2, end=9, text="a@b.com")
        assert len(match) == 7
        assert match.span == (2, 9)

    def test_overlaps(self) -> None:
        a = Match(entity=Entity.EMAIL, start=0, end=10, text="x" * 10)
        b = Match(entity=Entity.PHONE, start=5, end=15, text="y" * 10)
        c = Match(entity=Entity.PHONE, start=10, end=20, text="z" * 10)
        assert a.overlaps(b) and b.overlaps(a)
        assert not a.overlaps(c)  # touching spans do not overlap

    def test_entity_is_a_string_enum(self) -> None:
        assert Entity.EMAIL == "EMAIL"
        assert str(Entity.EMAIL) == "EMAIL"


class TestRegistry:
    def test_every_entity_has_a_detector(self) -> None:
        registered = {d.entity for d in all_detectors()}
        assert registered == set(Entity)

    def test_detectors_are_priority_ordered(self) -> None:
        priorities = [d.priority for d in all_detectors()]
        assert priorities == sorted(priorities, reverse=True)

    def test_priorities_are_documented_and_sane(self) -> None:
        assert get_detector(Entity.PRIVATE_KEY).priority > get_detector(Entity.EMAIL).priority
        assert get_detector(Entity.EMAIL).priority > get_detector(Entity.PHONE).priority

    def test_detector_names_are_lowercase_entity_names(self) -> None:
        assert get_detector(Entity.EMAIL).name == "email"


class TestStrategyEdges:
    def test_ephemeral_key_is_generated_when_none_given(self) -> None:
        strategy = HashStrategy()
        assert strategy.ephemeral
        assert len(strategy.key) == 32

    def test_ephemeral_keys_differ_between_instances(self) -> None:
        a = Scrubber(strategy=HashStrategy()).scrub("ops@acme.io").text
        b = Scrubber(strategy=HashStrategy()).scrub("ops@acme.io").text
        assert a != b

    def test_token_length_is_configurable(self) -> None:
        strategy = HashStrategy(key="k", length=16)
        assert len(strategy.token("value")) == 16

    def test_mask_with_zero_keep_hides_everything(self) -> None:
        out = Scrubber(strategy=MaskStrategy()).scrub("ssn 574-38-2914").text
        assert out == "ssn ***-**-****"  # separators survive, digits do not

    def test_mask_keep_override(self) -> None:
        out = Scrubber(strategy=MaskStrategy(keep=2)).scrub("4111111111111111").text
        assert out.endswith("11")
        assert out.count("*") == 14

    def test_mask_custom_character(self) -> None:
        out = Scrubber(strategy=MaskStrategy(char="#")).scrub("4111111111111111").text
        assert "#" in out and "*" not in out


class TestStrategyFactory:
    def test_unknown_strategy_raises(self) -> None:
        from blackbar import build_strategy

        with pytest.raises(ValueError, match="unknown strategy"):
            build_strategy("nonsense")

    @pytest.mark.parametrize("name", ["label", "hash", "mask", "remove"])
    def test_all_named_strategies_build(self, name: str) -> None:
        from blackbar import build_strategy

        assert (
            build_strategy(name).apply(
                Match(entity=Entity.EMAIL, start=0, end=11, text="ops@acme.io")
            )
            is not None
        )
