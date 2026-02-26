"""Tests for the session router — deterministic session key generation and
binding resolution."""

from __future__ import annotations

import pytest

from openrattler.gateway.router import (
    ALLOWED_CHANNELS,
    Binding,
    resolve_agent,
    route_to_session,
)
from openrattler.models.sessions import Peer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dm(peer_id: str = "user1") -> Peer:
    return Peer(kind="dm", id=peer_id)


def _group(peer_id: str) -> Peer:
    return Peer(kind="group", id=peer_id)


def _thread(thread_id: str, parent: Peer) -> Peer:
    return Peer(kind="thread", id=thread_id, parent=parent)


# ---------------------------------------------------------------------------
# route_to_session — correct key shapes
# ---------------------------------------------------------------------------


class TestRouteToSession:
    def test_dm_routes_to_main_session(self) -> None:
        key = route_to_session("telegram", "main", _dm())
        assert key == "agent:main:main"

    def test_dm_ignores_peer_id(self) -> None:
        """Different DM peer IDs all collapse to the same main session."""
        k1 = route_to_session("telegram", "main", _dm("user1"))
        k2 = route_to_session("telegram", "main", _dm("user2"))
        assert k1 == k2 == "agent:main:main"

    def test_group_includes_channel_and_peer_id(self) -> None:
        key = route_to_session("telegram", "main", _group("123"))
        assert key == "agent:main:telegram:group:123"

    def test_group_key_format(self) -> None:
        key = route_to_session("slack", "work", _group("C-abc"))
        assert key == "agent:work:slack:group:C-abc"

    def test_thread_extends_dm_parent(self) -> None:
        peer = _thread("t42", _dm())
        key = route_to_session("telegram", "main", peer)
        assert key == "agent:main:main:thread:t42"

    def test_thread_extends_group_parent(self) -> None:
        peer = _thread("t99", _group("456"))
        key = route_to_session("telegram", "main", peer)
        assert key == "agent:main:telegram:group:456:thread:t99"

    def test_nested_thread_extends_correctly(self) -> None:
        """thread-within-thread produces a deeply nested key."""
        group_peer = _group("grp1")
        thread1 = _thread("t1", group_peer)
        thread2 = _thread("t2", thread1)
        key = route_to_session("slack", "work", thread2)
        assert key == "agent:work:slack:group:grp1:thread:t1:thread:t2"

    def test_deterministic_same_inputs_same_key(self) -> None:
        """Calling with identical inputs always returns the same key."""
        peer = _group("789")
        k1 = route_to_session("discord", "main", peer)
        k2 = route_to_session("discord", "main", peer)
        assert k1 == k2

    def test_different_channels_produce_different_group_keys(self) -> None:
        peer = _group("100")
        k_telegram = route_to_session("telegram", "main", peer)
        k_slack = route_to_session("slack", "main", peer)
        assert k_telegram != k_slack

    # ------------------------------------------------------------------
    # Security tests
    # ------------------------------------------------------------------

    def test_different_group_ids_produce_different_keys(self) -> None:
        """Two different group IDs must never share a session key (isolation)."""
        k1 = route_to_session("telegram", "main", _group("group-A"))
        k2 = route_to_session("telegram", "main", _group("group-B"))
        assert k1 != k2

    def test_group_key_cannot_match_dm_key(self) -> None:
        """A group session key must never equal a DM session key."""
        dm_key = route_to_session("telegram", "main", _dm())
        group_key = route_to_session("telegram", "main", _group("main"))
        # Even if peer.id == "main", group key must differ from DM key
        assert dm_key != group_key

    def test_different_agents_produce_different_keys(self) -> None:
        """Two different agent IDs must produce different session keys."""
        peer = _group("same-group")
        k1 = route_to_session("telegram", "main", peer)
        k2 = route_to_session("telegram", "work", peer)
        assert k1 != k2

    def test_thread_key_distinct_from_parent_group_key(self) -> None:
        group = _group("grp1")
        thread = _thread("t1", group)
        group_key = route_to_session("telegram", "main", group)
        thread_key = route_to_session("telegram", "main", thread)
        assert thread_key != group_key
        assert thread_key.startswith(group_key)


# ---------------------------------------------------------------------------
# route_to_session — input validation
# ---------------------------------------------------------------------------


class TestRouteToSessionValidation:
    def test_empty_channel_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            route_to_session("", "main", _dm())

    def test_unknown_channel_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unknown channel"):
            route_to_session("fax", "main", _dm())

    def test_empty_agent_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            route_to_session("telegram", "", _dm())

    def test_unsafe_agent_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid characters"):
            route_to_session("telegram", "main/agent", _dm())

    def test_empty_peer_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            route_to_session("telegram", "main", Peer(kind="dm", id=""))

    def test_unsafe_peer_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid characters"):
            route_to_session("telegram", "main", Peer(kind="group", id="../../etc"))

    def test_thread_with_no_parent_rejected(self) -> None:
        with pytest.raises(ValueError, match="parent"):
            route_to_session("telegram", "main", Peer(kind="thread", id="t1"))

    def test_allowed_channels_all_accepted(self) -> None:
        """Every channel in ALLOWED_CHANNELS must pass validation."""
        for ch in ALLOWED_CHANNELS:
            key = route_to_session(ch, "main", _dm())
            assert key == "agent:main:main"


# ---------------------------------------------------------------------------
# Binding model
# ---------------------------------------------------------------------------


class TestBinding:
    def test_binding_minimal(self) -> None:
        b = Binding(channel="cli", agent_id="main")
        assert b.channel == "cli"
        assert b.agent_id == "main"
        assert b.team_id is None
        assert b.guild_id is None
        assert b.peer_kind is None

    def test_binding_with_all_filters(self) -> None:
        b = Binding(
            channel="slack",
            agent_id="work",
            team_id="T123",
            guild_id=None,
            peer_kind="group",
        )
        assert b.team_id == "T123"
        assert b.peer_kind == "group"


# ---------------------------------------------------------------------------
# resolve_agent
# ---------------------------------------------------------------------------

_BINDINGS: list[Binding] = [
    Binding(channel="slack", team_id="T-work", agent_id="work"),
    Binding(channel="slack", agent_id="main"),  # fallback for other Slack teams
    Binding(channel="telegram", peer_kind="dm", agent_id="main"),
    Binding(channel="telegram", peer_kind="group", agent_id="public"),
    Binding(channel="discord", guild_id="G-public", agent_id="public"),
    Binding(channel="cli", agent_id="main"),
]


class TestResolveAgent:
    def test_resolve_cli_to_main(self) -> None:
        assert resolve_agent("cli", _BINDINGS) == "main"

    def test_resolve_slack_team_to_work_agent(self) -> None:
        assert resolve_agent("slack", _BINDINGS, team_id="T-work") == "work"

    def test_resolve_slack_other_team_to_main(self) -> None:
        """A Slack workspace without a specific binding falls through to the
        catch-all slack binding."""
        assert resolve_agent("slack", _BINDINGS, team_id="T-other") == "main"

    def test_resolve_telegram_dm_to_main_agent(self) -> None:
        assert resolve_agent("telegram", _BINDINGS, peer_kind="dm") == "main"

    def test_resolve_telegram_group_to_public_agent(self) -> None:
        assert resolve_agent("telegram", _BINDINGS, peer_kind="group") == "public"

    def test_resolve_discord_guild_to_public_agent(self) -> None:
        assert resolve_agent("discord", _BINDINGS, guild_id="G-public") == "public"

    def test_resolve_first_match_wins(self) -> None:
        """When multiple bindings could match, the first one in the list wins."""
        bindings = [
            Binding(channel="slack", agent_id="first"),
            Binding(channel="slack", agent_id="second"),
        ]
        assert resolve_agent("slack", bindings) == "first"

    def test_resolve_no_match_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="No binding found"):
            resolve_agent("discord", _BINDINGS, guild_id="UNKNOWN-GUILD")

    def test_resolve_empty_bindings_raises(self) -> None:
        with pytest.raises(ValueError, match="No binding found"):
            resolve_agent("cli", [])

    def test_resolve_invalid_channel_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown channel"):
            resolve_agent("fax", _BINDINGS)

    def test_resolve_empty_channel_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            resolve_agent("", _BINDINGS)

    def test_binding_filter_not_in_filters_matches_any(self) -> None:
        """A binding with no filter fields matches any caller filters."""
        bindings = [Binding(channel="cli", agent_id="main")]
        # Passing extra filters that the binding doesn't constrain — still matches
        assert resolve_agent("cli", bindings, team_id="anything") == "main"
