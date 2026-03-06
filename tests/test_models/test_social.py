"""Tests for the Social Secretary data models.

Test classes:
    TestSocialAlert          — construction, field constraints, defaults
    TestContactEntry         — construction, optional fields, dict fields
    TestLearningObservation  — construction, literal validation, lifecycle
    TestSocialSecretaryConfig — defaults, bounded fields, literal validation
    TestAlertQueue           — empty valid, append, round-trip serialisation
    TestContactsStore        — empty valid, mutate, round-trip serialisation
    TestLearningQueue        — empty valid, observation lifecycle
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from openrattler.models.social import (
    AlertQueue,
    ContactEntry,
    ContactsStore,
    LearningObservation,
    LearningQueue,
    SocialAlert,
    SocialSecretaryConfig,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alert(**kwargs: object) -> SocialAlert:
    defaults: dict[str, object] = {
        "source": "facebook",
        "person": "Alice Smith",
        "relationship_strength": "strong",
        "relationship_context": "college friend group",
        "event_type": "birthday",
        "summary": "Alice posted about her upcoming birthday on April 15.",
        "urgency": "next_interaction",
        "recommended_action": "suggest_response",
        "recommended_timing": "next_natural_interaction",
        "confidence": 0.9,
        "raw_reference_id": "fb_post_12345",
    }
    defaults.update(kwargs)
    return SocialAlert(**defaults)  # type: ignore[arg-type]


def _contact(**kwargs: object) -> ContactEntry:
    defaults: dict[str, object] = {
        "name": "Bob Jones",
        "relationship": "close friend",
        "context_learned": "Mentioned by user in conversation",
        "source": "user_mentioned",
    }
    defaults.update(kwargs)
    return ContactEntry(**defaults)  # type: ignore[arg-type]


def _observation(**kwargs: object) -> LearningObservation:
    defaults: dict[str, object] = {
        "observed": "User mentioned they were going to the doctor.",
        "source_session": "agent:main:main",
        "source_date": date(2025, 4, 1),
        "priority": "important",
        "best_context": "next_interaction",
        "relates_to": "user",
        "purpose": "social_obligation",
    }
    defaults.update(kwargs)
    return LearningObservation(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestSocialAlert
# ---------------------------------------------------------------------------


class TestSocialAlert:
    """SocialAlert construction, field constraints, and defaults."""

    def test_valid_construction(self) -> None:
        """A fully-specified alert is accepted."""
        alert = _alert()
        assert alert.person == "Alice Smith"
        assert alert.source == "facebook"
        assert alert.event_type == "birthday"

    def test_id_auto_generated(self) -> None:
        """id is generated with the 'social_alert_' prefix by default."""
        alert = _alert()
        assert alert.id.startswith("social_alert_")
        assert len(alert.id) == len("social_alert_") + 8  # hex8

    def test_id_is_unique_per_instance(self) -> None:
        """Two separate alerts get different ids."""
        a1 = _alert()
        a2 = _alert()
        assert a1.id != a2.id

    def test_custom_id_accepted(self) -> None:
        """A manually supplied id overrides the default factory."""
        alert = _alert(id="social_alert_abcd1234")
        assert alert.id == "social_alert_abcd1234"

    def test_acknowledged_defaults_false(self) -> None:
        """acknowledged starts as False and acknowledged_at is None."""
        alert = _alert()
        assert alert.acknowledged is False
        assert alert.acknowledged_at is None

    def test_confidence_lower_bound(self) -> None:
        """confidence=0.0 is valid."""
        alert = _alert(confidence=0.0)
        assert alert.confidence == 0.0

    def test_confidence_upper_bound(self) -> None:
        """confidence=1.0 is valid."""
        alert = _alert(confidence=1.0)
        assert alert.confidence == 1.0

    def test_confidence_below_zero_rejected(self) -> None:
        """confidence < 0.0 raises ValidationError."""
        with pytest.raises(ValidationError):
            _alert(confidence=-0.1)

    def test_confidence_above_one_rejected(self) -> None:
        """confidence > 1.0 raises ValidationError."""
        with pytest.raises(ValidationError):
            _alert(confidence=1.01)

    def test_invalid_urgency_rejected(self) -> None:
        """urgency must be a defined literal."""
        with pytest.raises(ValidationError):
            _alert(urgency="critical")

    def test_invalid_event_type_rejected(self) -> None:
        """event_type must be a defined literal."""
        with pytest.raises(ValidationError):
            _alert(event_type="lottery_win")

    def test_invalid_recommended_action_rejected(self) -> None:
        """recommended_action must be a defined literal."""
        with pytest.raises(ValidationError):
            _alert(recommended_action="delete_contact")

    def test_invalid_recommended_timing_rejected(self) -> None:
        """recommended_timing must be a defined literal."""
        with pytest.raises(ValidationError):
            _alert(recommended_timing="someday")

    def test_invalid_relationship_strength_rejected(self) -> None:
        """relationship_strength must be a defined literal."""
        with pytest.raises(ValidationError):
            _alert(relationship_strength="very_close")

    def test_created_is_utc_datetime(self) -> None:
        """created is set to a UTC-aware datetime by default."""
        alert = _alert()
        assert isinstance(alert.created, datetime)
        assert alert.created.tzinfo is not None

    def test_all_event_types_accepted(self) -> None:
        """All defined event_type literals are accepted."""
        for et in (
            "birthday",
            "health_update",
            "life_event",
            "career_change",
            "engagement",
            "birth",
            "death",
            "anniversary",
            "post_mention",
        ):
            a = _alert(event_type=et)
            assert a.event_type == et

    def test_serialisation_round_trip(self) -> None:
        """model_dump → model_validate produces equal model."""
        alert = _alert()
        data = alert.model_dump()
        reloaded = SocialAlert.model_validate(data)
        assert reloaded.id == alert.id
        assert reloaded.person == alert.person
        assert reloaded.confidence == alert.confidence


# ---------------------------------------------------------------------------
# TestContactEntry
# ---------------------------------------------------------------------------


class TestContactEntry:
    """ContactEntry construction and optional dict fields."""

    def test_valid_construction(self) -> None:
        """Minimal required fields are enough to create a ContactEntry."""
        contact = _contact()
        assert contact.name == "Bob Jones"
        assert contact.relationship == "close friend"

    def test_relevant_details_defaults_empty(self) -> None:
        """relevant_details is an empty dict by default."""
        contact = _contact()
        assert contact.relevant_details == {}

    def test_relevant_details_accepts_string_dict(self) -> None:
        """relevant_details stores arbitrary string key-value pairs."""
        contact = _contact(relevant_details={"birthday": "April 15", "city": "Chicago"})
        assert contact.relevant_details["birthday"] == "April 15"

    def test_social_ids_defaults_empty(self) -> None:
        """social_ids is an empty dict by default."""
        contact = _contact()
        assert contact.social_ids == {}

    def test_social_ids_stores_platform_mapping(self) -> None:
        """social_ids stores platform → id pairs."""
        contact = _contact(social_ids={"facebook": "fb_id_999", "twitter": "tw_999"})
        assert contact.social_ids["facebook"] == "fb_id_999"

    def test_attention_level_default_normal(self) -> None:
        """attention_level defaults to 'normal'."""
        contact = _contact()
        assert contact.attention_level == "normal"

    def test_attention_level_literals(self) -> None:
        """All valid attention_level values are accepted."""
        for level in ("watch_closely", "normal", "low"):
            c = _contact(attention_level=level)
            assert c.attention_level == level

    def test_invalid_attention_level_rejected(self) -> None:
        """attention_level must be a defined literal."""
        with pytest.raises(ValidationError):
            _contact(attention_level="ignore")

    def test_notes_defaults_empty(self) -> None:
        """notes is an empty list by default."""
        contact = _contact()
        assert contact.notes == []

    def test_notes_stores_strings(self) -> None:
        """notes accepts a list of strings."""
        contact = _contact(notes=["Met at conference 2023", "Likes hiking"])
        assert len(contact.notes) == 2

    def test_last_updated_is_utc(self) -> None:
        """last_updated is a UTC-aware datetime."""
        contact = _contact()
        assert isinstance(contact.last_updated, datetime)
        assert contact.last_updated.tzinfo is not None

    def test_serialisation_round_trip(self) -> None:
        """model_dump → model_validate produces equal model."""
        contact = _contact(
            relevant_details={"birthday": "June 3"},
            social_ids={"facebook": "fb_42"},
        )
        data = contact.model_dump()
        reloaded = ContactEntry.model_validate(data)
        assert reloaded.name == contact.name
        assert reloaded.relevant_details == contact.relevant_details


# ---------------------------------------------------------------------------
# TestLearningObservation
# ---------------------------------------------------------------------------


class TestLearningObservation:
    """LearningObservation construction and lifecycle."""

    def test_valid_construction(self) -> None:
        """Required fields produce a valid open observation."""
        obs = _observation()
        assert obs.observed == "User mentioned they were going to the doctor."
        assert obs.status == "open"
        assert obs.priority == "important"

    def test_id_auto_generated(self) -> None:
        """id is generated with the 'obs_' prefix."""
        obs = _observation()
        assert obs.id.startswith("obs_")
        assert len(obs.id) == len("obs_") + 8

    def test_id_unique_per_instance(self) -> None:
        """Two observations get different ids."""
        o1 = _observation()
        o2 = _observation()
        assert o1.id != o2.id

    def test_status_defaults_open(self) -> None:
        """status defaults to 'open'."""
        obs = _observation()
        assert obs.status == "open"

    def test_invalid_priority_rejected(self) -> None:
        """priority must be a defined literal."""
        with pytest.raises(ValidationError):
            _observation(priority="urgent")

    def test_invalid_status_rejected(self) -> None:
        """status must be a defined literal."""
        with pytest.raises(ValidationError):
            _observation(status="completed")

    def test_all_priority_literals(self) -> None:
        """All valid priority values are accepted."""
        for p in ("blocking", "important", "curious"):
            o = _observation(priority=p)
            assert o.priority == p

    def test_all_status_literals(self) -> None:
        """All valid status values are accepted."""
        for s in ("open", "in_progress", "resolved", "archived"):
            o = _observation(status=s)
            assert o.status == s

    def test_resolved_date_and_resolution_optional(self) -> None:
        """resolved_date and resolution default to None."""
        obs = _observation()
        assert obs.resolved_date is None
        assert obs.resolution is None

    def test_resolved_observation_can_set_date_and_resolution(self) -> None:
        """resolved_date and resolution can be set independently of status."""
        obs = _observation(
            status="resolved",
            resolved_date=date(2025, 5, 1),
            resolution="The doctor visit went well.",
        )
        assert obs.resolved_date == date(2025, 5, 1)
        assert obs.resolution == "The doctor visit went well."

    def test_blocks_optional(self) -> None:
        """blocks defaults to None."""
        obs = _observation()
        assert obs.blocks is None

    def test_blocks_stores_task_name(self) -> None:
        """blocks accepts a task name string."""
        obs = _observation(blocks="Q3 hiring plan")
        assert obs.blocks == "Q3 hiring plan"

    def test_serialisation_round_trip(self) -> None:
        """model_dump → model_validate produces equal model."""
        obs = _observation(
            status="resolved",
            resolved_date=date(2025, 5, 1),
            resolution="All clear.",
        )
        data = obs.model_dump()
        reloaded = LearningObservation.model_validate(data)
        assert reloaded.id == obs.id
        assert reloaded.resolved_date == obs.resolved_date


# ---------------------------------------------------------------------------
# TestSocialSecretaryConfig
# ---------------------------------------------------------------------------


class TestSocialSecretaryConfig:
    """SocialSecretaryConfig defaults, bounds, and literal validation."""

    def test_defaults(self) -> None:
        """Default config is sensible and disabled by default."""
        cfg = SocialSecretaryConfig()
        assert cfg.enabled is False
        assert cfg.cycle_interval_minutes == 120
        assert cfg.active_hours_start == "07:00"
        assert cfg.active_hours_end == "22:00"
        assert cfg.model == "anthropic/claude-haiku-4.5"
        assert cfg.escalation_model == "anthropic/claude-sonnet-4.5"
        assert cfg.max_alerts_per_cycle == 10
        assert cfg.security_profile == "observer"
        assert cfg.connected_platforms == []
        assert cfg.strip_urls is True
        assert cfg.strip_mentions is False

    def test_default_watch_event_types(self) -> None:
        """Default watch_event_types includes core life events."""
        cfg = SocialSecretaryConfig()
        assert "birthday" in cfg.watch_event_types
        assert "death" in cfg.watch_event_types
        assert "health_update" in cfg.watch_event_types

    def test_cycle_interval_minimum_15(self) -> None:
        """cycle_interval_minutes must be >= 15."""
        with pytest.raises(ValidationError):
            SocialSecretaryConfig(cycle_interval_minutes=14)

    def test_cycle_interval_exactly_15_accepted(self) -> None:
        """cycle_interval_minutes=15 is the minimum valid value."""
        cfg = SocialSecretaryConfig(cycle_interval_minutes=15)
        assert cfg.cycle_interval_minutes == 15

    def test_invalid_security_profile_rejected(self) -> None:
        """security_profile must be one of: observer, interactive, publisher."""
        with pytest.raises(ValidationError):
            SocialSecretaryConfig(security_profile="admin")  # type: ignore[arg-type]

    def test_all_security_profiles_accepted(self) -> None:
        """All defined security_profile literals are accepted."""
        for profile in ("observer", "interactive", "publisher"):
            cfg = SocialSecretaryConfig(security_profile=profile)  # type: ignore[arg-type]
            assert cfg.security_profile == profile

    def test_empty_connected_platforms_valid(self) -> None:
        """empty connected_platforms is valid (SS starts inactive)."""
        cfg = SocialSecretaryConfig(connected_platforms=[])
        assert cfg.connected_platforms == []

    def test_multiple_platforms_accepted(self) -> None:
        """Multiple MCP server IDs are accepted."""
        cfg = SocialSecretaryConfig(connected_platforms=["facebook-mcp", "twitter-mcp"])
        assert len(cfg.connected_platforms) == 2

    def test_max_alerts_per_cycle_minimum_1(self) -> None:
        """max_alerts_per_cycle must be >= 1."""
        with pytest.raises(ValidationError):
            SocialSecretaryConfig(max_alerts_per_cycle=0)

    def test_serialisation_round_trip(self) -> None:
        """model_dump → model_validate preserves all fields."""
        cfg = SocialSecretaryConfig(
            enabled=True,
            cycle_interval_minutes=60,
            connected_platforms=["facebook-mcp"],
        )
        data = cfg.model_dump()
        reloaded = SocialSecretaryConfig.model_validate(data)
        assert reloaded.enabled is True
        assert reloaded.cycle_interval_minutes == 60
        assert reloaded.connected_platforms == ["facebook-mcp"]


# ---------------------------------------------------------------------------
# TestAlertQueue
# ---------------------------------------------------------------------------


class TestAlertQueue:
    """AlertQueue container — empty valid, append, serialisation."""

    def test_empty_queue_valid(self) -> None:
        """An empty AlertQueue is valid."""
        q = AlertQueue()
        assert q.alerts == []
        assert q.last_cycle is None
        assert q.total_cycles_run == 0

    def test_append_alert(self) -> None:
        """An alert can be appended to the queue."""
        q = AlertQueue()
        alert = _alert()
        q.alerts.append(alert)
        assert len(q.alerts) == 1
        assert q.alerts[0].id == alert.id

    def test_multiple_alerts(self) -> None:
        """Multiple alerts can be stored in the queue."""
        alerts = [_alert(person=f"Person {i}") for i in range(5)]
        q = AlertQueue(alerts=alerts)
        assert len(q.alerts) == 5

    def test_last_cycle_can_be_set(self) -> None:
        """last_cycle accepts a datetime."""
        now = datetime.now(timezone.utc)
        q = AlertQueue(last_cycle=now, total_cycles_run=3)
        assert q.last_cycle == now
        assert q.total_cycles_run == 3

    def test_serialisation_round_trip(self) -> None:
        """model_dump → model_validate preserves all fields."""
        now = datetime.now(timezone.utc)
        q = AlertQueue(
            alerts=[_alert()],
            last_cycle=now,
            total_cycles_run=7,
        )
        data = q.model_dump()
        reloaded = AlertQueue.model_validate(data)
        assert len(reloaded.alerts) == 1
        assert reloaded.total_cycles_run == 7
        assert reloaded.alerts[0].person == "Alice Smith"


# ---------------------------------------------------------------------------
# TestContactsStore
# ---------------------------------------------------------------------------


class TestContactsStore:
    """ContactsStore container — empty valid, add/remove, serialisation."""

    def test_empty_store_valid(self) -> None:
        """An empty ContactsStore is valid."""
        store = ContactsStore()
        assert store.contacts == []
        assert store.last_updated is None

    def test_add_contact(self) -> None:
        """A contact can be appended to the store."""
        store = ContactsStore()
        contact = _contact()
        store.contacts.append(contact)
        assert len(store.contacts) == 1

    def test_remove_contact(self) -> None:
        """A contact can be removed by index."""
        contact = _contact()
        store = ContactsStore(contacts=[contact])
        store.contacts.remove(contact)
        assert len(store.contacts) == 0

    def test_last_updated_can_be_set(self) -> None:
        """last_updated accepts a datetime."""
        now = datetime.now(timezone.utc)
        store = ContactsStore(last_updated=now)
        assert store.last_updated == now

    def test_serialisation_round_trip(self) -> None:
        """model_dump → model_validate preserves contacts."""
        contact = _contact(
            relevant_details={"birthday": "June 3"},
            social_ids={"facebook": "fb_123"},
        )
        store = ContactsStore(contacts=[contact], last_updated=datetime.now(timezone.utc))
        data = store.model_dump()
        reloaded = ContactsStore.model_validate(data)
        assert len(reloaded.contacts) == 1
        assert reloaded.contacts[0].name == "Bob Jones"
        assert reloaded.contacts[0].relevant_details["birthday"] == "June 3"


# ---------------------------------------------------------------------------
# TestLearningQueue
# ---------------------------------------------------------------------------


class TestLearningQueue:
    """LearningQueue container — empty valid, observation lifecycle."""

    def test_empty_queue_valid(self) -> None:
        """An empty LearningQueue is valid."""
        q = LearningQueue()
        assert q.observations == []

    def test_add_observation(self) -> None:
        """An observation can be appended."""
        q = LearningQueue()
        obs = _observation()
        q.observations.append(obs)
        assert len(q.observations) == 1

    def test_open_to_resolved_lifecycle(self) -> None:
        """An observation can be moved from open to resolved."""
        obs = _observation(status="open")
        assert obs.status == "open"

        # Simulate resolution
        resolved = obs.model_copy(
            update={
                "status": "resolved",
                "resolved_date": date(2025, 6, 1),
                "resolution": "Follow-up confirmed: no issues.",
            }
        )
        assert resolved.status == "resolved"
        assert resolved.resolved_date == date(2025, 6, 1)
        assert resolved.resolution is not None

    def test_resolved_to_archived_lifecycle(self) -> None:
        """A resolved observation can be archived."""
        obs = _observation(status="resolved", resolved_date=date(2025, 6, 1))
        archived = obs.model_copy(update={"status": "archived"})
        assert archived.status == "archived"

    def test_filter_open_observations(self) -> None:
        """Open observations can be filtered from a mixed queue."""
        obs_open = _observation(status="open")
        obs_resolved = _observation(status="resolved")
        obs_archived = _observation(status="archived")
        q = LearningQueue(observations=[obs_open, obs_resolved, obs_archived])

        open_obs = [o for o in q.observations if o.status == "open"]
        assert len(open_obs) == 1
        assert open_obs[0].id == obs_open.id

    def test_serialisation_round_trip(self) -> None:
        """model_dump → model_validate preserves observations."""
        obs = _observation(
            status="resolved",
            resolved_date=date(2025, 5, 15),
            resolution="Doctor visit went fine.",
        )
        q = LearningQueue(observations=[obs])
        data = q.model_dump()
        reloaded = LearningQueue.model_validate(data)
        assert len(reloaded.observations) == 1
        assert reloaded.observations[0].status == "resolved"
        assert reloaded.observations[0].resolution == "Doctor visit went fine."
