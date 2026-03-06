"""Proactive processors — scheduler-driven components that observe external data
and produce structured output for main to surface to the user.

Unlike channel agents (reactive, message-driven), proactive processors run on
a configurable schedule and never interact with the user directly.  Their blast
radius is limited: they can only read social feeds and write to their own
restricted output structures.

Current processors
------------------
- SocialSecretaryProcessor  — watches social media feeds, generates alerts
"""
