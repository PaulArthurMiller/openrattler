"""Channel adapters — bridge external I/O protocols to UniversalMessage.

Each adapter implements ``ChannelAdapter`` (``openrattler.channels.base``)
and translates a specific channel's native format to/from UniversalMessage.

Available adapters:
    CLIAdapter   — stdin/stdout (``openrattler.channels.cli_adapter``)
"""
