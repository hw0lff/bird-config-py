# SPDX-License-Identifier: EUPL-1.2
# generic bird config generation library
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum, auto
from ipaddress import IPv4Address, IPv6Address, ip_network
from textwrap import indent


class Switch(StrEnum):
    Off = "off"
    On = "on"

    @classmethod
    def _missing_(cls, value):
        value = str(value).lower()
        for member in cls:
            if member.value == "on" and value == "true":
                return member
            if member.value == "off" and value == "false":
                return member
        return None


class DebugLevel(StrEnum):
    Off = auto()
    All = auto()
    States = auto()
    Routes = auto()
    Filters = auto()
    Interfaces = auto()
    Events = auto()
    Packets = auto()


def format_debug_option(debug: set[DebugLevel] = set(), infix="") -> str | None:
    if len(debug) == 0:
        return None
    levels = ", ".join(sorted(list(debug))) if debug else None
    infix = infix + " " if infix else ""
    return "debug " + infix + "{ " + f"{levels}" + " };" if debug and levels else None


def format_switch(
    prefix: str, switch: Switch | None, with_semicolon=True
) -> str | None:
    suffix = ";" if with_semicolon else ""
    return f"{prefix} {Switch(switch).value}{suffix}" if switch is not None else None


def try_ip_network(subnet, prefix="") -> str:
    try:
        return prefix + str(ip_network(subnet))
    except:
        return f"{str(subnet)}"


# port: maybe import or export. so just port
def format_port_filter(
    port: str, port_filter: str | Iterable[str] | None
) -> str | None:
    if port_filter is None:
        return None
    filter_str = ""
    if isinstance(port_filter, str) and port_filter.startswith("filter_"):
        port_filter = str(port_filter).removeprefix("filter_")
        filter_str = f"filter {port_filter}"
    elif isinstance(port_filter, Iterable) and not isinstance(port_filter, str):
        networks = (try_ip_network(net) for net in port_filter)
        subnets = ", ".join(networks)
        filter_str = f"where net ~ [ {subnets} ]"
    else:
        filter_str = try_ip_network(port_filter, prefix="where net=")

    return f"{port} {filter_str};"


class Render(ABC):

    # render part of the config line by line.
    # the result contains no newlines
    @abstractmethod
    def render(self) -> Iterable[str]:
        raise NotImplementedError


@dataclass(frozen=True)
class Include(Render):
    file: str

    def render(self) -> Iterable[str]:
        yield f'include "{self.file}";'


@dataclass(frozen=True)
class IPv4Table(Render):
    name: str

    def render(self) -> Iterable[str]:
        nettype = "ipv4"
        yield f"{nettype} table {self.name};"


@dataclass(frozen=True)
class IPv6Table(Render):
    name: str

    def render(self) -> Iterable[str]:
        nettype = "ipv6"
        yield f"{nettype} table {self.name};"


@dataclass(kw_only=True, frozen=True)
class Filter(Render):
    name: str
    body: str

    def render(self) -> Iterable[str]:
        yield f"filter {self.name} {{"
        # prepend \t for indentation
        yield from indent(self.body, "\t").splitlines()
        yield "}"


# base channel class.
# use ChannelV4 and ChannelV6
@dataclass(kw_only=True, frozen=True)
class Channel(Render):
    # channel name implies its nettype (ipv4, ipv6)
    name: str
    debug: set[DebugLevel] = field(default_factory=set)
    table: str | None = None

    import_keep_filtered: Switch | None = None
    # all | none | filter <name>
    #     | filter { <filter commands> }
    #     | where <boolean filter expression>
    import_filter: str | Iterable[str] | None = None
    # all | none | filter <name>
    #     | filter { <filter commands> }
    #     | where <boolean filter expression>
    export_filter: str | Iterable[str] | None = None

    preference: str | None = None

    def render_channel_options(self) -> Iterable[str | None]:
        yield format_debug_option(self.debug)
        yield f"table {self.table};" if self.table else None
        yield format_switch("import keep filtered", self.import_keep_filtered)
        yield format_port_filter("import", self.import_filter)
        yield format_port_filter("export", self.export_filter)
        yield f"preference {self.preference};" if self.preference else None

    def render(self) -> Iterable[str]:
        if self.is_empty():
            return
            yield
        yield f"{self.name} " + "{"

        # remove empty options
        options = filter(None, self.render_channel_options())
        # indent options
        yield from (indent(line, "\t") for line in options)
        yield "};"

    def is_empty(self) -> bool:
        # fmt: off
        return all((
            len(self.debug) == 0,
            self.table is None,
            self.import_keep_filtered is None,
            (self.import_filter is None or self.import_filter == []),
            (self.export_filter is None or self.export_filter == []),
        ))
        # fmt:on


@dataclass(kw_only=True, frozen=True)
class ChannelV4(Channel):
    name: str = "ipv4"


@dataclass(kw_only=True, frozen=True)
class ChannelV6(Channel):
    name: str = "ipv6"


# base protocol class.
# do not use directly
@dataclass(kw_only=True, frozen=True)
class Protocol(Render, ABC):
    # e.g. kernel, direct, bfd, bgp, ospf
    protocol_type: str
    name: str | None = None
    from_template: str | None = None
    # mark this protocol instance as a template
    is_template: bool = False

    # body
    disabled: Switch | None = None
    debug: set[DebugLevel] = field(default_factory=set)
    description: str | None = None
    vrf: str | None = None

    # render common protocol options
    def render_common_options(self) -> Iterable[str]:
        disabled = format_switch("disabled", self.disabled)
        debug = format_debug_option(self.debug)
        description = (
            f'description "{str(self.description)}";' if self.description else None
        )
        vrf = f'vrf "{str(self.vrf)}";' if self.vrf else None
        # no "" when default
        vrf = "vrf default;" if str(self.vrf) == "default" else vrf

        # remove empty common options
        yield from filter(None, (disabled, debug, description, vrf))

    def render(self) -> Iterable[str]:
        block_type = "protocol" if not self.is_template else "template"
        from_template = f"from {self.from_template} " if self.from_template else ""
        name = f"{self.name} " if self.name else ""
        yield f"{block_type} {self.protocol_type} {name}{from_template}" + "{"

        # body
        common_options = list(self.render_common_options())
        # render protocol specific options
        options: list[str] = list(filter(None, self.render_options()))
        padding = [""] if options and common_options else []
        body: list[str] = common_options + padding + options

        # add indentation to options in the body
        yield from (indent(line, "\t") for line in body)
        yield "}"

    # render additional protocol options. contains no newlines
    @abstractmethod
    def render_options(self) -> Iterable[str | None]:
        raise NotImplementedError


@dataclass(kw_only=True, frozen=True)
class Device(Protocol):
    protocol_type: str = "device"

    def render_options(self) -> Iterable[str | None]:
        return
        yield


@dataclass(kw_only=True, frozen=True)
class Direct(Protocol):
    protocol_type: str = "direct"
    interface: str | list[str] | None = None
    check_link: Switch | None = None

    channel_v4: ChannelV4 | None = None
    channel_v6: ChannelV6 | None = None

    def render_options(self) -> Iterable[str | None]:
        ifaces = [self.interface] if isinstance(self.interface, str) else self.interface
        ifaces_fmt = ", ".join(ifaces) if ifaces else None
        yield f"interface {ifaces_fmt};" if ifaces else None

        yield format_switch("check link", self.check_link)

        yield from self.channel_v4.render() if self.channel_v4 else ()
        yield from self.channel_v6.render() if self.channel_v6 else ()


@dataclass(kw_only=True, frozen=True)
class Bfd(Protocol):
    protocol_type: str = "bfd"
    # accept [ipv4|ipv6] [direct|multihop];
    accept: str | None = None

    # neighbor <ip> [dev "<interface>"] [local <ip>] [multihop <switch>]
    nb_ip: IPv4Address | IPv6Address | None = None
    nb_dev: str | None = None
    nb_local_ip: IPv4Address | IPv6Address | None = None
    nb_multihop: Switch | None = None

    def render_options(self) -> Iterable[str | None]:
        yield f"accept {self.accept};" if self.accept else None
        nb = f"neighbor {self.nb_ip}" if self.nb_ip else None
        if nb:
            nb += f' dev "{self.nb_dev}"' if self.nb_dev else ""
            nb += f" local {self.nb_local_ip}" if self.nb_local_ip else ""
            multihop = format_switch("multihop", self.nb_multihop, False)
            nb += " " + multihop if multihop else ""
            nb += ";"

        yield nb


@dataclass(kw_only=True, frozen=True)
class Bgp(Protocol):
    protocol_type: str = "bgp"

    local_as: int | None = None
    src_addr: IPv4Address | IPv6Address | None = None
    neighbor_ip: IPv4Address | IPv6Address | None = None
    neighbor_as: int | None = None

    direct: bool | None = None
    check_link: Switch | None = None
    bfd: Switch | None = None
    strict_bind: Switch | None = None

    channel_v4: ChannelV4 | None = None
    channel_v6: ChannelV6 | None = None

    def render_options(self) -> Iterable[str | None]:
        yield f"local as {self.local_as};" if self.local_as else None
        yield f"source address {self.src_addr};" if self.src_addr else None
        yield (
            f"neighbor {self.neighbor_ip} as {self.neighbor_as};"
            if (self.neighbor_ip and self.neighbor_as)
            else None
        )

        yield "direct;" if self.direct else None
        yield format_switch("check link", self.check_link)
        yield format_switch("bfd", self.bfd)
        yield format_switch("strict bind", self.strict_bind)

        yield from self.channel_v4.render() if self.channel_v4 else ()
        yield from self.channel_v6.render() if self.channel_v6 else ()


@dataclass(kw_only=True, frozen=True)
class Kernel(Protocol):
    protocol_type: str = "kernel"
    scan_time: int | None = None
    learn: Switch | None = None
    kernel_table: int | None = None
    metric: int | None = None
    merge_paths: Switch | None = None

    channel: ChannelV4 | ChannelV6 | None = None

    def render_options(self) -> Iterable[str | None]:
        yield f"scan time {self.scan_time};" if self.scan_time else None
        yield format_switch("learn", self.learn)
        yield f"kernel table {self.kernel_table};" if self.kernel_table else None
        yield f"metric {self.metric};" if self.metric else None
        yield format_switch("merge paths", self.merge_paths)
        yield from self.channel.render() if self.channel else ()


@dataclass(kw_only=True, frozen=True)
class BirdConfig(Render):
    router_id: IPv4Address
    log: str = "syslog all"
    debug_protocols: set[DebugLevel] = field(default_factory=set)

    includes: list[Include] = field(default_factory=list)
    ipv4_tables: list[IPv4Table] = field(default_factory=list)
    ipv6_tables: list[IPv6Table] = field(default_factory=list)
    filters: list[Filter] = field(default_factory=list)
    protocols: list[Protocol] = field(default_factory=list)

    def render(self) -> Iterable[str]:
        yield f"router id {self.router_id};"
        yield f"log {self.log};"
        debug = format_debug_option(self.debug_protocols, infix="protocols")
        if debug:
            yield debug
        yield ""  # padding

        sections: list[list] = [
            self.includes,
            self.ipv4_tables,
            self.ipv6_tables,
            self.filters,
            self.protocols,
        ]

        for section in sections:
            subsections: list[Iterable[str]] = [item.render() for item in section]
            if len(subsections) > 0:
                subsections += [[""]]
            yield from (line for rendered_item in subsections for line in rendered_item)

    def merge(self, other: "BirdConfig") -> "BirdConfig":
        return BirdConfig(
            router_id=other.router_id,
            log=other.log,
            debug_protocols=self.debug_protocols | other.debug_protocols,
            includes=self.includes + other.includes,
            ipv4_tables=self.ipv4_tables + other.ipv4_tables,
            ipv6_tables=self.ipv6_tables + other.ipv6_tables,
            filters=self.filters + other.filters,
            protocols=self.protocols + other.protocols,
        )

    __or__ = merge
