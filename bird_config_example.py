# SPDX-License-Identifier: EUPL-1.2
# example usage of bird_config.py
from textwrap import dedent
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

try:
    from rich import print
except ImportError:
    pass

from bird_config import (
    Switch,
    DebugLevel,
    Include,
    IPv4Table,
    IPv6Table,
    ChannelV4,
    ChannelV6,
    Protocol,
    Filter,
    Device,
    Direct,
    Bfd,
    Bgp,
    Kernel,
    BirdConfig,
)

def make_defaults(router_id) -> BirdConfig:
    routes = dict(v4="0.0.0.0/0", v6="::/0")
    actions = dict(only=["accept", "reject"], no=["reject", "accept"])

    default_filters = []
    for suffix, route in routes.items():
        for prefix, decision in actions.items():
            body = f"""
                if (net = {route}) then {{
                \t{decision[0]};
                }} else {decision[1]};
            """
            default_filters += [
                Filter(
                    name=f"{prefix}_default_route_{suffix}",
                    body=dedent(body).strip(),
                )
            ]

    device_proto = Device(debug={DebugLevel.States, DebugLevel.Interfaces})
    protocols: list[Protocol] = [device_proto]

    bird_config = BirdConfig(
        router_id=router_id,
        debug_protocols={DebugLevel.States, DebugLevel.Interfaces, DebugLevel.Events},
        filters=default_filters,
        protocols=protocols,
    )
    return bird_config


router_id = IPv4Address("192.0.2.123")
alt_v4 = IPv4Address("192.0.2.23")
router_ipv6 = IPv6Address("2001:db8::1234")
default_config = make_defaults(router_id)

debug = {DebugLevel.States, DebugLevel.Interfaces, DebugLevel.Events}
kernel_filter_v4 = Filter(
    name="kernel_prefsrc_v4",
    body=dedent(
        f"""
            krt_prefsrc = {router_id};
            accept;
        """
    ).strip(),
)
kernel_filter_v6 = Filter(
    name="kernel_prefsrc_v6",
    body=dedent(
        f"""
            krt_prefsrc = {router_ipv6};
            accept;
        """
    ).strip(),
)

filters = [kernel_filter_v4, kernel_filter_v6]

v4channel = ChannelV4(import_filter="none", export_filter="all")
v6channel = ChannelV6(import_filter="all", export_filter="none")

k_chan4 = ChannelV4(
    import_filter="all", export_filter="filter_kernel_prefsrc_v4", table="my_other_vrf"
)
k_chan6 = ChannelV6(import_filter="all", export_filter="filter_kernel_prefsrc_v6")

krnl_tmpl = Kernel(
    name="kernel_tmpl",
    is_template=True,
    debug=debug,
    scan_time=60,
    metric=1500,
    merge_paths=Switch.On,
)
krnl_my_other_vrf = Kernel(
    name="kernel_my_other_vrf",
    from_template="kernel_tmpl",
    kernel_table=1042,
    channel=k_chan4,
    vrf="my_other_vrf",
)
krnl_my_other_vrf6 = Kernel(
    name="kernel_my_other_vrf6",
    from_template="kernel_tmpl",
    kernel_table=1042,
    channel=k_chan6,
)

bfd_tmpl = Bfd(
    name="bfd_tmpl",
    is_template=True,
    debug=debug,
    accept="direct",
)
bfd_my_other_vrf = Bfd(
    name="bfd_my_other_vrf",
    from_template="bfd_tmpl",
    vrf="my_other_vrf",
)
bfd_default = Bfd(
    name="bfd_default",
    from_template="bfd_tmpl",
    vrf="default",
)
bfd_cool = Bfd(
    name="bfd_cool",
    from_template="bfd_tmpl",
    vrf="my_extra_vrf",
    nb_ip=ip_address("192.0.2.233"),
    nb_dev="eth0",
    nb_local_ip=router_id,
)
direct_tmpl = Direct(
    check_link=Switch.On,
    name="direct_tmpl",
    debug=debug,
    is_template=True,
    channel_v4=v4channel,
    channel_v6=v6channel,
)
direct = Direct(
    name="my_other_vrf",
    interface=[str(router_id), str(alt_v4), "2001:db8::1/64"],
    debug=debug,
    from_template="direct_tmpl",
    channel_v4=ChannelV4(table="my_other_vrf"),
    channel_v6=ChannelV6(table="my_other_vrf6"),
)

bgp_v4chan = ChannelV4(
    import_keep_filtered=Switch.On,
    import_filter="all",
    export_filter=[f"{router_id}", f"{alt_v4}", ip_network("192.0.2.20/30")],
)
bgp_v6chan = ChannelV6(
    import_keep_filtered=Switch.On, import_filter="all", export_filter=f"{router_ipv6}"
)

bgp_kwargs = {
    "direct": True,
    "check_link": Switch.On,
    "bfd": Switch.On,
    "strict_bind": Switch.On,
}
bgp_tmpl_v4 = Bgp(
    name="bgp_tmpl_v4",
    is_template=True,
    debug=debug,
    channel_v4=bgp_v4chan,
    **bgp_kwargs,
)
bgp_tmpl_v6 = Bgp(
    name="bgp_tmpl_v6",
    is_template=True,
    debug=debug,
    channel_v6=bgp_v6chan,
    **bgp_kwargs,
)


def mkBgp(src, local_as, neighbor_ip, neighbor_as):
    return Bgp(
        from_template="bgp_tmpl_v4",
        src_addr=src,
        local_as=local_as,
        neighbor_ip=neighbor_ip,
        neighbor_as=neighbor_as,
    )


protocols: list[Protocol] = [
    direct_tmpl,
    direct,
    bfd_tmpl,
    bfd_my_other_vrf,
    bfd_default,
    bfd_cool,
    krnl_tmpl,
    krnl_my_other_vrf,
    krnl_my_other_vrf6,
    bgp_tmpl_v4,
    bgp_tmpl_v6,
    mkBgp(router_id, 4242420001, "192.0.2.245", 4242420003),
    mkBgp(router_id, 4242420001, "192.0.2.244", 4242420002),
]
generated = BirdConfig(
    router_id=router_id,
    includes=[Include("/your/very/special/file.conf")],
    ipv4_tables=[IPv4Table("my_other_vrf"), IPv4Table("my_extra_vrf")],
    ipv6_tables=[IPv6Table("my_other_vrf6"), IPv6Table("my_extra_vrf6")],
    filters=filters,
    protocols=protocols,
)
merged = default_config.merge(generated)

print("\n".join(merged.render()))
