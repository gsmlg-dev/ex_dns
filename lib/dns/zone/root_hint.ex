defmodule Dns.Zone.RootHint do
  @moduledoc """
  DNS Root Hint

  Root Servers

  The authoritative name servers that serve the DNS root zone, commonly known as the “root servers”, are a network of hundreds of servers in many countries around the world. They are configured in the DNS root zone as 13 named authorities, as follows.

  List of Root Servers

  Hostname | IP Addresses | Operator
  a.root-servers.net | 198.41.0.4, 2001:503:ba3e::2:30 | Verisign, Inc.
  b.root-servers.net | 170.247.170.2, 2801:1b8:10::b | University of Southern California, Information Sciences Institute
  c.root-servers.net | 192.33.4.12, 2001:500:2::c | Cogent Communications
  d.root-servers.net | 199.7.91.13, 2001:500:2d::d | University of Maryland
  e.root-servers.net | 192.203.230.10, 2001:500:a8::e | NASA (Ames Research Center)
  f.root-servers.net | 192.5.5.241, 2001:500:2f::f | Internet Systems Consortium, Inc.
  g.root-servers.net | 192.112.36.4, 2001:500:12::d0d | US Department of Defense (NIC)
  h.root-servers.net | 198.97.190.53, 2001:500:1::53 | US Army (Research Lab)
  i.root-servers.net | 192.36.148.17, 2001:7fe::53 | Netnod
  j.root-servers.net | 192.58.128.30, 2001:503:c27::2:30 | Verisign, Inc.
  k.root-servers.net | 193.0.14.129, 2001:7fd::1 | RIPE NCC
  l.root-servers.net | 199.7.83.42, 2001:500:9f::42 | ICANN
  m.root-servers.net | 202.12.27.33, 2001:dc3::35 | WIDE Project

  """

  @links [
    root_hints: "https://www.internic.net/domain/named.root",
    root_zone: "https://www.internic.net/domain/root.zone",
    root_trust_anchor: [
      url: "https://data.iana.org/root-anchors/",
      icannbundle: "icannbundle.pem",
      p7s: "root-anchors.p7s",
      xml: "root-anchors.xml",
      checksum: "checksums-sha256.txt"
    ],
    top_level_domains: "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
  ]

  def links(), do: @links

  def data_dir, do: Path.join([:code.priv_dir(:ex_dns), "data"])
end
