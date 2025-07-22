#!/usr/bin/env elixir

# Comprehensive test of all DNS.Message.Record.Data String.Chars implementations
IO.puts("=== Comprehensive DNS Record Data String.Chars Test ===")
IO.puts("Testing all record types in ex_dns library\n")

# Record types to test with sample data
record_tests = [
  {DNS.Message.Record.Data.A, %DNS.Message.Record.Data.A{address: {192, 168, 1, 1}}, "A record"},
  {DNS.Message.Record.Data.AAAA, %DNS.Message.Record.Data.AAAA{address: {0x2001, 0x0DB8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001}}, "AAAA record"},
  {DNS.Message.Record.Data.CAA, %DNS.Message.Record.Data.CAA{flags: 128, tag: "issue", value: "letsencrypt.org"}, "CAA record"},
  {DNS.Message.Record.Data.CNAME, %DNS.Message.Record.Data.CNAME{cname: "example.com"}, "CNAME record"},
  {DNS.Message.Record.Data.DNSKEY, %DNS.Message.Record.Data.DNSKEY{flags: 256, protocol: 3, algorithm: 8, public_key: <<1, 1, 1>>}, "DNSKEY record"},
  {DNS.Message.Record.Data.DS, %DNS.Message.Record.Data.DS{key_tag: 12345, algorithm: 8, digest_type: 2, digest: <<1, 2, 3, 4, 5>>}, "DS record"},
  {DNS.Message.Record.Data.HTTPS, %DNS.Message.Record.Data.HTTPS{priority: 1, target: "https.example.com", svc_params: %{alpn: ["h2"], port: 443}}, "HTTPS record"},
  {DNS.Message.Record.Data.MX, %DNS.Message.Record.Data.MX{exchange: "mail.example.com", preference: 10}, "MX record"},
  {DNS.Message.Record.Data.NS, %DNS.Message.Record.Data.NS{nsdname: "ns1.example.com"}, "NS record"},
  {DNS.Message.Record.Data.NSEC, %DNS.Message.Record.Data.NSEC{next_domain_name: "z.example.com", type_bit_maps: [:A, :AAAA]}, "NSEC record"},
  {DNS.Message.Record.Data.NSEC3, %DNS.Message.Record.Data.NSEC3{hash_algorithm: 1, flags: 0, iterations: 100, salt: "salt", next_hashed_owner_name: "hash", type_bit_maps: [:A, :AAAA]}, "NSEC3 record"},
  {DNS.Message.Record.Data.NSEC3PARAM, %DNS.Message.Record.Data.NSEC3PARAM{hash_algorithm: 1, flags: 0, iterations: 100, salt: "salt"}, "NSEC3PARAM record"},
  {DNS.Message.Record.Data.OPT, %DNS.Message.Record.Data.OPT{payload_size: 4096, extended_rcode: 0, version: 0, flags: 0, options: []}, "OPT record"},
  {DNS.Message.Record.Data.PTR, %DNS.Message.Record.Data.PTR{ptrdname: "mail.example.com"}, "PTR record"},
  {DNS.Message.Record.Data.RRSIG, %DNS.Message.Record.Data.RRSIG{
    type_covered: :A,
    algorithm: 8,
    labels: 2,
    original_ttl: 3600,
    signature_expiration: 1672531200,
    signature_inception: 1672444800,
    key_tag: 12345,
    signers_name: "example.com",
    signature: <<1, 2, 3, 4, 5>>
  }, "RRSIG record"},
  {DNS.Message.Record.Data.SOA, %DNS.Message.Record.Data.SOA{
    mname: "ns1.example.com",
    rname: "admin.example.com",
    serial: 2023070100,
    refresh: 3600,
    retry: 1800,
    expire: 1209600,
    minimum: 300
  }, "SOA record"},
  {DNS.Message.Record.Data.SRV, %DNS.Message.Record.Data.SRV{priority: 10, weight: 20, port: 5060, target: "sip.example.com"}, "SRV record"},
  {DNS.Message.Record.Data.SVCB, %DNS.Message.Record.Data.SVCB{
    priority: 1,
    target: "svc.example.com", 
    svc_params: %{alpn: ["h2"], ipv4hint: [{192, 168, 1, 1}]}
  }, "SVCB record"},
  {DNS.Message.Record.Data.TLSA, %DNS.Message.Record.Data.TLSA{usage: 3, selector: 1, matching_type: 1, certificate_association_data: <<1, 2, 3, 4, 5>>}, "TLSA record"},
  {DNS.Message.Record.Data.TXT, %DNS.Message.Record.Data.TXT{strings: ["v=spf1 include:_spf.example.com ~all"]}, "TXT record"}
]

# Test each record type
IO.puts("Testing String.Chars protocol for #{length(record_tests)} record types...")
IO.puts("=" * 60)

Enum.each(record_tests, fn {module, record, description} ->
  try do
    string_result = to_string(record)
    IO.puts("✓ #{description}: #{string_result}")
  rescue
    e ->
      IO.puts("✗ #{description}: ERROR - #{inspect(e)}")
  end
end)

IO.puts("=" * 60)
IO.puts("Test completed!")