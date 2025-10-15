#!/usr/bin/env elixir

IO.puts("=== Testing DNS Record Data String.Chars Protocol ===")

# Test basic record types that we can confirm work
test_records = [
  {DNS.Message.Record.Data.A, %DNS.Message.Record.Data.A{data: {192, 168, 1, 1}}, "A record"},
  {DNS.Message.Record.Data.AAAA, %DNS.Message.Record.Data.AAAA{data: {0x2001, 0x0DB8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001}}, "AAAA record"},
  {DNS.Message.Record.Data.CNAME, %DNS.Message.Record.Data.CNAME{data: "example.com"}, "CNAME record"},
  {DNS.Message.Record.Data.NS, %DNS.Message.Record.Data.NS{data: "ns1.example.com"}, "NS record"},
  {DNS.Message.Record.Data.PTR, %DNS.Message.Record.Data.PTR{data: "mail.example.com"}, "PTR record"},
  {DNS.Message.Record.Data.TXT, %DNS.Message.Record.Data.TXT{data: ["v=spf1 include:_spf.example.com ~all"]}, "TXT record"},
  {DNS.Message.Record.Data.MX, %DNS.Message.Record.Data.MX{data: {10, DNS.Message.Domain.new("mail.example.com")}}, "MX record"},
  {DNS.Message.Record.Data.SOA, %DNS.Message.Record.Data.SOA{
    mname: "ns1.example.com",
    rname: "admin.example.com",
    serial: 2023070100,
    refresh: 3600,
    retry: 1800,
    expire: 1209600,
    minimum: 300
  }, "SOA record"},
  {DNS.Message.Record.Data.SRV, %DNS.Message.Record.Data.SRV{priority: 10, weight: 20, port: 5060, target: "sip.example.com"}, "SRV record"}
]

IO.puts("Testing #{length(test_records)} record types...")
IO.puts("=" * 50)

results = Enum.map(test_records, fn {module, record, description} ->
  try do
    string_result = to_string(record)
    IO.puts("✓ #{description}: #{string_result}")
    :ok
  rescue
    e ->
      IO.puts("✗ #{description}: ERROR - #{inspect(e)}")
      :error
  end
end)

ok_count = Enum.count(results, &(&1 == :ok))
total_count = length(results)

IO.puts("=" * 50)
IO.puts("Results: #{ok_count}/#{total_count} record types tested successfully")