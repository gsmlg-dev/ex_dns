defmodule DNS.Message.EDNS0.Option do
  @moduledoc """
  DNS EDNS0 Option Codes (OPT)

        0	Reserved		[RFC6891](https://datatracker.ietf.org/doc/html/rfc6891)
        1	LLQ	Optional	[RFC8764](https://datatracker.ietf.org/doc/html/rfc8764)
        2	Update Lease	Standard	[RFC-ietf-dnssd-update-lease-08]
        3	NSID	Standard	[RFC5001](https://datatracker.ietf.org/doc/html/rfc5001)
        4	Reserved		[draft-cheshire-edns0-owner-option]
        5	DAU	Standard	[RFC6975](https://datatracker.ietf.org/doc/html/rfc6975)
        6	DHU	Standard	[RFC6975](https://datatracker.ietf.org/doc/html/rfc6975)
        7	N3U	Standard	[RFC6975](https://datatracker.ietf.org/doc/html/rfc6975)
        8	edns-client-subnet	Optional	[RFC7871](https://datatracker.ietf.org/doc/html/rfc7871)
        9	EDNS EXPIRE	Optional	[RFC7314](https://datatracker.ietf.org/doc/html/rfc7314)
        10	COOKIE	Standard	[RFC7873](https://datatracker.ietf.org/doc/html/rfc7873)
        11	edns-tcp-keepalive	Standard	[RFC7828](https://datatracker.ietf.org/doc/html/rfc7828)
        12	Padding	Standard	[RFC7830](https://datatracker.ietf.org/doc/html/rfc7830)
        13	CHAIN	Standard	[RFC7901](https://datatracker.ietf.org/doc/html/rfc7901)
        14	edns-key-tag	Optional	[RFC8145](https://datatracker.ietf.org/doc/html/rfc8145)
        15	Extended DNS Error	Standard	[RFC8914](https://datatracker.ietf.org/doc/html/rfc8914)
        16	EDNS-Client-Tag	Optional	[draft-bellis-dnsop-edns-tags]
        17	EDNS-Server-Tag	Optional	[draft-bellis-dnsop-edns-tags]
        18	Report-Channel	Standard	[RFC9567](https://datatracker.ietf.org/doc/html/rfc9567)
        19-20291	Unassigned
        20292	Umbrella Ident	Optional	[https://developer.cisco.com/docs/cloud-security/#!integrating-network-devices/rdata-description][Cisco_CIE_DNS_team]
        20293-26945	Unassigned
        26946	DeviceID	Optional	[https://developer.cisco.com/docs/cloud-security/#!network-devices-getting-started/response-codes][Cisco_CIE_DNS_team]
        26947-65000	Unassigned
        65001-65534	Reserved for Local/Experimental Use		[RFC6891](https://datatracker.ietf.org/doc/html/rfc6891)
        65535	Reserved for future expansion		[RFC6891](https://datatracker.ietf.org/doc/html/rfc6891)
  """

  # alias DNS.Message.EDNS0.Option

  @type t :: %__MODULE__{
          code: 0..65535,
          data: any()
        }

  defstruct code: 0, data: nil

  def new(code, data) do
    %__MODULE__{code: code, data: data}
  end

  def from_binary(<<code::16, length::16, payload::binary>>) do
  end

  @doc """
  Parse Option

  ## 8	edns-client-subnet

                +0 (MSB)                            +1 (LSB)
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         0: |                          OPTION-CODE                          |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         2: |                         OPTION-LENGTH                         |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         4: |                            FAMILY                             |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         8: |                           ADDRESS...                          /
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  """
  def parse(code, buffer)

  def parse(8, <<family::16, source_prefix::8, scope_prefix::8, addr::binary>>) do
    case {family, source_prefix} do
      {1, source_prefix} when source_prefix <= 8 ->
        <<a::8>> = addr
        {{a, 0, 0, 0}, source_prefix, scope_prefix}

      {1, source_prefix} when source_prefix <= 16 ->
        <<a::8, b::8>> = addr
        {{a, b, 0, 0}, source_prefix, scope_prefix}

      {1, source_prefix} when source_prefix <= 24 ->
        <<a::8, b::8, c::8>> = addr
        {{a, b, c, 0}, source_prefix, scope_prefix}

      {1, source_prefix} when source_prefix <= 32 ->
        <<a::8, b::8, c::8, d::8>> = addr
        {{a, b, c, d}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 8 ->
        <<a::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(0), 0, 0, 0, 0, 0, 0, 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 16 ->
        <<a::8, b::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), 0, 0, 0, 0, 0, 0, 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 24 ->
        <<a::8, b::8, c::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(0), 0, 0, 0, 0, 0,
          0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 32 ->
        <<a::8, b::8, c::8, d::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d), 0, 0, 0, 0, 0,
          0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 40 ->
        <<a::8, b::8, c::8, d::8, e::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(0), 0, 0, 0, 0, 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 48 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), 0, 0, 0, 0, 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 56 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(0), 0, 0, 0, 0},
         source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 64 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h), 0, 0, 0, 0},
         source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 72 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8>> =
          addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(0), 0, 0, 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 80 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8, j::8>> =
          addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(j), 0, 0, 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 88 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8, j::8, k::8>> =
          addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(j), Bitwise.<<<(k, 8) |> Bitwise.bor(0), 0, 0},
         source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 96 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8, j::8, k::8, l::8>> =
          addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(j), Bitwise.<<<(k, 8) |> Bitwise.bor(l), 0, 0},
         source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 104 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8, j::8, k::8, l::8, m::8>> =
          addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(j), Bitwise.<<<(k, 8) |> Bitwise.bor(l),
          Bitwise.<<<(m, 8) |> Bitwise.bor(0), 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 112 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8, j::8, k::8, l::8, m::8, n::8>> =
          addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(j), Bitwise.<<<(k, 8) |> Bitwise.bor(l),
          Bitwise.<<<(m, 8) |> Bitwise.bor(n), 0}, source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 120 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8, j::8, k::8, l::8, m::8, n::8,
          o::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(j), Bitwise.<<<(k, 8) |> Bitwise.bor(l),
          Bitwise.<<<(m, 8) |> Bitwise.bor(n), Bitwise.<<<(o, 8) |> Bitwise.bor(0)},
         source_prefix, scope_prefix}

      {2, source_prefix} when source_prefix <= 128 ->
        <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8, i::8, j::8, k::8, l::8, m::8, n::8,
          o::8, p::8>> = addr

        {{Bitwise.<<<(a, 8) |> Bitwise.bor(b), Bitwise.<<<(c, 8) |> Bitwise.bor(d),
          Bitwise.<<<(e, 8) |> Bitwise.bor(f), Bitwise.<<<(g, 8) |> Bitwise.bor(h),
          Bitwise.<<<(i, 8) |> Bitwise.bor(j), Bitwise.<<<(k, 8) |> Bitwise.bor(l),
          Bitwise.<<<(m, 8) |> Bitwise.bor(n), Bitwise.<<<(o, 8) |> Bitwise.bor(p)},
         source_prefix, scope_prefix}
    end
  end

  def parse(10, buffer) do
    case byte_size(buffer) do
      8 ->
        <<client::binary-size(8)>> = buffer
        {client, nil}

      size when size >= 16 and size <= 40 ->
        <<client::binary-size(8), server::binary>> = buffer
        {client, server}

      _ ->
        throw({:edns0_cookie, :size_error})
    end
  end

  def parse(_, buffer) do
    buffer
  end

  def encode(code, data)

  def encode(8, {addr, source_prefix, scope_prefix}) do
    case {tuple_size(addr), source_prefix} do
      {4, source_prefix} when source_prefix <= 8 ->
        <<1::16, source_prefix::8, scope_prefix::8, elem(addr, 0)::8>>

      {4, source_prefix} when source_prefix <= 16 ->
        <<1::16, source_prefix::8, scope_prefix::8, elem(addr, 0)::8, elem(addr, 1)::8>>

      {4, source_prefix} when source_prefix <= 24 ->
        <<1::16, source_prefix::8, scope_prefix::8, elem(addr, 0)::8, elem(addr, 1)::8,
          elem(addr, 2)::8>>

      {4, source_prefix} when source_prefix <= 32 ->
        <<1::16, source_prefix::8, scope_prefix::8, elem(addr, 0)::8, elem(addr, 1)::8,
          elem(addr, 2)::8, elem(addr, 3)::8>>

      {8, source_prefix} when source_prefix <= 8 ->
        a = elem(addr, 0)
        <<2::16, source_prefix::8, scope_prefix::8, Bitwise.>>>(a, 8)::8>>

      {8, source_prefix} when source_prefix <= 16 ->
        a = elem(addr, 0)
        <<2::16, source_prefix::8, scope_prefix::8, a::16>>

      {8, source_prefix} when source_prefix <= 24 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        <<2::16, source_prefix::8, scope_prefix::8, a::16, Bitwise.>>>(b, 8)::8>>

      {8, source_prefix} when source_prefix <= 32 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16>>

      {8, source_prefix} when source_prefix <= 40 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, Bitwise.>>>(c, 8)::8>>

      {8, source_prefix} when source_prefix <= 48 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16>>

      {8, source_prefix} when source_prefix <= 56 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, Bitwise.>>>(d, 8)::8>>

      {8, source_prefix} when source_prefix <= 64 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16>>

      {8, source_prefix} when source_prefix <= 72 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16,
          Bitwise.>>>(e, 8)::8>>

      {8, source_prefix} when source_prefix <= 80 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16, e::16>>

      {8, source_prefix} when source_prefix <= 88 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)
        f = elem(addr, 5)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16, e::16,
          Bitwise.>>>(f, 8)::8>>

      {8, source_prefix} when source_prefix <= 96 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)
        f = elem(addr, 5)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16, e::16, f::16>>

      {8, source_prefix} when source_prefix <= 104 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)
        f = elem(addr, 5)
        g = elem(addr, 6)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16, e::16, f::16,
          Bitwise.>>>(g, 8)::8>>

      {8, source_prefix} when source_prefix <= 112 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)
        f = elem(addr, 5)
        g = elem(addr, 6)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16, e::16, f::16,
          g::16>>

      {8, source_prefix} when source_prefix <= 120 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)
        f = elem(addr, 5)
        g = elem(addr, 6)
        h = elem(addr, 7)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16, e::16, f::16,
          g::16, Bitwise.>>>(h, 8)::8>>

      {8, source_prefix} when source_prefix <= 128 ->
        a = elem(addr, 0)
        b = elem(addr, 1)
        c = elem(addr, 2)
        d = elem(addr, 3)
        e = elem(addr, 4)
        f = elem(addr, 5)
        g = elem(addr, 6)
        h = elem(addr, 7)

        <<2::16, source_prefix::8, scope_prefix::8, a::16, b::16, c::16, d::16, e::16, f::16,
          g::16, h::16>>
    end
  end

  def encode(10, {client, nil}) do
    <<client::binary-size(8)>>
  end

  def encode(10, {client, server}) do
    <<client::binary-size(8), server::binary>>
  end

  def encode(_, data) do
    data
  end

  def to_print({8, {ip, c, s}}) do
    "; ECS: #{:inet.ntoa(ip)}/#{c}/#{s}"
  end

  def to_print({10, {c, s}}) do
    "; COOKIE: #{Base.encode16(c)}#{if(s != nil, do: " #{Base.encode16(s)}")}"
  end

  def to_print({code, data}) do
    "; #{code}: #{data}"
  end
end
