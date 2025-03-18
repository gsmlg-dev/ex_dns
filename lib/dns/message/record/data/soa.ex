defmodule DNS.Message.Record.Data.SOA do
  alias DNS.Message.Domain

  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 4,
          raw: bitstring(),
          data:
            {Domain.t(), Domain.t(), 0..2_147_483_647, 0..2_147_483_647, 0..2_147_483_647,
             0..2_147_483_647, 0..2_147_483_647}
        }

  defstruct raw: nil, type: DNS.ResourceRecordType.new(6), rdlength: nil, data: nil

  def new({ns, rp, serial, refresh, retry, expire, negative}) do
    raw =
      <<DNS.to_binary(ns)::binary, DNS.to_binary(rp)::binary, serial::32, refresh::32, retry::32,
        expire::32, negative::32>>

    %__MODULE__{
      raw: raw,
      data: {ns, rp, serial, refresh, retry, expire, negative},
      rdlength: byte_size(raw)
    }
  end

  def from_binary(raw, message \\ nil) do
    ns = Domain.from_binary(raw, message)

    rp =
      Domain.from_binary(binary_part(raw, ns.size, byte_size(raw) - ns.size), message)

    <<serial::32, refresh::32, retry::32, expire::32, negative::32>> =
      binary_part(raw, ns.size + rp.size, byte_size(raw) - ns.size - rp.size)

    %__MODULE__{
      raw: raw,
      data: {ns, rp, serial, refresh, retry, expire, negative},
      rdlength: byte_size(raw)
    }
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data.SOA do
    @impl true
    def to_binary(%DNS.Message.Record.Data.SOA{data: data}) do
      {ns, rp, serial, refresh, retry, expire, negative} = data

      <<DNS.to_binary(ns)::binary, DNS.to_binary(rp)::binary, serial::32, refresh::32, retry::32,
        expire::32, negative::32>>
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data.SOA do
    def to_string(%DNS.Message.Record.Data.SOA{data: data}) do
      {ns, rp, serial, refresh, retry, expire, negative} = data
      "#{ns} #{rp} #{serial} #{refresh} #{retry} #{expire} #{negative}"
    end
  end
end
