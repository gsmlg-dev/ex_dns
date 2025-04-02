defmodule DNS.Message.Record.Data.A do
  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 4,
          raw: bitstring(),
          data: :inet.ip4_address()
        }

  defstruct raw: nil, type: DNS.ResourceRecordType.new(1), rdlength: 4, data: nil

  def new({a, b, c, d} = ip) do
    raw = <<a::8, b::8, c::8, d::8>>
    %__MODULE__{raw: raw, data: ip}
  end

  def from_iodata(raw, _message \\ nil) do
    <<a::8, b::8, c::8, d::8>> = raw
    %__MODULE__{raw: raw, data: {a, b, c, d}}
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data.A do
    @impl true
    def to_iodata(%DNS.Message.Record.Data.A{data: data}) do
      {a, b, c, d} = data
      <<4::16, a::8, b::8, c::8, d::8>>
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data.A do
    def to_string(%DNS.Message.Record.Data.A{data: data, raw: raw}) do
      case data |> :inet.ntoa() do
        ip when is_list(ip) -> "#{ip}"
        _ -> raw |> inspect()
      end
    end
  end
end
