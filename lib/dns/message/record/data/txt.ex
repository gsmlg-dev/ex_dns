defmodule DNS.Message.Record.Data.TXT do
  alias DNS.Message.Domain

  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 1..65535,
          raw: bitstring(),
          data: [binary()]
        }

  defstruct raw: nil, type: DNS.ResourceRecordType.new(16), rdlength: nil, data: nil

  def new(text) do
    raw = Enum.reduce(text, <<>>, fn x, acc -> <<acc::binary, byte_size(x)::8, x::binary>> end)
    %__MODULE__{raw: raw, data: text, rdlength: byte_size(raw)}
  end

  def from_binary(raw, message \\ nil) do
    data = Domain.from_binary(raw, message)
    %__MODULE__{raw: raw, data: data, rdlength: byte_size(raw)}
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data.TXT do
    @impl true
    def to_binary(%DNS.Message.Record.Data.TXT{raw: raw, rdlength: rdlength}) do
      <<rdlength::16, raw::binary>>
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data.TXT do
    def to_string(%DNS.Message.Record.Data.TXT{data: data}) do
      "#{data |> Enum.map(&inspect/1) |> Enum.join(" ")}"
    end
  end
end
