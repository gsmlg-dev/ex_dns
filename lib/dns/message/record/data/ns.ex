defmodule DNS.Message.Record.Data.NS do
  alias DNS.Message.Domain

  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 1..65535,
          raw: bitstring(),
          data: DNS.Message.Domain.t()
        }

  defstruct raw: nil, type: DNS.ResourceRecordType.new(2), rdlength: nil, data: nil

  def new(str) do
    domain = Domain.new(str)
    raw = DNS.to_binary(domain)
    %__MODULE__{raw: raw, data: domain, rdlength: domain.size}
  end

  def from_binary(raw, message \\ nil) do
    data = Domain.from_binary(raw, message)
    %__MODULE__{raw: raw, data: data}
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data.NS do
    @impl true
    def to_binary(%DNS.Message.Record.Data.NS{} = data) do
      data = DNS.to_binary(data.data)
      <<data.rdlength::16, data::binary>>
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data.NS do
    def to_string(record) do
      "#{record.data}"
    end
  end
end
