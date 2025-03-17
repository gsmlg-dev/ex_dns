defmodule DNS.Message.Record.Data.MX do
  alias DNS.Message.Domain

  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 1..65535,
          raw: bitstring(),
          data: {0..65535, DNS.Message.Domain.t()}
        }

  defstruct raw: nil, type: DNS.ResourceRecordType.new(15), rdlength: nil, data: nil

  def new({weight, str}) do
    domain = Domain.new(str)
    raw = DNS.to_binary(domain)

    %__MODULE__{
      raw: <<weight::16, raw::binary>>,
      data: {weight, domain},
      rdlength: domain.size + 2
    }
  end

  def from_binary(<<weight::16, data::binary>>, message \\ nil) do
    domain = Domain.from_binary(data, message)
    %__MODULE__{raw: <<weight::16, DNS.to_binary(domain)::binary>>, data: {weight, domain}, rdlength: byte_size(data) + 2}
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data.MX do
    @impl true
    def to_binary(%DNS.Message.Record.Data.MX{} = data) do
      data = DNS.to_binary(data.data)
      <<data.rdlength::16, data::binary>>
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data.MX do
    def to_string(%DNS.Message.Record.Data.MX{data: {weight, domain}}) do
      "#{weight} #{domain}"
    end
  end
end
