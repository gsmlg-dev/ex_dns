defmodule DNS.Message.Record.Data do
  alias DNS.ResourceRecordType, as: RRType
  alias DNS.Message.Record.Data.Registry

  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 0..65535,
          raw: bitstring()
        }

  defstruct raw: <<>>, type: nil, rdlength: nil

  def new(%RRType{value: <<type::16>>} = rtype, rdata) do
    case Registry.lookup(type) do
      {:ok, module} ->
        module.new(rdata)
      {:error, :not_found} ->
        # Fallback to generic data storage for unknown types
        %__MODULE__{type: rtype, rdlength: byte_size(rdata), raw: rdata}
    end
  end

  def from_iodata(type, raw, message \\ <<>>) do
    case Registry.lookup(type) do
      {:ok, module} ->
        module.from_iodata(raw, message)
      {:error, :not_found} ->
        # Fallback to generic data storage for unknown types
        %__MODULE__{type: DNS.ResourceRecordType.new(type), rdlength: byte_size(raw), raw: raw}
    end
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data do
    @impl true
    def to_iodata(%DNS.Message.Record.Data{} = data) do
      <<data.rdlength::16>> <> data.raw
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data do
    def to_string(record) do
      record.raw |> inspect()
    end
  end
end
