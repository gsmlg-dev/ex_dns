defmodule DNS.Message.Recrod.Data do
  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 0..65535,
          data: bitstring(),
          message: nil | bitstring(),
          size: 2..65537
        }

  defstruct data: <<>>, type: nil, rdlength: nil, message: nil, size: nil

  def new(type, rdlength, data, message \\ nil) do
    %__MODULE__{type: type, rdlength: rdlength, data: data, message: message}
  end

  defimpl DNS.Parameter, for: DNS.Message.Recrod.Data do
    @impl true
    def to_binary(%DNS.Message.Recrod.Data{} = data) do
      <<data.rdlength::16>> <> data.data
    end
  end

  defimpl String.Chars, for: DNS.Message.Recrod.Data do
    def to_string(record) do
      record.data |> inspect()
    end
  end
end
