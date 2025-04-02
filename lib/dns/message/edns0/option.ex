defmodule DNS.Message.EDNS0.Option do
  @moduledoc """
  DNS EDNS0
  """

  alias DNS.Message.EDNS0.Option
  alias DNS.Message.EDNS0.OptionCode

  @type t :: %__MODULE__{
          code: OptionCode.t(),
          length: 0..65535,
          data: term()
        }

  defstruct code: nil, length: nil, data: nil

  def new(code, data) do
    case code do
      8 -> Option.ECS.new(data)
      10 -> Option.Cookie.new(data)
      _ -> %__MODULE__{code: OptionCode.new(code), data: data}
    end
  end

  def from_iodata(<<code::16, length::16, payload::binary-size(length)>> = raw) do
    case code do
      8 -> Option.ECS.from_iodata(raw)
      10 -> Option.Cookie.from_iodata(raw)
      _ -> %__MODULE__{code: OptionCode.new(code), data: payload}
    end
  end

  defimpl DNS.Parameter, for: DNS.Message.EDNS0.Option do
    @impl true
    def to_iodata(%DNS.Message.EDNS0.Option{
          data: data
        }) do
      <<10::16, byte_size(data)::16, data::binary>>
    end
  end

  defimpl String.Chars, for: DNS.Message.EDNS0.Option do
    def to_string(%DNS.Message.EDNS0.Option{
          code: code,
          data: data
        }) do
      "#{code}: #{Base.encode16(data)}"
    end
  end
end
