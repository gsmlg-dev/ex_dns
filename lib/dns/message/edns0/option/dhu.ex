defmodule DNS.Message.EDNS0.Option.DHU do
  @moduledoc """
  EDNS0.Option.DHU [RFC6975](https://datatracker.ietf.org/doc/html/rfc6975)

  DS Hash Understood (DHU) option is used to indicate which DS hash
  algorithms a resolver understands.

  Option Format:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        OPTION-CODE = 6        |       OPTION-LENGTH           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    /                      ALGORITHM LIST                           /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  - ALGORITHM LIST: Variable length, list of DS hash algorithm codes
  """
  alias DNS.Message.EDNS0.OptionCode

  @type t :: %__MODULE__{
          code: OptionCode.t(),
          length: 0..65535,
          data: [integer()]
        }

  defstruct code: OptionCode.new(6), length: nil, data: []

  @spec new([integer()]) :: t()
  def new(algorithm_list) do
    len = length(algorithm_list)
    %__MODULE__{length: len, data: algorithm_list}
  end

  def from_iodata(<<6::16, length::16, algorithm_list::binary-size(length)>>) do
    algorithms = :binary.bin_to_list(algorithm_list)
    %__MODULE__{length: length, data: algorithms}
  end

  defimpl DNS.Parameter, for: DNS.Message.EDNS0.Option.DHU do
    @impl true
    def to_iodata(%DNS.Message.EDNS0.Option.DHU{data: algorithm_list}) do
      algorithm_binary = :binary.list_to_bin(algorithm_list)
      <<6::16, byte_size(algorithm_binary)::16, algorithm_binary::binary>>
    end
  end

  defimpl String.Chars, for: DNS.Message.EDNS0.Option.DHU do
    def to_string(%DNS.Message.EDNS0.Option.DHU{code: code, data: algorithm_list}) do
      algorithms = Enum.join(algorithm_list, ",")
      "#{code}: [#{algorithms}]"
    end
  end
end