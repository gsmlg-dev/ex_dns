defmodule DNS.Message.OpCode do
  @moduledoc """
  # DNS OpCode

      OpCode 	Name 	Reference
      0	Query	[RFC1035]
      1	IQuery (Inverse Query, OBSOLETE)	[RFC3425]
      2	Status	[RFC1035]
      3	Unassigned
      4	Notify	[RFC1996]
      5	Update	[RFC2136]
      6	DNS Stateful Operations (DSO)	[RFC8490]
      7-15	Unassigned

  # Reference
  - [iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)
  - [DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
  - [Domain Name System (DNS) IANA Considerations](https://tools.ietf.org/html/rfc6895)
  """

  @type t :: %__MODULE__{value: <<_::4>>}

  defstruct value: 0

  alias DNS.Message.OpCode

  def new(value) when is_integer(value) do
    %OpCode{value: <<value::4>>}
  end

  def new(value) do
    %OpCode{value: value}
  end

  @doc """
  # query is a standard query
  [RFC1035](https://tools.ietf.org/html/rfc1035)
  """
  @spec query() :: 0
  def query(), do: 0

  @doc """
  # iquery is a non-standard extension to DNS that is used by the
  [DNS Zone Transfer Protocol](https://tools.ietf.org/html/rfc1996)
  """
  @spec iquery() :: 1
  def iquery(), do: 1

  @doc """
  # status is a non-standard extension to DNS that is used by the
  [DNS Zone Transfer Protocol](https://tools.ietf.org/html/rfc1996)
  """
  @spec status() :: 2
  def status(), do: 2

  @doc """
  # notify is a non-standard extension to DNS that is used by the
  [DNS Zone Transfer Protocol](https://tools.ietf.org/html/rfc1996)
  """
  @spec notify() :: 4
  def notify(), do: 4

  @doc """
  # update is a non-standard extension to DNS that is used by the
  [Dynamic DNS Update](https://tools.ietf.org/html/rfc2136)
  """
  @spec update() :: 5
  def update(), do: 5

  @doc """
  # dso is a non-standard extension to DNS that is used by the
  [DNS Stateful Operations (DSO)](https://tools.ietf.org/html/draft-sekar-dns-ultradns-00)
  """
  @spec dso() :: 6
  def dso(), do: 6

  defimpl String.Chars, for: DNS.Message.OpCode do
    @impl true
    @spec to_string(DNS.Message.OpCode.t()) :: binary()
    def to_string(op_code) do
      <<value::4>> = op_code.value

      case value do
        0 -> "Query"
        1 -> "IQuery"
        2 -> "Status"
        4 -> "Notify"
        5 -> "Update"
        6 -> "DSO"
        value -> "Unassigned(#{value})"
      end
    end
  end
end
