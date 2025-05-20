defmodule DNS.Zone.Name do
  @moduledoc """
  # DNS Zone Name

  """
  alias DNS.Zone.Name

  @type t :: %__MODULE__{
          value: binary(),
          data: bitstring()
        }

  defstruct value: ".", data: <<0>>

  @spec new(binary()) :: Name.t()
  def new(value) do
    value = value |> String.trim(".")

    data =
      case value |> String.split(".") |> Enum.filter(&(&1 != "")) do
        [] ->
          <<0>>

        list ->
          list
          |> Enum.reduce(<<>>, fn part, acc ->
            part_length = byte_size(part)
            <<part_length::8, part::binary-size(part_length), acc::binary>>
          end)
      end

    %Name{
      value: value,
      data: data
    }
  end

  @doc """
  Check if the name1 is a child of name2.
  """
  def child?(%Name{data: d1}, _name2) when d1 == <<0>>, do: true

  def child?(%Name{data: d1} = name1, %Name{data: d2} = name2) when name1 != name2 do
    String.starts_with?(d2, d1)
  end

  def child?(_, _), do: false

  defimpl DNS.Parameter, for: Name do
    @impl true
    def to_iodata(%Name{value: domain}) do
      case String.split(domain, ".") |> Enum.filter(&(&1 != "")) do
        [] ->
          <<0>>

        list ->
          list
          |> Enum.reverse()
          |> Enum.reduce(<<0>>, fn part, acc ->
            part_length = byte_size(part)
            <<part_length::8, part::binary-size(part_length), acc::binary>>
          end)
      end
    end
  end

  defimpl String.Chars, for: Name do
    @impl true
    @spec to_string(Name.t()) :: binary()
    def to_string(domain) do
      domain.value
    end
  end

  defimpl Inspect, for: Name do
    import Inspect.Algebra

    @impl true
    def inspect(domain, _opts) do
      concat(["#DNS.Zone.Name<", domain.value, ">"])
    end
  end
end
