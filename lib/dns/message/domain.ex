defmodule DNS.Message.Domain do
  @moduledoc """
  # DNS Domain

  """
  alias DNS.Message.Domain

  @type t :: %__MODULE__{
          size: non_neg_integer(),
          value: binary()
        }

  defstruct value: ".", size: 1

  @spec new(binary(), non_neg_integer()) :: Domain.t()
  def new(value, length) do
    %Domain{
      value: value,
      size: length
    }
  end

  @spec new(binary()) :: Domain.t()
  def new(value) do
    %Domain{
      value: value,
      size: domain_byte_size(value)
    }
  end

  @doc """
  Get name from bitstring, uncompress name in message
  """
  def from_binary(bitstring, dns_message \\ <<>>) do
    {len, domain} = parse_domain_from_message(bitstring, dns_message)
    new(domain, len)
  end

  defp parse_domain_from_message(<<size::8, _::binary>>, _) when size == 0, do: {1, "."}

  defp parse_domain_from_message(<<size::8, pos::8, rest::binary>>, message) when size == 0xC0 do
    case message do
      <<_::binary-size(pos), next::8, next_buffer::binary>> when next > 0 and next < 64 ->
        {_, name} = parse_domain_from_message(<<next::8, next_buffer::binary>>, message)
        {2, name}

      <<_::binary-size(pos), next::8, next_pos::8, next_buffer::binary>>
      when next == 0xC0 and pos != next_pos ->
        {_, name} =
          parse_domain_from_message(<<next::8, next_pos::8, next_buffer::binary>>, message)

        {2, name}

      _ ->
        throw({FormatError, size, pos, rest, message})
    end
  end

  defp parse_domain_from_message(<<size::8, rest::binary>>, message)
       when size > 0 and size < 64 do
    case rest do
      <<part::binary-size(size), next::8, _::binary>> when next == 0 ->
        {1 + size + 1, part <> "."}

      <<part::binary-size(size), next::8, next_pos::8, last_buffer::binary>> when next == 0xC0 ->
        {_, compressed_name} =
          parse_domain_from_message(<<next::8, next_pos::8, last_buffer::binary>>, message)

        {1 + size + 2, part <> "." <> compressed_name}

      <<part::binary-size(size), next::8, next_buffer::binary>> when next > 0 and next < 64 ->
        {last_size, last_name} = parse_domain_from_message(<<next, next_buffer::binary>>, message)
        {1 + size + last_size, part <> "." <> last_name}

      <<_::binary-size(size), _::binary>> ->
        throw({FormatError, size, rest, message})
    end
  end

  defp parse_domain_from_message(buffer, message) do
    throw({FormatError, buffer, message})
  end

  defp domain_byte_size(domain) do
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
    |> byte_size()
  end

  defimpl DNS.Parameter, for: Domain do
    @impl true
    def to_binary(%Domain{value: {_, domain}}) do
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

  defimpl String.Chars, for: Domain do
    @impl true
    @spec to_string(Domain.t()) :: binary()
    def to_string(domain) do
      "#{domain.value |> elem(1)}"
    end
  end
end
