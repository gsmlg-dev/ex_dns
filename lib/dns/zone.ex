defmodule DNS.Zone do
  @moduledoc """
  DNS Zone

  type:
  - Authoritative
  - Stub
  - Forward
  - Cache
  """

  alias DNS.Zone.Name

  @type zone_type :: :authoritative | :stub | :forward | :cache

  @type t :: %__MODULE__{
          name: Name.t(),
          type: zone_type(),
          options: list(term())
        }

  defstruct name: Name.new("."), type: :authoritative, options: []

  @spec new(binary() | map(), any()) :: t()
  def new(name, type \\ :authoritative, options \\ [])

  def new(name, type, options) when is_binary(name) do
    new(Name.new(name), type, options)
  end

  def new(name, type, options) when is_struct(name, Name) do
    %__MODULE__{
      name: name,
      type: type,
      options: options
    }
  end

  @spec hostname(Name.t(), DNS.Message.Domain.t()) :: Name.t()
  def hostname(%Name{value: "."} = _zone_name, %DNS.Message.Domain{} = domain) do
    Name.from_domain(domain)
  end

  def hostname(%Name{} = zone_name, %DNS.Message.Domain{} = domain) do
    domain_name = Name.from_domain(domain)

    if Name.child?(zone_name, domain_name) do
      domain_name.value
      |> String.trim_trailing(zone_name.value)
      |> Name.new()
    else
      false
    end
  end
end
