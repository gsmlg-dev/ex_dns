defmodule DNS.Zone do
  @moduledoc """
  DNS Zone

  type:
  - Authoritative
  - Stub
  - Forward
  - Recursive
  - Caching
  - Reverse
  """

  alias DNS.Zone.Name
  alias DNS.Zone.RRSet

  @type zone_type :: :authoritative | :stub | :forward | :caching | :reverse

  @type t :: %__MODULE__{
          name: Name.t(),
          type: zone_type(),
          options: list(term()),
          data: list(RRSet.t())
        }

  defstruct name: Name.new("."), type: :authoritative, data: [], options: []

  @spec new(binary() | map(), any()) :: DNS.Zone.t()
  def new(name, type \\ :authoritative, options \\ [])

  def new(name, type, options) when is_binary(name) do
    new(Name.new(name), type, options)
  end

  def new(name, type, options) when is_struct(name, Name) do
    %__MODULE__{
      name: name,
      type: type,
      options: options,
      data: []
    }
  end
end
