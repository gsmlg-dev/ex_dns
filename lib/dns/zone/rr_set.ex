defmodule DNS.Zone.RRSet do
  @moduledoc """
  DNS Resource Record Set
  """

  alias DNS.ResourceRecordType, as: RRType

  @type t :: %__MODULE__{
          name: String.t(),
          type: RRType.t(),
          ttl: 0..4_294_967_295,
          data: list(term()),
          glue: list(term())
        }

  defstruct zone: nil, name: nil, type: nil, ttl: 3600, data: [], glue: []

  @spec new(any(), any(), any()) :: DNS.Zone.RRSet.t()
  def new(zone, name, type, data \\ [], glue \\ []) do
    %__MODULE__{
      zone: zone,
      name: name,
      type: type,
      data: data,
      glue: glue
    }
  end
end
