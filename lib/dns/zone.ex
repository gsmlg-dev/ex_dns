defmodule Dns.Zone do
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

  @type zone_type :: :authoritative | :stub | :forward | :recursive | :caching | :reverse

  @type t :: %__MODULE__{
          name: String.t(),
          type: zone_type(),
          default_ttl: integer(),
          rr_sets: list(Dns.RRSet.t())
        }

  defstruct name: nil, type: nil, default_ttl: 3600, rr_sets: []
end
