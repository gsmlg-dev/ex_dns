defmodule DNS do
  @moduledoc """
  Documentation for `DNS`.

  All DNS related modules are namespaced under this module.
  DNS resources are implemented with protocols `String.Chars` and `DNS.Parameter`.

  - `to_string/1` is implemented for all DNS resources to show human readable data information.

  - `to_iodata/1` is implemented for all DNS resources in dns protocol data.

  """

  def to_iodata(value) do
    DNS.Parameter.to_iodata(value)
  end
end
