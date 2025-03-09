defmodule DNS do
  @moduledoc """
  Documentation for `DNS`.
  """

  def to_binary(value) do
    DNS.Parameter.to_binary(value)
  end
end
