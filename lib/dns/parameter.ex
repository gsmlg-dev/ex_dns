defprotocol DNS.Parameter do
  @spec to_binary(term()) :: binary()
  def to_binary(value)
end

defimpl DNS.Parameter, for: List do
  @impl true
  def to_binary(list) do
    list |> Enum.map(&DNS.to_binary/1) |> Enum.join(<<>>)
  end
end
