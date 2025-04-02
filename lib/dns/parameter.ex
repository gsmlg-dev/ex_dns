defprotocol DNS.Parameter do
  @spec to_iodata(term()) :: binary()
  def to_iodata(value)
end

defimpl DNS.Parameter, for: List do
  @impl true
  def to_iodata(list) do
    list |> Enum.map(&DNS.to_iodata/1) |> Enum.join(<<>>)
  end
end
