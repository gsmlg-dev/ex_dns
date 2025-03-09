defprotocol DNS.Parameter do
  @spec to_binary(term()) :: binary()
  def to_binary(value)
end
