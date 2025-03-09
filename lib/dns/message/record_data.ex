defprotocol DNS.Message.RecrodData do
  @spec to_binary(term()) :: binary()
  def to_binary(value)
end
