defprotocol DNS.Message.RecordData do
  @spec to_binary(term()) :: binary()
  def to_binary(value)
end
