defmodule DNS.Message.DomainTest do
  use ExUnit.Case

  test "DNS Message Domain new" do
    d = DNS.Message.Domain.new("www.example.com")
    assert %DNS.Message.Domain{} = d
  end

  test "DNS Message Domain to_string/1" do
    d = DNS.Message.Domain.new("www.example.com")
    assert "www.example.com." = "#{d}"
  end
end
