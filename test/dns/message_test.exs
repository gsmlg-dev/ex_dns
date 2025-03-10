defmodule DNS.MessageTest do
  use ExUnit.Case

  test "DNS message from_binary/1" do
    raw =
      <<118, 11, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 3, 119, 119, 119, 6, 103, 111, 111, 103, 108, 101,
        3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 210,
        213, 222, 136, 249, 150, 28, 88>>

    msg = DNS.Message.from_binary(raw)

    [qd] = msg.qdlist

    assert to_string(qd.name) == "www.google.com."
    assert to_string(qd.type) == "A"
    assert to_string(qd.class) == "IN"

    # IO.inspect(msg, limit: :infinity)
    # IO.puts("#{to_string(msg)}")
  end
end
