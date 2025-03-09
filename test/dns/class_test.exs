defmodule DNS.ClassTest do
  use ExUnit.Case

  test "DNS class new" do
    c1 = DNS.Class.new(1)
    assert c1 == %DNS.Class{value: <<1::16>>}
  end

  test "DNS class to_string/1" do
    c1 = DNS.Class.new(1)
    assert "#{c1}" == "IN"
  end
end
