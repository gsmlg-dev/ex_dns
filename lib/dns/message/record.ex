defmodule DNS.Message.Record do
  @moduledoc """
    Record is a struct that represents a DNS resource record.

    All RRs have the same top level format shown below:

    ```txt
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                      NAME                     /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     CLASS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TTL                      |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   RDLENGTH                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        /                     RDATA                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ```

    where:

    NAME            an owner name, i.e., the name of the node to which this
                    resource record pertains.

    TYPE            two octets containing one of the RR TYPE codes.

    CLASS           two octets containing one of the RR CLASS codes.

    TTL             a 32 bit signed integer that specifies the time interval
                    that the resource record may be cached before the source
                    of the information should again be consulted.  Zero
                    values are interpreted to mean that the RR can only be
                    used for the transaction in progress, and should not be
                    cached.  For example, SOA records are always distributed
                    with a zero TTL to prohibit caching.  Zero values can
                    also be used for extremely volatile data.

    RDLENGTH        an unsigned 16 bit integer that specifies the length in
                    octets of the RDATA field.

    RDATA           a variable length string of octets that describes the
                    resource.  The format of this information varies
                    according to the TYPE and CLASS of the resource record.
  """
  alias DNS.Class
  alias DNS.Message.Domain
  alias DNS.Message.Record
  alias DNS.ResourceRecordType, as: RRType
  alias DNS.Message.Recrod.Data, as: RData

  @type t :: %__MODULE__{
          name: Domain.t(),
          type: RRType.t(),
          class: Class.t(),
          ttl: 0..4_294_967_295,
          data: RData.t()
        }

  defstruct name: Domain.new("."),
            type: RRType.new(1),
            class: Class.new(1),
            ttl: 0,
            data: RData.new(RRType.new(1), 4, <<0, 0, 0, 0>>)

  def new(name, type, class, ttl, data) do
    %__MODULE__{name: name, type: type, class: class, ttl: ttl, data: data}
  end

  def from_binary(buffer, message \\ <<>>) do
    with domain <- Domain.from_binary(buffer, message),
         <<_::binary-size(domain.size), type::16, class::16, ttl::32, rdlength::16, rest::binary>> <-
           buffer,
         <<rdata::binary-size(rdlength), _>> <- rest do
      rtype = RRType.new(<<type::16>>)

      %Record{
        name: domain,
        type: rtype,
        class: Class.new(class),
        ttl: ttl,
        data: RData.new(rtype, rdlength, rdata, message)
      }
    else
      error ->
        throw({:format_error, error})
    end
  end

  def list_from_message(count, message, offset) do
    {record_list, end_offset} =
      Enum.reduce(1..count, {[], offset}, fn _, {records, offset} ->
        <<_::binary-size(offset), buffer::binary>> = message
        record = from_binary(buffer, message)
        {[record | records], offset + record.name.size + 2 + 2 + 4 + 2 + record.data.rdlength}
      end)

    {record_list, end_offset}
  end

  defimpl DNS.Parameter, for: DNS.Message.Record do
    @impl true
    def to_binary(%DNS.Message.Record{} = record) do
      DNS.to_binary(record.name) <>
        DNS.to_binary(record.type) <>
        DNS.to_binary(record.class) <>
        <<record.ttl::32>> <> DNS.to_binary(record.data)
    end
  end

  defimpl String.Chars, for: DNS.Message.Record do
    def to_string(record) do
      "#{record.name} #{record.type} #{record.class} #{record.ttl} #{record.data}"
    end
  end
end
