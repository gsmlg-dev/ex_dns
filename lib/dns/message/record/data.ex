defmodule DNS.Message.Record.Data do
  alias DNS.ResourceRecordType, as: RRType
  alias DNS.Message.Record.Data, as: RData

  @type t :: %__MODULE__{
          type: DNS.ResourceRecordType.t(),
          rdlength: 0..65535,
          raw: bitstring()
        }

  defstruct raw: <<>>, type: nil, rdlength: nil

  def new(%RRType{value: <<type::16>>} = rtype, rdata) do
    case type do
      1 -> RData.A.new(rdata)
      2 -> RData.NS.new(rdata)
      5 -> RData.CNAME.new(rdata)
      6 -> RData.SOA.new(rdata)
      12 -> RData.PTR.new(rdata)
      15 -> RData.MX.new(rdata)
      16 -> RData.TXT.new(rdata)
      28 -> RData.AAAA.new(rdata)
      33 -> RData.SRV.new(rdata)
      # 41 -> RData.OPT.new(rdata)
      # 43 -> RData.DS.new(rdata)
      # 46 -> RData.RRSIG.new(rdata)
      47 -> RData.NSEC.new(rdata)
      # 48 -> RData.DNSKEY.new(rdata)
      # 49 -> RData.DHCID.new(rdata)
      # 50 -> RData.NSEC3.new(rdata)
      # 51 -> RData.NSEC3PARAM.new(rdata)
      # 52 -> RData.TLSA.new(rdata)
      # 59 -> RData.CDS.new(rdata)
      # 60 -> RData.CDNSKEY.new(rdata)
      # 61 -> RData.OPENPGPKEY.new(rdata)
      # 62 -> RData.CSYNC.new(rdata)
      # 63 -> RData.ZONEMD.new(rdata)
      # 64 -> RData.SVCB.new(rdata)
      # 65 -> RData.HTTPS.new(rdata)
      # 99 -> RData.SPF.new(rdata)
      # 249 -> RData.URI.new(rdata)
      # 250 -> RData.CAA.new(rdata)
      # 251 -> RData.AVC.new(rdata)
      # 252 -> RData.TA.new(rdata)
      # 253 -> RData.DLV.new(rdata)
      _ -> %__MODULE__{type: rtype, rdlength: byte_size(rdata), raw: rdata}
    end
  end

  def from_iodata(type, raw, message \\ <<>>) do
    case type do
      1 -> RData.A.from_iodata(raw, message)
      2 -> RData.NS.from_iodata(raw, message)
      5 -> RData.CNAME.from_iodata(raw, message)
      6 -> RData.SOA.from_iodata(raw, message)
      12 -> RData.PTR.from_iodata(raw, message)
      15 -> RData.MX.from_iodata(raw, message)
      16 -> RData.TXT.from_iodata(raw, message)
      28 -> RData.AAAA.from_iodata(raw, message)
      33 -> RData.SRV.from_iodata(raw, message)
      # 41 -> RData.OPT.from_iodata(raw, message)
      # 43 -> RData.DS.from_iodata(raw, message)
      # 46 -> RData.RRSIG.from_iodata(raw, message)
      47 -> RData.NSEC.from_iodata(raw, message)
      # 48 -> RData.DNSKEY.from_iodata(raw, message)
      # 49 -> RData.DHCID.from_iodata(raw, message)
      # 50 -> RData.NSEC3.from_iodata(raw, message)
      # 51 -> RData.NSEC3PARAM.from_iodata(raw, message)
      # 52 -> RData.TLSA.from_iodata(raw, message)
      # 59 -> RData.CDS.from_iodata(raw, message)
      # 60 -> RData.CDNSKEY.from_iodata(raw, message)
      # 61 -> RData.OPENPGPKEY.from_iodata(raw, message)
      # 62 -> RData.CSYNC.from_iodata(raw, message)
      # 63 -> RData.ZONEMD.from_iodata(raw, message)
      # 64 -> RData.SVCB.from_iodata(raw, message)
      # 65 -> RData.HTTPS.from_iodata(raw, message)
      # 99 -> RData.SPF.from_iodata(raw, message)
      # 249 -> RData.URI.from_iodata(raw, message)
      # 250 -> RData.CAA.from_iodata(raw, message)
      # 251 -> RData.AVC.from_iodata(raw, message)
      # 252 -> RData.TA.from_iodata(raw, message)
      # 253 -> RData.DLV.from_iodata(raw, message)
      _ -> %__MODULE__{type: DNS.ResourceRecordType.new(type), rdlength: byte_size(raw), raw: raw}
    end
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data do
    @impl true
    def to_iodata(%DNS.Message.Record.Data{} = data) do
      <<data.rdlength::16>> <> data.raw
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data do
    def to_string(record) do
      record.raw |> inspect()
    end
  end
end
