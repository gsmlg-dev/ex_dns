defmodule DNS.Message.Record.Data.SVCB do
  @moduledoc """
  DNS SVCB Record (Type 64)

  The SVCB (Service Binding) record provides a way to publish information about
  alternative endpoints and parameters for a service, primarily for HTTPS.

  RFC 9460 defines the SVCB record format:
  - SvcPriority: 2 octets
  - TargetName: domain name
  - SvcParams: variable length
  """
  alias DNS.Message.Domain
  alias DNS.ResourceRecordType, as: RRType

  @type t :: %__MODULE__{
          type: RRType.t(),
          rdlength: 0..65535,
          raw: bitstring(),
          data: {
            svc_priority :: 0..65535,
            target_name :: Domain.t(),
            svc_params :: binary()
          }
        }

  defstruct raw: nil, type: RRType.new(64), rdlength: nil, data: nil

  @spec new({integer(), Domain.t(), binary()}) :: t()
  def new({svc_priority, target_name, svc_params}) do
    target_name_binary = DNS.to_iodata(target_name)
    
    raw = <<
      svc_priority::16,
      target_name_binary::binary,
      svc_params::binary
    >>
    
    %__MODULE__{
      raw: raw,
      data: {svc_priority, target_name, svc_params},
      rdlength: byte_size(raw)
    }
  end

  @spec from_iodata(bitstring(), bitstring() | nil) :: t()
  def from_iodata(raw, message \\ nil) do
    <<
      svc_priority::16,
      rest::binary
    >> = raw
    
    target_name = Domain.from_iodata(rest, message)
    target_name_size = target_name.size
    svc_params = binary_part(rest, target_name_size, byte_size(rest) - target_name_size)
    
    %__MODULE__{
      raw: raw,
      data: {svc_priority, target_name, svc_params},
      rdlength: byte_size(raw)
    }
  end

  defimpl DNS.Parameter, for: DNS.Message.Record.Data.SVCB do
    @impl true
    def to_iodata(%DNS.Message.Record.Data.SVCB{data: data}) do
      {svc_priority, target_name, svc_params} = data
      
      target_name_binary = DNS.to_iodata(target_name)
      size = 2 + byte_size(target_name_binary) + byte_size(svc_params)
      
      <<
        size::16,
        svc_priority::16,
        target_name_binary::binary,
        svc_params::binary
      >>
    end
  end

  defimpl String.Chars, for: DNS.Message.Record.Data.SVCB do
    def to_string(%DNS.Message.Record.Data.SVCB{data: data}) do
      {svc_priority, target_name, svc_params} = data
      "#{svc_priority} #{target_name} #{svc_params}"
    end
  end
end