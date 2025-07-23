defmodule DNS.Zone do
  @moduledoc """
  DNS Zone management and operations.

  This module provides the core DNS zone functionality including zone creation,
  management, validation, zone file parsing, and zone transfers.

  ## Zone Types

  The following zone types are supported:
  - `:authoritative` - Primary authoritative zone with full record management
  - `:stub` - Stub zone containing only NS records for delegation
  - `:forward` - Forward zone redirecting queries to specified servers
  - `:cache` - Cache zone for temporary DNS response caching

  ## Creating Zones

  ### Basic Zone Creation
  ```elixir
  # Create a basic authoritative zone
  zone = DNS.Zone.new("example.com")

  # Create a zone with specific type
  zone = DNS.Zone.new("example.com", :authoritative)

  # Create a zone with options
  zone = DNS.Zone.new("example.com", :authoritative, soa_records: [soa_record])
  ```

  ### Interactive Zone Creation
  ```elixir
  # Create zone with interactive prompts
  {:ok, zone} = DNS.Zone.Editor.create_zone_interactive("example.com")

  # Create zone with initial records
  {:ok, zone} = DNS.Zone.Editor.create_zone_interactive("example.com",
    type: :authoritative,
    soa: [
      mname: "ns1.example.com",
      rname: "admin.example.com",
      serial: 2024010101,
      refresh: 3600,
      retry: 1800,
      expire: 604800,
      minimum: 300
    ],
    ns: ["ns1.example.com", "ns2.example.com"],
    a: ["192.168.1.1"]
  )
  ```

  ## Managing Zone Records

  ### Adding Records
  ```elixir
  # Add an A record
  {:ok, zone} = DNS.Zone.Editor.add_record("example.com", :a,
    name: "www.example.com",
    ip: {192, 168, 1, 100},
    ttl: 300
  )

  # Add an MX record
  {:ok, zone} = DNS.Zone.Editor.add_record("example.com", :mx,
    name: "example.com",
    preference: 10,
    exchange: "mail.example.com"
  )

  # Add a CNAME record
  {:ok, zone} = DNS.Zone.Editor.add_record("example.com", :cname,
    name: "ftp.example.com",
    target: "www.example.com"
  )
  ```

  ### Listing and Searching Records
  ```elixir
  # List all records in a zone
  {:ok, records} = DNS.Zone.Editor.list_records("example.com")

  # Search for specific records
  {:ok, a_records} = DNS.Zone.Editor.search_records("example.com", type: :a)
  {:ok, www_records} = DNS.Zone.Editor.search_records("example.com", name: "www.example.com")
  ```

  ### Updating and Removing Records
  ```elixir
  # Update a record
  {:ok, zone} = DNS.Zone.Editor.update_record(
    "example.com", :a,
    [name: "www.example.com"],
    [ttl: 600]
  )

  # Remove records
  {:ok, zone} = DNS.Zone.Editor.remove_record("example.com", :a, name: "old.example.com")
  ```

  ## Zone Validation

  ### Basic Validation
  ```elixir
  # Validate a zone
  case DNS.Zone.Validator.validate_zone(zone) do
    {:ok, result} ->
      IO.puts("Zone is valid: \#{result.zone_name}")
    {:error, result} ->
      IO.puts("Zone has errors: \#{inspect(result.errors)}")
  end
  ```

  ### Comprehensive Diagnostics
  ```elixir
  # Generate zone diagnostics
  diagnostics = DNS.Zone.Validator.generate_diagnostics(zone)
  IO.inspect(diagnostics.statistics)
  IO.inspect(diagnostics.security_assessment)
  IO.inspect(diagnostics.recommendations)
  ```

  ## Zone File Operations

  ### Parsing Zone Files
  ```elixir
  # Load zone from BIND format file
  {:ok, zone} = DNS.Zone.Loader.load_zone_from_file("example.com.zone")

  # Load zone from string
  zone_content = \"\"\"
  $TTL 3600
  $ORIGIN example.com.
  @ IN SOA ns1.example.com. admin.example.com. (
      2024010101 ; serial
      3600       ; refresh
      1800       ; retry
      604800     ; expire
      300        ; minimum
  )
  @ IN NS ns1.example.com.
  @ IN NS ns2.example.com.
  www IN A 192.168.1.100
  mail IN A 192.168.1.200
  \"\"\"
  {:ok, zone} = DNS.Zone.Loader.load_zone_from_string(zone_content)
  ```

  ### Exporting Zone Files
  ```elixir
  # Export to BIND format
  {:ok, bind_content} = DNS.Zone.Editor.export_zone("example.com", format: :bind)
  File.write!("example.com.zone", bind_content)

  # Export to JSON
  {:ok, json_content} = DNS.Zone.Editor.export_zone("example.com", format: :json)
  File.write!("example.com.json", json_content)

  # Export to YAML
  {:ok, yaml_content} = DNS.Zone.Editor.export_zone("example.com", format: :yaml)
  File.write!("example.com.yaml", yaml_content)
  ```

  ## Zone Transfers

  ### Full Zone Transfer (AXFR)
  ```elixir
  # Perform AXFR transfer
  case DNS.Zone.Transfer.axfr("example.com") do
    {:ok, records} ->
      IO.puts("Received \#{length(records)} records via AXFR")
    {:error, reason} ->
      IO.puts("AXFR failed: \#{reason}")
  end
  ```

  ### Incremental Zone Transfer (IXFR)
  ```elixir
  # Perform IXFR transfer
  case DNS.Zone.Transfer.ixfr("example.com", 2024010101) do
    {:ok, changes} ->
      IO.puts("Received \#{length(changes)} changes via IXFR")
    {:error, reason} ->
      IO.puts("IXFR failed: \#{reason}")
  end
  ```

  ### Applying Zone Transfers
  ```elixir
  # Apply transferred zone data
  records = [...] # Records from AXFR/IXFR
  case DNS.Zone.Transfer.apply_transfer("example.com", records, transfer_type: :axfr) do
    {:ok, zone} ->
      IO.puts("Zone updated successfully")
    {:error, reason} ->
      IO.puts("Failed to apply transfer: \#{reason}")
  end
  ```

  ## DNSSEC Management

  ### Enabling DNSSEC
  ```elixir
  # Enable DNSSEC for a zone
  case DNS.Zone.Editor.enable_dnssec("example.com") do
    {:ok, signed_zone} ->
      IO.puts("DNSSEC enabled successfully")
    {:error, reason} ->
      IO.puts("DNSSEC setup failed: \#{reason}")
  end
  ```

  ### Manual DNSSEC Signing
  ```elixir
  # Sign zone with custom options
  case DNS.Zone.DNSSEC.sign_zone(zone,
    algorithm: :rsasha256,
    key_size: 2048,
    nsec3_enabled: true
  ) do
    {:ok, signed_zone} ->
      IO.puts("Zone signed successfully")
    {:error, reason} ->
      IO.puts("Signing failed: \#{reason}")
  end
  ```

  ## Zone Cloning

  ### Clone Zone for Testing
  ```elixir
  # Clone an existing zone
  case DNS.Zone.Editor.clone_zone("production.com", "staging.com") do
    {:ok, cloned_zone} ->
      IO.puts("Zone cloned successfully")
    {:error, reason} ->
      IO.puts("Cloning failed: \#{reason}")
  end
  ```

  ## Examples

  ### Complete Zone Setup
  ```elixir
  # Create a complete zone with all essential records
  {:ok, zone} = DNS.Zone.Editor.create_zone_interactive("company.com",
    type: :authoritative,
    soa: [
      mname: "ns1.company.com",
      rname: "admin.company.com",
      serial: 2024010101,
      refresh: 3600,
      retry: 1800,
      expire: 604800,
      minimum: 300
    ],
    ns: ["ns1.company.com", "ns2.company.com"],
    a: [
      {"@", "192.168.1.10"},
      {"www", "192.168.1.10"},
      {"mail", "192.168.1.20"},
      {"ns1", "192.168.1.1"},
      {"ns2", "192.168.1.2"}
    ],
    mx: [{10, "mail.company.com"}],
    txt: [{"@", "v=spf1 mx ~all"}]
  )

  # Validate the zone
  {:ok, validation} = DNS.Zone.Validator.validate_zone(zone)
  IO.inspect(validation.summary)

  # Export to BIND format
  {:ok, zone_file} = DNS.Zone.Editor.export_zone("company.com", format: :bind)
  File.write!("company.com.zone", zone_file)
  ```
  """

  alias DNS.Zone.Name

  @type zone_type :: :authoritative | :stub | :forward | :cache

  @type t :: %__MODULE__{
          name: Name.t(),
          type: zone_type(),
          options: list(term())
        }

  defstruct name: Name.new("."), type: :authoritative, options: []

  @spec new(binary() | map(), any()) :: t()
  def new(name, type \\ :authoritative, options \\ [])

  def new(name, type, options) when is_binary(name) do
    new(Name.new(name), type, options)
  end

  def new(name, type, options) when is_struct(name, Name) do
    %__MODULE__{
      name: name,
      type: type,
      options: options
    }
  end

  @spec hostname(Name.t(), DNS.Message.Domain.t()) :: Name.t() | false
  def hostname(%Name{value: "."} = _zone_name, %DNS.Message.Domain{} = domain) do
    Name.from_domain(domain)
  end

  def hostname(%Name{} = zone_name, %DNS.Message.Domain{} = domain) do
    domain_name = Name.from_domain(domain)

    if Name.child?(zone_name, domain_name) do
      domain_name.value
      |> String.trim_trailing(zone_name.value)
      |> Name.new()
    else
      false
    end
  end
end
