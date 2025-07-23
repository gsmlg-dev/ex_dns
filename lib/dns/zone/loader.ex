defmodule DNS.Zone.Loader do
  @moduledoc """
  Zone loading and persistence system.

  Handles loading zones from files, databases, and other sources,
  as well as saving zones back to persistent storage.
  """

  alias DNS.Zone
  alias DNS.Zone.FileParser

  @doc """
  Load zones from a directory containing zone files.
  """
  @spec load_zones_from_directory(String.t()) :: {:ok, list(Zone.t())} | {:error, String.t()}
  def load_zones_from_directory(directory) do
    case File.ls(directory) do
      {:ok, files} ->
        zones =
          files
          |> Enum.filter(&String.ends_with?(&1, ".zone"))
          |> Enum.map(fn filename ->
            path = Path.join(directory, filename)
            name = String.replace_suffix(filename, ".zone", "")
            {name, path}
          end)
          |> Enum.map(fn {name, path} -> load_zone_from_file(name, path) end)
          |> Enum.filter(fn
            {:ok, _} -> true
            {:error, _} -> false
          end)
          |> Enum.map(fn {:ok, zone} -> zone end)

        {:ok, zones}

      {:error, reason} ->
        {:error, "Failed to read directory: #{reason}"}
    end
  end

  @doc """
  Load a single zone from file.
  """
  @spec load_zone_from_file(String.t(), String.t()) :: {:ok, Zone.t()} | {:error, String.t()}
  def load_zone_from_file(name, file_path) do
    case FileParser.parse_file(file_path) do
      {:ok, zone_data} ->
        zone = create_zone_from_data(name, zone_data, file_path)
        {:ok, zone}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Reload a zone from its source file.
  """
  @spec reload_zone(Zone.t()) :: {:ok, Zone.t()} | {:error, String.t()}
  def reload_zone(zone) do
    case Keyword.get(zone.options, :source_file) do
      nil ->
        {:error, "Zone has no source file"}

      file_path ->
        load_zone_from_file(zone.name.value, file_path)
    end
  end

  @doc """
  Save a zone to file.
  """
  @spec save_zone_to_file(Zone.t(), String.t()) :: :ok | {:error, String.t()}
  def save_zone_to_file(zone, file_path) do
    zone_data = extract_zone_data(zone)
    zone_content = FileParser.generate(zone_data)

    case File.write(file_path, zone_content) do
      :ok -> :ok
      {:error, reason} -> {:error, "Failed to write zone file: #{reason}"}
    end
  end

  @doc """
  Create zone data from zone options.
  """
  @spec create_zone_data(Zone.t()) :: map()
  def create_zone_data(zone) do
    %{
      origin: Keyword.get(zone.options, :origin),
      ttl: Keyword.get(zone.options, :ttl, 3600),
      soa: Keyword.get(zone.options, :soa),
      records: Keyword.get(zone.options, :records, []),
      includes: Keyword.get(zone.options, :includes, []),
      directives: Keyword.get(zone.options, :directives, []),
      errors: Keyword.get(zone.options, :errors, []),
      warnings: Keyword.get(zone.options, :warnings, [])
    }
  end

  ## Private functions

  defp create_zone_from_data(name, zone_data, source_file) do
    options = [
      origin: zone_data.origin,
      ttl: zone_data.ttl,
      soa: zone_data.soa,
      records: zone_data.records,
      includes: zone_data.includes,
      directives: zone_data.directives,
      errors: zone_data.errors,
      warnings: zone_data.warnings,
      source: :file,
      source_file: source_file
    ]

    Zone.new(name, :authoritative, options)
  end

  defp extract_zone_data(zone) do
    %{
      origin: Keyword.get(zone.options, :origin),
      ttl: Keyword.get(zone.options, :ttl, 3600),
      soa: Keyword.get(zone.options, :soa),
      records: Keyword.get(zone.options, :records, []),
      includes: Keyword.get(zone.options, :includes, []),
      directives: Keyword.get(zone.options, :directives, []),
      errors: Keyword.get(zone.options, :errors, []),
      warnings: Keyword.get(zone.options, :warnings, [])
    }
  end
end
