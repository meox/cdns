defmodule Utils do
  @doc """
  Convert a hostname to a qname object.

  ##    Examples

        iex> Utils.qname("example.com")
        <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109>>
  """
  def qname(host) do
    host
    |> String.split(".")
    |> Enum.map(fn section -> URI.encode(section) end)
    |> Enum.map_join(fn section ->
      [String.length(section) | String.to_charlist(section)]
      |> Enum.map_join(fn x -> <<x::8-big>> end)
    end)
  end
end
