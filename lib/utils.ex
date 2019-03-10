defmodule Utils do
  @doc """
  Convert a hostname to a qname object.

  ##    Examples

        iex> Utils.qname("example.com")
        <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109>>
  """
  @spec qname(String.t()) :: binary()
  def qname(host) do
    host
    |> String.split(".")
    |> Enum.map(fn section -> URI.encode(section) end)
    |> Enum.map_join(fn section ->
      [String.length(section) | String.to_charlist(section)]
      |> Enum.map_join(fn x -> <<x::8-big>> end)
    end)
  end

  @doc """
  From the original packet retrieve the hostname/cname
  starting from the specified index.
  """
  @spec to_name(binary(), non_neg_integer()) :: binary()
  def to_name(orig, index) do
    compose_name(orig, index, [])
  end

  ##### PRIVATE #####

  defp compose_name(orig, index, acc) do
    <<len::8>> = binary_part(orig, index, 1)
    take_token(orig, index, len, acc)
  end

  defp take_token(_orig, _index, 0, acc) do
    acc
    |> Enum.reverse()
    |> Enum.join(".")
  end

  defp take_token(orig, index, len, acc) do
    token =
      orig
      |> binary_part(index + 1, len)
      |> String.codepoints()
      |> Enum.join("")
    compose_name(orig, index + len + 1, [token | acc])
  end
end
