defmodule CDNS do
  @moduledoc """
  Documentation for Cdns.
  """

  @dns_server {1, 1, 1, 1}

  def resolve(host) do
    with {:ok, socket} <- :gen_udp.open(0, [:binary, {:active, false}]),
         {id, data} <- query(host),
         :ok <- :gen_udp.send(socket, @dns_server, 53, data),
         {:ok, data} <- read_reply(socket, id) do
      {:ok, data}
    else
      {:error, reason} ->
        {:error, reason}

      {:error, reason, desc} ->
        {:error, reason, desc}

      _ ->
        {:error, :generic}
    end
  end

  def query(host) do
    id = :rand.uniform(255)
    {id, query_header(id) <> question(host)}
  end

  ##### PRIVATE #####

  @spec query_header(integer()) :: binary()
  defp query_header(id) when is_integer(id) do
    <<
      0xAA::8,
      id::8,
      # QR
      0::1,
      # OPCODE: Standard query
      0::4,
      # AA
      0::1,
      # TC [off]
      0::1,
      # RD: Recursion [on]
      1::1,
      # Rest
      0::8,
      # number of requests
      1::16,
      0::16,
      0::16,
      0::16
    >>
  end

  @spec question(String.t()) :: binary()
  def question(host) do
    qname(host) <>
      <<
        0::8,
        # A record
        1::16,
        # QTYPE: IN
        1::16
      >>
  end

  defp read_reply(socket, id) do
    case :gen_udp.recv(socket, 0, 300) do
      {:ok, {_ip, _port, reply}} ->
        :gen_udp.close(socket)
        parse_query_reply(id, reply)

      {:error, reason} ->
        :gen_udp.close(socket)
        {:error, reason}
    end
  end

  ### PARSE REPLY ###

  def parse_query_reply(
        id,
        <<
          0xAA::8,
          id::8,
          1::1,
          _::11,
          0::4-integer,
          _qdcount::16,
          ancount::16,
          _nscount::16,
          _arcount::16,
          rest::binary
        >>
      ) do
    IO.puts("reply #{ancount}")

    rest
    |> discard_request()
    |> parse_reply_content(ancount)
  end

  def parse_query_reply(id, <<0xAA::8, id::8, 1::1, _::11, rcode::4-integer, _rest::binary>>) do
    {:error, :bad_query, "rcode: #{rcode}"}
  end

  def parse_reply_content(data, ancount) do
    parse_all_reply(data, [], ancount)
  end

  defp parse_all_reply(_data, acc, 0), do: {:ok, acc}

  defp parse_all_reply(data, acc, ancount) do
    <<_name::16, type::16, _class::16, ttl::32-unsigned, _len::16-unsigned, rdata::binary>> = data
    <<a::8, b::8, c::8, d::8, rest::binary>> = rdata
    parse_all_reply(rest, [{type, ttl, {a, b, c, d}} | acc], ancount - 1)
  end


  def discard_request(<<0x00::8, _::32, data::binary>>) do
    data
  end

  def discard_request(<<len::8, data::binary>>) do
    <<_::len*8, remain::binary>> = data
    IO.puts("len = #{len}")
    discard_request(remain)
  end

  ### INTERNAL ###

  @doc """
  Convert a hostname to a qname object.

  ##    Examples

        iex> CDNS.qname("example.com")
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
