defmodule CDNS do
  @moduledoc """
  Client DNS is a simple Elixir lib
  to query a DNS server.

  Ref:
    - https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html
    - http://www.zytrax.com/books/dns/ch15/

  Dump PCAP for test:
    sudo tcpdump -w dns_test.pcap
  """

  @dns_server {{1, 1, 1, 1}, 53}

  @spec resolve(String.t(), Keyword.t()) ::
          {:ok, [any()]} | {:error, any()} | {:error, any(), String.t()}
  def resolve(host, opts \\ [{:dns_server, @dns_server}]) do
    {dns_server, dns_port} = Keyword.get(opts, :dns_server)

    with {:ok, socket} <- :gen_udp.open(0, [:binary, {:active, false}]),
         {id, data} <- query(host),
         :ok <- :gen_udp.send(socket, dns_server, dns_port, data),
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

  ##### PRIVATE #####

  defp query(host) do
    id = :rand.uniform(255)
    {id, query_header(id) <> question(host)}
  end

  @spec query_header(integer()) :: binary()
  defp query_header(id) when is_integer(id) do
    <<
      # identifier: 0xAA + random integer
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
  defp question(host) do
    Utils.qname(host) <>
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

  defp parse_query_reply(
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

  defp parse_query_reply(id, <<0xAA::8, id::8, 1::1, _::11, rcode::4-integer, _rest::binary>>) do
    {:error, :bad_query, "rcode: #{rcode}"}
  end

  @spec parse_reply_content(binary(), integer()) :: {:ok, [any()]}
  defp parse_reply_content(data, ancount) do
    parse_all_reply(data, [], ancount)
  end

  defp parse_all_reply(_data, acc, 0), do: {:ok, acc}

  defp parse_all_reply(data, acc, ancount) do
    <<_name::16, type::16, _class::16, ttl::32-unsigned, _len::16-unsigned, rdata::binary>> = data
    <<a::8, b::8, c::8, d::8, rest::binary>> = rdata
    parse_all_reply(rest, [{type, ttl, {a, b, c, d}} | acc], ancount - 1)
  end

  defp discard_request(<<0x00::8, _::32, data::binary>>) do
    data
  end

  defp discard_request(<<len::8, data::binary>>) do
    <<_::len*8, remain::binary>> = data
    IO.puts("len = #{len}")
    discard_request(remain)
  end
end
