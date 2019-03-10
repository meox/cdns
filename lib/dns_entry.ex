defmodule CDNS.Entry do
  alias __MODULE__

  defstruct(
    name: nil,
    type: :unknown,
    ttl: 0,
    value: nil
  )

  @type t :: %Entry{
          name: String.t(),
          type: atom(),
          ttl: integer(),
          value: String.t()
        }
end
