require Logger
use Amnesia
use Bitwise


defmodule Sslanalyze.Historical.Supervisor do
  use Supervisor
  def start_link() do
    Supervisor.start_link(__MODULE__, [], [name: __MODULE__])
  end

  def init([]) do
    poolsize = 20
    poolover = 100

    pool_options = [
      name: {:local, :cbhistory},
      worker_module: Sslanalyze.Historical,
      size: poolsize,
      max_overflow: poolover
    ]

    children = [
      :poolboy.child_spec(:cbhistory, pool_options, [])
    ]

    supervise(children, strategy: :one_for_one)
  end

  def searchHistorical(count) do
    cbservercon = Application.get_env(:sslanalyze, :cbservercon)
    {:ok, %{"results" => results}} = Cbclientapi.Process.search(cbservercon, {"netconn_count:[1 TO *]",count})
    Enum.map(results, fn(%{"id" => uid, "segment_id" => sid, "netconn_count" => cnt}) -> 
                            spawn(Sslanalyze.Historical.Supervisor, :dispatch, [{uid,sid,cnt}]) end )

  end

  def dispatch({uid, sid, cnt}) do
    Logger.info inspect({uid, sid, cnt})
    cbservercon = Application.get_env(:sslanalyze, :cbservercon)
    {:ok, %{"process" => %{"netconn_complete" => res}}} = Cbclientapi.Process.events(cbservercon, uid, sid)
#    Logger.info inspect(res)
    Enum.map(res, fn(x) -> Regex.split(~r/\|/, x) end)
    |> Enum.filter(fn([_,_,portnum,_,_,_]) -> if (portnum == "443") do true else false end end) # Only port 443
    |> Enum.map(fn([_,ipint,_,_,_,_]) -> ipint end)                                             # Extract IP in integer form (but still string typed)
    |> Enum.reduce(HashSet.new, fn(x,acc) -> HashSet.put(acc, x) end)                           # Uniq
    |> Enum.to_list                                                                             # Into a list
    |> Enum.map(&inttoIP/1)                                                                     # Convert to real IP "string" (or nil)
    |> Enum.filter(&(&1))                                                                       # Remove nils
    |> Enum.reject(&inMemCache?/1)                                                              # Only process unknown IPs
    |> IO.inspect
  end

  def inttoIP("") do
    nil
  end
  def inttoIP(intstr) do
    int = String.to_integer(intstr)
    Enum.map([24,16,8,0], fn(x) -> (int >>> x) &&& 0xFF end) 
    |> Enum.join(".")
  end

  def inMemCache?(ipaddr) do
    SSLAnalyzeDB.IPMemCache.member?(ipaddr)
  end
end



defmodule Sslanalyze.Historical do
  use GenServer
  
  def start_link([]) do
    GenServer.start_link(__MODULE__, nil, []) #name: __MODULE__)
  end

  def init(nil) do
    {:ok, HashDict.new}
  end

  def handle_cast({:historical, count}, state) do
    cbservercon = Application.get_env(:sslanalyze, :cbservercon)
    {:ok, %{"results" => results}} = Cbclientapi.Process.search(cbservercon, {"netconn_count:[1 TO *]",count})

    Enum.map(results, fn(%{"id" => uid, "segment_id" => sid, "netconn_count" => cnt}) -> {uid,sid,cnt} end )
    |> Enum.map(&IO.inspect/1)
#    Enum.map(results, &IO.inspect/1)



    {:noreply, state}

  end





end
