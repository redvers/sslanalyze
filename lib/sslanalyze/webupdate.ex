defmodule SslAnalyze.WebUpdate do
  use GenServer
  require Logger

  def start_link() do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  end

  def init(nil) do
    :timer.send_interval(500, SslAnalyze.WebUpdate, :tick)
    :ets.new(:stats, [:named_table, :public, :set])
    :ets.insert(:stats, {:cachehit, 0})
    :ets.insert(:stats, {:ssldispatch, 0})
    {:ok, HashDict.new}
  end
 
  def handle_cast(:tick, state) do
    update
    {:noreply, state}
  end

  def handle_info(:tick, state) do
    update
    {:noreply, state}
  end

  def update do
#    Logger.debug("Sending client update...")
    Sslanalyze.Endpoint.broadcast! "rooms:lobby", "db_msg",
      %{imc: SSLAnalyzeDB.IPMemCache.properties[:size],
        ipc: SSLAnalyzeDB.IPPersist.properties[:size],
        cpc: SSLAnalyzeDB.CertPersist.properties[:size],
        dpc: SSLAnalyzeDB.DomainPersist.properties[:size],
        ims: SSLAnalyzeDB.IPMemCache.properties[:memory],
        ips: SSLAnalyzeDB.IPPersist.properties[:memory],
        cps: SSLAnalyzeDB.CertPersist.properties[:memory],
        dps: SSLAnalyzeDB.DomainPersist.properties[:memory],
        cachehit: cachehit,
        ssldispatch: ssldispatch
       }
  end

  def cachehit do
    [cachehit: ch] = :ets.lookup(:stats, :cachehit)
    ch
  end
  def ssldispatch do
    [ssldispatch: ch] = :ets.lookup(:stats, :ssldispatch)
    ch
  end
end
