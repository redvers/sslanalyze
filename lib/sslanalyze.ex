defmodule Sslanalyze do
  use Application

  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    case Amnesia.Table.exists?(SSLAnalyzeDB.IPMemCache) do
      false ->  Amnesia.stop
                Amnesia.Schema.destroy
                Amnesia.Schema.create
                Amnesia.start

                SSLAnalyzeDB.IPMemCache.create!()
                SSLAnalyzeDB.IPPersist.create!(disk: [node])
                SSLAnalyzeDB.CertPersist.create!(disk: [node])
                SSLAnalyzeDB.DomainPersist.create!(disk: [node])
      true  ->  :ok
    end


    children = [
      # Start the endpoint when the application starts
      supervisor(Sslanalyze.Endpoint, []),
      supervisor(Sslanalyze.Process.Supervisor, []),
      supervisor(Sslanalyze.Historical.Supervisor, []),
      # Here you could define other workers and supervisors as children
      # worker(Sslanalyze.Worker, [arg1, arg2, arg3]),
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Sslanalyze.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  def config_change(changed, _new, removed) do
    Sslanalyze.Endpoint.config_change(changed, removed)
    :ok
  end
end
