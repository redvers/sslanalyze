defmodule Sslanalyze.Mixfile do
  use Mix.Project

  def project do
    [app: :sslanalyze,
     version: "0.0.1",
     elixir: "~> 1.0",
     elixirc_paths: elixirc_paths(Mix.env),
     compilers: [:phoenix] ++ Mix.compilers,
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [mod: {Sslanalyze, []},
     applications: [:phoenix, :phoenix_html, :cowboy, :logger, 
                    :runtime_tools, :exjsx, :poolboy, :amnesia, :cbserverapi, :cbclientapi, :ssl, :public_key]]
  end

  # Specifies which paths to compile per environment
  defp elixirc_paths(:test), do: ["lib", "web", "test/support"]
  defp elixirc_paths(_),     do: ["lib", "web"]

  # Specifies your project dependencies
  #
  # Type `mix help deps` for examples and options
  defp deps do
    [{:phoenix, "~> 0.13.1"},
     {:phoenix_html, "~> 1.0"},
     {:phoenix_live_reload, "~> 0.4", only: :dev},
     {:exrm, "~> 0.15.3"},
     {:amnesia, git: "https://github.com/meh/amnesia.git"},
     {:cbserverapi, git: "https://github.com/redvers/cbserverapi.git"},
     {:cbclientapi, git: "https://github.com/redvers/cbclientapi.git"},
     {:poolboy, "~> 1.5.1"},
     {:cowboy, "~> 1.0"}]
  end
end
