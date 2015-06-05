use Mix.Config

config :sslanalyze, Sslanalyze.Endpoint,
  http: [port: 8000],
  url: [host: "example.com"]
#  https: [port: 443,
#      keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
#      certfile: System.get_env("SOME_APP_SSL_CERT_PATH")]

config :logger, level: :info
config :phoenix, :serve_endpoints, true

import_config "prod.secret.exs"
