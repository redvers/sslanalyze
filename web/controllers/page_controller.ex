defmodule Sslanalyze.PageController do
  use Sslanalyze.Web, :controller

  plug :action

  def index(conn, _params) do
    render conn, "index.html"
  end
  def ips(conn, _params) do
    render conn, "ips.html"
  end
end
