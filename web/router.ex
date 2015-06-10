defmodule Sslanalyze.Router do
  use Sslanalyze.Web, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", Sslanalyze do
    pipe_through :browser # Use the default browser stack

    get "/", PageController, :index
    get "/ip", PageController, :ips
  end

  socket "/ws", Sslanalyze do
    channel "rooms:*", RoomChannel
  end

  # Other scopes may use custom stacks.
  # scope "/api", Sslanalyze do
  #   pipe_through :api
  # end
end
