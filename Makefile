all:
	MIX_ENV=prod iex -S mix

release:
	MIX_ENV=prod mix release --verbosity=verbose
