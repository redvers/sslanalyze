require Logger
use Amnesia
use Bitwise

defdatabase SSLAnalyzeDB do                                                                                                                                           
  deftable IPMemCache, [:ip, :cachetime, :state], type: :set do end                                                                                                   
  deftable IPPersist, [:ip, :keyid, :timestamp], type: :bag do end
  deftable CertPersist, [:keyid, :signingkeyid, :blob, :state], type: :set do end
  deftable DomainPersist, [:domain, :keyid], type: :bag do end
end 

defmodule Sslanalyze.Process.Supervisor do
  use Supervisor
  def start_link() do
    Supervisor.start_link(__MODULE__, [], [name: __MODULE__])
  end

  def init([]) do
    poolsize = 20
    poolover = 100

    pool_options = [
      name: {:local, :sslanalyze},
      worker_module: Sslanalyze.Process,
      size: poolsize,
      max_overflow: poolover
    ]

    :ets.new(:sslrcvr, [:named_table, :public, :bag])

    children = [
      :poolboy.child_spec(:sslanalyze, pool_options, [])
    ]

    supervise(children, strategy: :one_for_one)
  end

  def fipin({ip,port}) do
    ip = to_char_list(ip)
    spawn(Sslanalyze.Process.Supervisor, :dispatch, [{ip,port}])
  end

  def dispatch({ip,port}) do
    Logger.info("In dispatch")
    :poolboy.transaction(:sslanalyze, fn(worker)-> :gen_server.call(worker, {ip, port}) end, :infinity)
  end
end



defmodule Sslanalyze.Process do
  require Record
  require XPKCSFRAME
  require Xpublic_key
  require XOTPPUBKEY
  use GenServer

#  Record.defrecord :OTPCertificate, [tbsCertificate: :undefined, signatureAlgorithm: :undefined, signature: :undefined]
#  Record.defrecord :OTPTBSCertificate, [version: :asn1_DEFAULT, serialNumber: :undefined, signature: :undefined,
#                                        issuer: :undefined, validity: :undefined, subject: :undefined,
#                                        subjectPublicKeyInfo: :undefined, issuerUniqueID: :asn1_NOVALUE,
#                                        subjectUniqueID: :asn1_NOVALUE, extensions: :asn1_NOVALUE]
#  Record.defrecord :
  
  def start_link([]) do
    GenServer.start_link(__MODULE__, nil, []) #name: __MODULE__)
  end

  def init(nil) do
    {:ok, HashDict.new}
  end

  def handle_call({ip, port}, _from, state) do
    Logger.info("Analysis requested for #{ip}")
    {:ok, sslsock}  = :ssl.connect(ip, 443, [verify: :verify_peer, cacertfile: '/etc/ssl/certs/ca-certificates.crt', depth: 9, verify_fun: {&Sslanalyze.Process.verify_fun/3,ip}], 2000)
    :ok = :ssl.close(sslsock)
    processcertdata(ip)
    {:reply, :ok, state}
  end

  def verify_fun(a,b = {:bad_cert, _},userstate)  do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end
  def verify_fun(a,b = {:extension, _},userstate) do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end
  def verify_fun(a,b = :valid,userstate)          do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end
  def verify_fun(a,b = :valid_peer,userstate)     do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end

  def processcertdata(ip) do
    :ets.lookup(:sslrcvr, ip)
    |> Enum.map(&Tuple.to_list/1)
    |> Enum.map(&certentry/1)
  end

  def certentry([ip, :valid_peer,b]) do
    # Valid chain of custard(y) ;-)
    tbsCertificate = XOTPPUBKEY."OTPCertificate"(b, :tbsCertificate)
    serialNumber   = XOTPPUBKEY."OTPTBSCertificate"(tbsCertificate, :serialNumber)
    Logger.info(inspect(serialNumber))
  end

  def certentry([ip, :valid,b]) do
    :ok
  end

  def certentry([ip, {:extension,_},b]) do
    # Ignore for now
    :ok
  end

  def certentry([ip, {:bad_cert, reason},b]) do
    # Bad cert for a good reason
    :ok
  end
end

defmodule SSLRecordsWriter do
  require Record
  def write(filename) do
    {:ok, form} = :epp_dodger.quick_parse_file("include/" <> filename <> ".hrl")
    contents = Enum.map(form, fn({:attribute, _, :record, record}) -> record end )
    |> Enum.reduce("defmodule X" <> Regex.replace(~r/\-/, filename, "") <> " do\nrequire Record\n", fn({x,y}, acc) -> acc <> "  Record.defrecord :\""<>Atom.to_string(x) <> "\", " <> inspect(Record.Extractor.extract(x, from: "include/" <> filename <> ".hrl")) <> "\n" end )
    contents = contents <> "end\n"

    File.write!("lib/#{filename}.ex", String.to_char_list(contents))
  end
end


