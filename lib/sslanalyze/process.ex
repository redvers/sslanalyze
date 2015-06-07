require Logger
use Amnesia
use Bitwise

defdatabase SSLAnalyzeDB do                                                                                                                                           
  deftable IPMemCache, [:ip, :cachetime, :state], type: :set do end                                                                                                   
  deftable IPPersist, [:ip, :keyid, :timestamp], type: :bag do end
  deftable CertPersist, [:keyid, :signingkeyid, :blob, :state], type: :set do end
  deftable DomainPersist, [:tldomain, :domain, :keyid], type: :bag do end
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

    case SSLAnalyzeDB.IPMemCache.read!(ip) do
      nil ->      SSLAnalyzeDB.IPMemCache.write!(%SSLAnalyzeDB.IPMemCache{ip: ip, cachetime: ts, state: nil})
                  spawn(Sslanalyze.Process.Supervisor, :dispatch, [{ip,port}])
      _   ->      Logger.info("CACHE HIT!")
    end

  end

  def dispatch({ip,port}) do
    Logger.info("In dispatch")
    :poolboy.transaction(:sslanalyze, fn(worker)-> :gen_server.call(worker, {ip, port}) end, :infinity)
  end

  def ts do
    {ms, s, _} = :os.timestamp
    (ms * 1000000) + s
  end
end



defmodule Sslanalyze.Process do
  require Record
  require XPKCSFRAME
  require Xpublic_key
  require XOTPPUBKEY
  use GenServer

  def start_link([]) do
    GenServer.start_link(__MODULE__, nil, []) #name: __MODULE__)
  end

  def init(nil) do
    {:ok, HashDict.new}
  end

  def handle_call({ip, port}, _from, state) do
    Logger.info("Analysis requested for #{ip}")
#    {:ok, sslsock}  = :ssl.connect(ip, 443, [verify: :verify_peer, cacertfile: '/etc/ssl/certs/ca-certificates.crt', depth: 9, verify_fun: {&Sslanalyze.Process.verify_fun/3,ip}], 2000)
    case :ssl.connect(ip, 443, [verify: :verify_peer, cacertfile: '/etc/ssl/certs/ca-certificates.crt', depth: 9, verify_fun: {&Sslanalyze.Process.verify_fun/3,ip}], 2000) do
      {:ok, sslsock} -> :ssl.close(sslsock)
                        processcertdata(ip)
      _              -> :ok
    end
    {:reply, :ok, state}
  end

  def verify_fun(a,b = {:bad_cert, _},userstate)  do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end
  def verify_fun(a,b = {:extension, _},userstate) do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end
  def verify_fun(a,b = :valid,userstate)          do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end
  def verify_fun(a,b = :valid_peer,userstate)     do :ets.insert(:sslrcvr, {userstate, b, a}) ; {:valid, userstate} end

  def processcertdata(ip) do
    :ets.lookup(:sslrcvr, ip)
    |> Enum.map(&Tuple.to_list/1)
    |> Enum.filter(&certentry/1)

    :ets.delete(:sslrcvr, ip)
    :ok
  end


  def commitcert(ip, otpcert) do
    tbsCertificate = XOTPPUBKEY."OTPCertificate"(otpcert, :tbsCertificate)
    serialNumber   = XOTPPUBKEY."OTPTBSCertificate"(tbsCertificate, :serialNumber)
    subject   = XOTPPUBKEY."OTPTBSCertificate"(tbsCertificate, :subject)
    extensions     = XOTPPUBKEY."OTPTBSCertificate"(tbsCertificate, :extensions)

    keywords = Enum.map(extensions, fn(extent) -> {XOTPPUBKEY."Extension"(extent, :extnID), XOTPPUBKEY."Extension"(extent, :extnValue)} end)
    |> Enum.map(fn({key, value}) -> {String.to_atom(OID.oid2txt(key)), value} end )

      keyid = Keyword.get(keywords, :"id-ce-subjectKeyIdentifier", [])
    cakeyid = XOTPPUBKEY."AuthorityKeyIdentifier"(Keyword.get(keywords, :"id-ce-authorityKeyIdentifier", XOTPPUBKEY."AuthorityKeyIdentifier"()), :keyIdentifier)
    subjAlt = Keyword.get(keywords, :"id-ce-subjectAltName", [])

    Logger.info("KeyID: " <> inspect(keyid))
    Logger.info("CAKeyID: " <> inspect(cakeyid))

    subject = rationalize_subject(subject)
    Logger.info("subject: " <> inspect(subject))

    rsubjAlt = extractdNSName(subjAlt)
    Logger.info("rsubjAlt: " <> inspect(rsubjAlt))

    Amnesia.transaction do
      SSLAnalyzeDB.IPPersist.write(%SSLAnalyzeDB.IPPersist{ip: ip, keyid: keyid, timestamp: ts})
      SSLAnalyzeDB.CertPersist.write(%SSLAnalyzeDB.CertPersist{keyid: keyid, signingkeyid: cakeyid, blob: otpcert, state: nil})

      Enum.map(rsubjAlt, fn([full, sld]) -> SSLAnalyzeDB.DomainPersist.write(%SSLAnalyzeDB.DomainPersist{tldomain: sld, domain: full, keyid: keyid}) end )
    end




  end

  def extractdNSName(subjAlt) do
    Enum.filter(subjAlt, fn({type, value}) -> if (type == :dNSName) do true else false end end)
    |> Enum.map(fn({:dNSName, charlist}) -> to_string(charlist) end)
    |> Enum.map(fn(domain) -> Regex.run(~r/.*([^.]+\.[^.]+)$/r, domain) end )
  end



  def rationalize_subject({:rdnSequence, subject}) do
    Enum.map(subject, fn([x]) -> {OID.oid2txt(XOTPPUBKEY."AttributeTypeAndValue"(x, :type)), XOTPPUBKEY."AttributeTypeAndValue"(x, :value)} end)
  end



  def certentry([ip, :valid_peer,b]) do
    # Valid chain of custard(y) ;-)
    commitcert(ip,b)
  end

  def certentry([ip, :valid,b]) do
    commitcert(ip,b)
    nil
  end

  def certentry([ip, {:extension,_},b]) do
    # Ignore for now
    nil
  end

  def certentry([ip, {:bad_cert, reason},b]) do
    # Bad cert for a good reason
    nil
  end

  def ts do
    {ms, s, _} = :os.timestamp
    (ms * 1000000) + s
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


