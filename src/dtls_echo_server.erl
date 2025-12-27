%% src/dtls_echo_server.erl
-module(dtls_echo_server).
-behaviour(gen_statem).

-include("enet_peer.hrl").
-include("enet_commands.hrl").
-include("enet_protocol.hrl").

-export([start_link/5, start_link/7]).
-export([
  callback_mode/0,
  init/1,
  client_connect/3,
  handshake/3,
  connected/3,
  terminate/3,
  code_change/4
]).

-record(state, {
  transport,
  raw_socket,
  is_socket_owned = true,
  socket = undefined,
  peername = undefined,
  connect_fun,
  compressor,
  remote_ip = undefined,
  remote_port = undefined,
  channels = undefined,
  connect_packet_data = undefined
}).

-define(NULL_PEER_ID, ?MAX_PEER_ID).

%%% Called via dtls_echo_conn_sup:start_child(Transport, Socket)
start_link(AssignedPort, ConnectFun, Options, Transport, RawSocket) ->
    gen_statem:start_link(?MODULE, {AssignedPort, ConnectFun, Options, Transport, RawSocket}, []).

%%% Called via dtls_echo_conn_sup:start_child_connect(HostPort, IP, RemotePort, ChannelCount)
start_link(AssignedPort, ConnectFun, Options, IP, RemotePort, ChannelCount, Data) ->
    gen_statem:start_link(?MODULE, {AssignedPort, ConnectFun, Options, IP, RemotePort, ChannelCount, Data}, []).

%%--------------------------------------------------------------------
%% Callback Mode
%%--------------------------------------------------------------------
callback_mode() -> state_functions.

init({AssignedPort, ConnectFun, Options, Transport, RawSocket}) ->
    process_flag(trap_exit, true),
    io:format("Init echo server socket ~p~n", [RawSocket]),
    Ref = make_ref(),
    gproc:reg({n, l, {enet_demux_peer, Ref}}),
    gproc:reg({p, l, name}, Ref),
    gproc:reg({p, l, port}, AssignedPort),
    %%gproc:reg({p, l, peer_id}, PeerID),

        Compressor = 
        case lists:keyfind(compression_mode, 1, Options) of
            {compression_mode, CompressionMode} -> CompressionMode;
            false -> none
        end,

    %% Store raw args and defer the actual wait() to handle_continue
    State0 = #state{transport = Transport,
                    raw_socket = RawSocket,
                    connect_fun = ConnectFun,
                    compressor = Compressor},
    {ok, handshake, State0, [{next_event, internal, exec}]};

init({AssignedPort, ConnectFun, Options, IP, RemotePort, ChannelCount, Data}) ->
    process_flag(trap_exit, true),
    io:format("Init echo client socket ~p:~p~n", [IP, RemotePort]),
    Ref = make_ref(),
    gproc:reg({n, l, {enet_demux_peer, Ref}}),
    gproc:reg({p, l, name}, Ref),
    gproc:reg({p, l, port}, AssignedPort),
    %%gproc:reg({p, l, peer_id}, PeerID),

        Compressor = 
        case lists:keyfind(compression_mode, 1, Options) of
            {compression_mode, CompressionMode} -> CompressionMode;
            false -> none
        end,
    %% For DTLS client, we don't need a raw socket - ssl:connect will create its own
    %% Store raw args and defer the actual connection to handle_continue
    State0 = #state{transport = ssl,
                    raw_socket = undefined,
                    connect_fun = ConnectFun,
                    compressor = Compressor,
                    remote_ip = IP,
                    remote_port = RemotePort,
                    channels = ChannelCount,
                    connect_packet_data = Data
                   },
    {ok, client_connect, State0, [{next_event, internal, exec}]}.

client_connect(internal, exec, State0 = #state{remote_ip = RemoteIP, remote_port = RemotePort}) ->
    io:format("Echo client: Starting DTLS connection to ~p:~p~n", [RemoteIP, RemotePort]),
    %% Get certificate paths from esockd priv directory
    %% For development, use server certificates if client certificates don't exist
    PrivDir = code:priv_dir(esockd),
    ServerCert = filename:join(PrivDir, "cert.pem"),
    ServerKey = filename:join(PrivDir, "key.pem"),
    ClientCert = filename:join(PrivDir, "client.pem"),
    ClientKey = filename:join(PrivDir, "client_key.pem"),
    CACert = filename:join(PrivDir, "ca.pem"),
    %% Use server certs if client certs don't exist (for development)
    FinalClientCert = case filelib:is_file(ClientCert) of
        true -> ClientCert;
        false -> ServerCert
    end,
    FinalClientKey = case filelib:is_file(ClientKey) of
        true -> ClientKey;
        false -> ServerKey
    end,
    FinalCACert = case filelib:is_file(CACert) of
        true -> CACert;
        false -> ServerCert  %% Use server cert as CA for development
    end,
    Opts = [
          {protocol,      dtls},
          {certfile,      FinalClientCert},
          {keyfile,       FinalClientKey},
          {cacertfile,    FinalCACert},
          {verify,        verify_none},  %% Allow self-signed certificates for development
          {active,        true}
        ],
    %% Connect to a DTLS session
    io:format("Echo client: Attempting SSL connect to ~p:~p with certs: ~p, ~p, ~p~n", 
              [RemoteIP, RemotePort, FinalClientCert, FinalClientKey, FinalCACert]),
    %% Check if certificate files exist
    case filelib:is_file(FinalClientCert) andalso filelib:is_file(FinalClientKey) andalso filelib:is_file(FinalCACert) of
        false ->
            io:format("Echo client: Certificate files missing! FinalClientCert exists: ~p, FinalClientKey exists: ~p, FinalCACert exists: ~p~n",
                      [filelib:is_file(FinalClientCert), filelib:is_file(FinalClientKey), filelib:is_file(FinalCACert)]),
            {stop, {certificates_missing, FinalClientCert, FinalClientKey, FinalCACert}, State0};
        true ->
            io:format("Echo client: Certificate files found, attempting SSL connect~n"),
            %% Convert IP from binary/string to tuple format if needed
            IPAddr = case RemoteIP of
                IPBin when is_binary(IPBin) ->
                    case inet:parse_address(binary_to_list(IPBin)) of
                        {ok, Addr} -> Addr;
                        _ -> 
                            Parts = string:tokens(binary_to_list(IPBin), "."),
                            PartsInt = [list_to_integer(P) || P <- Parts],
                            list_to_tuple(PartsInt)
                    end;
                IPStr when is_list(IPStr) ->
                    case inet:parse_address(IPStr) of
                        {ok, Addr} -> Addr;
                        _ -> 
                            Parts = string:tokens(IPStr, "."),
                            PartsInt = [list_to_integer(P) || P <- Parts],
                            list_to_tuple(PartsInt)
                    end;
                IPTup when is_tuple(IPTup) -> IPTup;
                _ -> RemoteIP
            end,
            io:format("Echo client: Connecting to ~p:~p~n", [IPAddr, RemotePort]),
            %% For DTLS client, use ssl:connect with IP and port - it will create its own socket
            ConnectResult = try
                ssl:connect(IPAddr, RemotePort, Opts, 10000)
            catch
                Class:ExceptionReason ->
                    io:format("Echo client: SSL connect exception: ~p:~p~n", [Class, ExceptionReason]),
                    {error, {exception, Class, ExceptionReason}}
            end,
            case ConnectResult of
      {ok, Socket} ->
        io:format("Echo client transport ok, socket ~p~n", [Socket]),
        {ok, PeerName} = ssl:peername(Socket),
        State = State0#state{socket=Socket, peername=PeerName},
                %% Handshake is complete, go directly to connected state
                {next_state, connected, State, [{next_event, internal, client_add_peer}]};
              {error, ConnectReason} ->
                io:format("Echo client transport fail, reason ~p~n", [ConnectReason]),
                io:format("Echo client transport error details - Opts: ~p, RemoteIP: ~p, RemotePort: ~p~n", 
                          [Opts, IPAddr, RemotePort]),
                {stop, {handshake_failed, ConnectReason}, State0}
            end
    end.

handshake(info, {'EXIT', From, Reason}, State) ->
    %% transport or socket died unexpectedly
    io:format("handshake - trapped exit from ~p: ~p~n", [From, Reason]),
    {stop, Reason, State};
handshake(internal, exec, State0 = #state{transport=Transport, raw_socket=RawSocket}) ->
    io:format("Echo server handshake socket ~p~n", [RawSocket]),
    %% Upgrade the raw socket to a DTLS session
    case Transport:wait(RawSocket) of
      {ok, Socket} ->
        io:format("Echo server trandport ok socket ~p~n", [Socket]),
        {ok, PeerName} = Transport:peername(Socket),
        State = State0#state{socket=Socket, peername=PeerName},
        {next_state, connected, State};
      {error, Reason} ->
        io:format("Echo server transport fail reason ~p~n", [Reason]),
        %%Transport:fast_close(RawSocket),
        {stop, {handshake_failed, Reason}, State0}
        %%{stop, {wait_error, Reason}}
    end;
handshake({call, From}, {send_outgoing_commands, C, _IP, _Port, PeerID}, S) ->
    %%
    %% Received outgoing commands during handshake.
    %% Queue them to send after handshake completes.
    %%
    #state{
        compressor = CompressionMode,
        transport = Transport,
        socket = Socket
    } = S,
    case Socket of
        undefined ->
            %% Socket not ready yet - return error
            {keep_state, S, [{reply, From, {error, handshake_in_progress}}]};
        _ ->
            %% Socket ready - send the packet
            {Compressed, Commands} = 
                case CompressionMode of
                    none -> 
                        {0, C}; % uncompressed
                    Compressor ->
                        {1, compress(C, Compressor)}
                end,
            SentTime = get_time(),
            PH = #protocol_header{
                compressed = Compressed,
                peer_id = PeerID,
                sent_time = SentTime
            },
            Packet = [enet_protocol_encode:protocol_header(PH), Commands],
            ok = Transport:send(Socket, Packet),
            {keep_state, S, [{reply, From, {sent_time, SentTime}}]}
    end;
handshake(internal, client, State0 = #state{raw_socket=_RawSocket, socket=Socket}) ->
    io:format("Echo client handshake socket ~p, starting SSL handshake (timeout 10000ms)~n", [Socket]),
    %% Do DTLS session handshake
    %% Note: ssl:handshake might need the socket to be in the right state
    %% Try handshake with a longer timeout and better error handling
    HandshakeResult = try
        ssl:handshake(Socket, 10000)
    catch
        Class:ExceptionReason ->
            io:format("Echo client: SSL handshake exception: ~p:~p~n", [Class, ExceptionReason]),
            {error, {exception, Class, ExceptionReason}}
    end,
    io:format("Echo client: SSL handshake returned: ~p~n", [HandshakeResult]),
    case HandshakeResult of
      {ok, AcceptedSocket} ->
        io:format("Echo client handshake ok socket~n"),
        {ok, PeerName} = ssl:peername(AcceptedSocket),
        State = State0#state{socket=AcceptedSocket, peername=PeerName},
        {next_state, connected, State, [{next_event, internal, client_add_peer}]};
      {error, HandshakeReason} ->
        io:format("Echo client handshake fail reason ~p~n", [HandshakeReason]),
        io:format("Echo client handshake error details: Socket=~p, State=~p~n", [Socket, State0]),
        %%Transport:fast_close(RawSocket),
        {stop, {handshake_failed, HandshakeReason}, State0}
    end. 

%%% Handle all DTLS/SSL messages
connected(info, {ssl, _Raw, Packet}, State = #state{transport=_T, socket=_Socket, peername=P}) ->
    %% Convert packet to binary if it's a list
    PacketBinary = case Packet of
        PList when is_list(PList) -> list_to_binary(PList);
        PBin when is_binary(PBin) -> PBin;
        _ -> iolist_to_binary(Packet)
    end,
    io:format("DTLS Server: Received SSL packet from ~s, size=~p~n", [esockd:format(P), byte_size(PacketBinary)]),
    %%T:async_send(Socket, Packet),
    {PeerIP, PeerPort} = P,
    demux_packet(PeerIP, PeerPort, PacketBinary, State),
    {keep_state, State};

connected(info, {ssl_passive, _Raw}, State = #state{transport=T, socket=S, peername=P}) ->
    io:format("~s → passive~n", [esockd:format(P)]),
    T:setopts(S, [{active, 100}]),
    {keep_state, State};

connected(info, {inet_reply, _Raw, ok}, State) ->
    {keep_state, State};

connected(info, {ssl_closed, _Raw}, State) ->
    {stop, normal, State};

connected(info, {ssl_error, _Raw, Reason}, State = #state{peername=P}) ->
    io:format("~s error: ~p~n", [esockd:format(P), Reason]),
    {stop, Reason, State};

connected(info, _Other, State) ->
    {keep_state, State};
                                 

connected(internal, client_add_peer, S) ->
    %%
    %% Connect to a remote peer.
    %%
    %% - Add a peer to the pool
    %% - Start the peer process
    %%
    #state{
        connect_fun = ConnectFun,
        remote_ip=IP, 
        remote_port=Port,
        channels=Channels,
        connect_packet_data = Data
    } = S,
    Ref = make_ref(),
    LocalPort = get_port(self()),
    ManagerName = get_name(self()),
    HostPid = get_host_pid(self()),
    _Reply =
        try enet_pool:add_peer(LocalPort, Ref) of
            PeerID ->
                Peer = #enet_peer{
                    handshake_flow = local,
                    peer_id = PeerID,
                    ip = IP,
                    port = Port,
                    name = Ref,
                    manager_name = ManagerName,
                    manager_pid = self(),
                    host = HostPid,
                    channels = Channels,
                    connect_fun = ConnectFun,
                    connect_packet_data = Data
                },
                gproc:reg({p, l, peer_id}, PeerID),
                gproc:reg({p, l, peer_name}, Ref),
                start_peer(Peer)
        catch
            error:pool_full -> {error, reached_peer_limit};
            error:exists -> {error, exists}
        end,
    %% TODO: Terminate on failure of start_peer
    {keep_state, S};

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

connected({call, From}, {send_outgoing_commands, C, _IP, _Port, PeerID}, S) ->
    %%
    %% Received outgoing commands from a peer.
    %%
    %% - Compress commands if compressor available
    %% - Wrap the commands in a protocol header
    %% - Send the packet
    %% - Return sent time
    %%
    #state{
        compressor = CompressionMode,
        transport = Transport,
        socket = Socket
    } = S,
    {Compressed, Commands} = 
        case CompressionMode of
            none -> 
                {0, C}; % uncompressed
            Compressor ->
                {1, compress(C, Compressor)}
        end,
    SentTime = get_time(),
    PH = #protocol_header{
        compressed = Compressed,
        peer_id = PeerID,
        sent_time = SentTime
    },
    Packet = [enet_protocol_encode:protocol_header(PH), Commands],
    ok = Transport:send(Socket, Packet),
    {keep_state, S, [{reply, From, {sent_time, SentTime}}]}.

%% Terminate
terminate(_Reason, handshake, #state{transport = T, raw_socket = RawSocket, socket = undefined}) ->
    %% Failed to upgrade raw_socket, close
    T:fast_close(RawSocket),
    ok;
terminate(Reason, _StateName, State) ->
    %% Invalid Unexpected State
    io:format("Invalid state on terminate/3: ~p~n~p~n", [State, Reason]),
    unknown.

code_change(_Old, _StateName, State, _Extra) ->
    {ok, State}.



%% Internal 
demux_packet(IP, Port, Packet, S) ->
    %%
    %% Received a UDP packet.
    %%
    %% - Unpack the ENet protocol header
    %% - Decompress the remaining packet if necessary
    %% - Send the packet to the peer (ID in protocol header)
    %%
    io:format("DTLS Server: demux_packet called for ~p:~p, packet size=~p~n", [IP, Port, byte_size(Packet)]),
    #state{
        compressor = CompressionMode,
        connect_fun = ConnectFun
    } = S,
    %% TODO: Replace call to enet_protocol_decode with binary pattern match.
    {ok,
        #protocol_header{
            compressed = IsCompressed,
            peer_id = RecipientPeerID,
            sent_time = SentTime
        },
        Rest} = enet_protocol_decode:protocol_header(Packet),
    io:format("DTLS Server: Decoded packet, RecipientPeerID=~p (NULL=~p)~n", [RecipientPeerID, ?NULL_PEER_ID]),
    Commands =
        case IsCompressed of
            0 -> Rest;
            1 -> decompress(Rest, CompressionMode)
        end,
    LocalPort = get_port(self()),
    ManagerName = get_name(self()),
    HostPid = get_host_pid(self()),
    case RecipientPeerID of
        ?NULL_PEER_ID ->
            %% No particular peer is the receiver of this packet.
            %% Create a new peer.
            io:format("DTLS Server: Creating new peer for CONNECT from ~p:~p~n", [IP, Port]),
            Ref = make_ref(),
            try enet_pool:add_peer(LocalPort, Ref) of
                PeerID ->
                    io:format("DTLS Server: Created peer PeerID=~p, Ref=~p~n", [PeerID, Ref]),
                    Peer = #enet_peer{
                        handshake_flow = remote,
                        peer_id = PeerID,
                        ip = IP,
                        port = Port,
                        name = Ref,
                        manager_name = ManagerName,
                        manager_pid = self(),
                        host = HostPid,
                        connect_fun = ConnectFun
                    },
                    gproc:reg({p, l, peer_id}, PeerID),
                    gproc:reg({p, l, peer_name}, Ref),
                    {ok, Pid} = start_peer(Peer),
                    io:format("DTLS Server: Started peer process Pid=~p, sending packet~n", [Pid]),
                    %%io:format("Peer start recv packet ~p ~p ~p ~p~n", [Pid, IP, SentTime, Commands]),
                    enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
            catch
                error:pool_full -> {error, reached_peer_limit};
                error:exists -> {error, exists}
            end;
        PeerID ->
            CurrentPeerID = get_peer_id(self()),
            case PeerID =:= CurrentPeerID  of
                true -> 
                    case enet_pool:pick_peer(LocalPort, CurrentPeerID) of
                        false ->
                            ok; %% Peer process failed?
                        Pid ->
                            enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
                    end;
                _ -> ok %% Drop invalid/malicious packet attempt
            end
    end.

%%get_next_peer_id() ->
    %% TODO: Replace with random unique 12bit uint excluding 16#FFF 
%%    make_ref().

get_name(Pid) ->
    gproc:get_value({p, l, name}, Pid).

%% get_peer_name(Peer) ->
%%     gproc:get_value({p, l, peer_name}, Peer).

get_peer_id(Peer) ->
    gproc:get_value({p, l, peer_id}, Peer).

get_port(Pid) ->
    gproc:get_value({p, l, port}, Pid).

get_host_pid(CurrentPid) ->
    AssignedPort = get_port(CurrentPid),
    %%gproc:where({n, g, {enet_host, AssignedPort}}).
    global:whereis_name({enet_host, AssignedPort}).

get_time() ->
    erlang:system_time(1000) band 16#FFFF.

start_peer(Peer = #enet_peer{name = Ref}) ->
    LocalPort = gproc:get_value({p, l, port}, self()),
    PeerSup = gproc:where({n, l, {enet_peer_sup, LocalPort}}),
    {ok, Pid} = enet_peer_sup:start_peer(PeerSup, Peer),
    _Ref = gproc:monitor({n, l, {enet_peer, Ref}}),
    {ok, Pid}.

decompress(Data, zlib) -> 
    zlib:uncompress(Data);
decompress(_Data, Mode) ->
    unsupported_compress_mode(Mode).

compress(Data, zlib) ->
    zlib:compress(Data);
compress(_Data, Mode) ->
    unsupported_compress_mode(Mode).

unsupported_compress_mode(Mode) -> 
    logger:error("Unsupported compression mode: ~p", [Mode]).
