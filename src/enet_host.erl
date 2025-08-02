-module(enet_host).
-behaviour(gen_server).

-include("enet_peer.hrl").
-include("enet_commands.hrl").
-include("enet_protocol.hrl").

%% API
-export([
    start_link/3,
    socket_options/0,
    give_socket/3,
    connect/5,
    send_outgoing_commands/4,
    send_outgoing_commands/5,
    get_port/1,
    get_incoming_bandwidth/1,
    get_outgoing_bandwidth/1,
    get_mtu/1,
    get_channel_limit/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    transport,
    peername,
    socket,
    compressor,
    connect_fun
}).

-define(NULL_PEER_ID, ?MAX_PEER_ID).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Port, ConnectFun, Options) ->
    gen_server:start_link(?MODULE, {Port, ConnectFun, Options}, []).

socket_options() ->
    [binary, {active, false}, {reuseaddr, false}, {broadcast, true}].

give_socket(Host, Socket, Transport) ->
    case Transport:controlling_process(Socket, Host) of
        ok ->
            io:format("Process transferred 1~n"),
            gen_server:cast(Host, {give_socket, Socket, Transport}),
            {ok, Host};
        {error, Reason} ->
            io:format("Failed to transfer process: ~p~n", [Reason]),
            {error, Reason}
    end.

    %%ok = Transport:controlling_process(Socket, Host),
    %%io:format("Process transferred 1"),
    %%ok = gen_udp:controlling_process(Socket, Host),
    %%gen_server:cast(Host, {give_socket, Socket, Transport}).

connect(Host, IP, Port, ChannelCount, Data) ->
    gen_statem:call(Host, {connect, IP, Port, ChannelCount, Data}).

send_outgoing_commands(Host, Commands, IP, Port) ->
    send_outgoing_commands(Host, Commands, IP, Port, ?NULL_PEER_ID).

send_outgoing_commands(Host, Commands, IP, Port, PeerID) ->
    gen_statem:call(
        Host, {send_outgoing_commands, Commands, IP, Port, PeerID}
    ).

get_port(Host) ->
    gproc:get_value({p, l, port}, Host).

get_incoming_bandwidth(Host) ->
    gproc:get_value({p, l, incoming_bandwidth}, Host).

get_outgoing_bandwidth(Host) ->
    gproc:get_value({p, l, outgoing_bandwidth}, Host).

get_mtu(Host) ->
    gproc:get_value({p, l, mtu}, Host).

get_channel_limit(Host) ->
    gproc:get_value({p, l, channel_limit}, Host).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init({AssignedPort, ConnectFun, Options}) ->
    true = gproc:reg({n, l, {enet_host, AssignedPort}}),
    yes = global:register_name({enet_host, AssignedPort}, self()),
    %%io:format("Global proc reg ~p~n", Options),
    ChannelLimit =
        case lists:keyfind(channel_limit, 1, Options) of
            {channel_limit, CLimit} -> CLimit;
            false -> ?MIN_CHANNEL_COUNT
        end,
    IncomingBandwidth =
        case lists:keyfind(incoming_bandwidth, 1, Options) of
            {incoming_bandwidth, IBandwidth} -> IBandwidth;
            false -> 0
        end,
    OutgoingBandwidth =
        case lists:keyfind(outgoing_bandwidth, 1, Options) of
            {outgoing_bandwidth, OBandwidth} -> OBandwidth;
            false -> 0
        end,
    Compressor = 
        case lists:keyfind(compression_mode, 1, Options) of
            {compression_mode, CompressionMode} -> CompressionMode;
            false -> none
        end,
    true = gproc:mreg(
        p,
        l,
        [
            {port, AssignedPort},
            {channel_limit, ChannelLimit},
            {incoming_bandwidth, IncomingBandwidth},
            {outgoing_bandwidth, OutgoingBandwidth},
            {mtu, ?HOST_DEFAULT_MTU}
        ]
    ),
    %%TODO: Evaluate restart behaviour
    %%ok = inet:setopts(Socket, [{active, true}]),
    {ok, #state{connect_fun = ConnectFun, 
                compressor = Compressor,
                transport = undefined,
                peername = undefined,
                socket = undefined}}.

handle_call({connect, IP, Port, Channels, Data}, _From, S) ->
    %%
    %% Connect to a remote peer.
    %%
    %% - Add a peer to the pool
    %% - Start the peer process
    %%
    #state{
        socket = Socket,
        connect_fun = ConnectFun
    } = S,
    Ref = make_ref(),
    LocalPort = get_port(self()),
    Reply =
        try enet_pool:add_peer(LocalPort, Ref) of
            PeerID ->
                Peer = #enet_peer{
                    handshake_flow = local,
                    peer_id = PeerID,
                    ip = IP,
                    port = Port,
                    name = Ref,
                    host = self(),
                    channels = Channels,
                    connect_fun = ConnectFun,
                    connect_packet_data = Data
                },
                start_peer(Peer)
        catch
            error:pool_full -> {error, reached_peer_limit};
            error:exists -> {error, exists}
        end,
    {reply, Reply, S};

handle_call({send_outgoing_commands, C, IP, Port, ID}, _From, S) ->
    %%
    %% Received outgoing commands from a peer.
    %%
    %% - Compress commands if compressor available
    %% - Wrap the commands in a protocol header
    %% - Send the packet
    %% - Return sent time
    %%
    #state{
        compressor = CompressionMode
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
        peer_id = ID,
        sent_time = SentTime
    },
    Packet = [enet_protocol_encode:protocol_header(PH), Commands],
    ok = gen_udp:send(S#state.socket, IP, Port, Packet),
    {reply, {sent_time, SentTime}, S}.

%%%
%%% handle_cast
%%%

handle_cast({give_socket, Socket, Transport}, S) ->
    ok = Transport:setopts(Socket, [{active, true}]),
    {ok, PeerName} = Transport:peername(Socket),
    io:format("Process transferred 2"),
    %%ok = inet:setopts(Socket, [{active, true}]),
    {noreply, S#state{socket = Socket, transport = Transport, peername = PeerName}};
handle_cast(_Msg, State) ->
    {noreply, State}.

%%%
%%% handle_info
%%%

%%% Handle all DTLS/SSL messages
handle_info({ssl, _Raw, Packet}, State = #state{transport=T, socket=S, peername=P}) ->
    io:format("Inside host sup~n"),
    %%io:format("Inside host ~p~n", [Packet]),
    io:format("~s ← ~p~n", [esockd:format(P), Packet]),
    T:async_send(S, Packet),
    {noreply, State};

handle_info({ssl_passive, _Raw}, State = #state{transport=T, socket=S, peername=P}) ->
    io:format("~s → passive~n", [esockd:format(P)]),
    T:setopts(S, [{active, 100}]),
    {noreply, State};

handle_info({inet_reply, _Raw, ok}, State) ->
    {noreply, State};

handle_info({ssl_closed, _Raw}, State) ->
    {stop, normal, State};

handle_info({ssl_error, _Raw, Reason}, State = #state{peername=P}) ->
    io:format("~s error: ~p~n", [esockd:format(P), Reason]),
    {stop, Reason, State};

%%
%% Handle UDP
%%

handle_info({udp, Socket, IP, Port, Packet}, S) ->
    demux_packet(Socket, IP, Port, Packet, S),
    {noreply, S};

handle_info({gproc, unreg, _Ref, {n, l, {enet_peer, Ref}}}, S) ->
    %%
    %% A Peer process has exited.
    %%
    %% - Remove it from the pool
    %%
    #state{
        socket = Socket
    } = S,
    LocalPort = get_port(self()),
    true = enet_pool:remove_peer(LocalPort, Ref),
    {noreply, S}.

%%%
%%% terminate
%%%

terminate(Reason, S) ->
    io:format("terminatin ~p~n",[Reason]).
    %%ok = gen_udp:close(S#state.socket).

%%%
%%% code_change
%%%

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

demux_packet(Socket, IP, Port, Packet, S) ->
    %%
    %% Received a UDP packet.
    %%
    %% - Unpack the ENet protocol header
    %% - Decompress the remaining packet if necessary
    %% - Send the packet to the peer (ID in protocol header)
    %%
    #state{
        socket = Socket,
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
    Commands =
        case IsCompressed of
            0 -> Rest;
            1 -> decompress(Rest, CompressionMode)
        end,
    LocalPort = get_port(self()),
    case RecipientPeerID of
        ?NULL_PEER_ID ->
            %% No particular peer is the receiver of this packet.
            %% Create a new peer.
            Ref = make_ref(),
            try enet_pool:add_peer(LocalPort, Ref) of
                PeerID ->
                    Peer = #enet_peer{
                        handshake_flow = remote,
                        peer_id = PeerID,
                        ip = IP,
                        port = Port,
                        name = Ref,
                        host = self(),
                        connect_fun = ConnectFun
                    },
                    {ok, Pid} = start_peer(Peer),
                    enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
            catch
                error:pool_full -> {error, reached_peer_limit};
                error:exists -> {error, exists}
            end;
        PeerID ->
            case enet_pool:pick_peer(LocalPort, PeerID) of
                %% Unknown peer - drop the packet
                %% In SSL, will drop packet if socket and packet peerid
                %% don't match
                false ->
                    ok;
                Pid ->
                    enet_peer:recv_incoming_packet(Pid, IP, SentTime, Commands)
            end
    end.

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
