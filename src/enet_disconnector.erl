-module(enet_disconnector).
-behaviour(gen_server).

%% API
-export([
    start_link/1,
    set_trigger/4,
    unset_trigger/4
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-record(state, {
    port
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(HostId) ->
    gen_server:start_link(?MODULE, [HostId], []).

set_trigger(HostId, PeerID, IP, Port) ->
    Server = gproc:where({n, l, {enet_disconnector, HostId}}),
    gen_server:cast(Server, {set_trigger, self(), PeerID, IP, Port}).

unset_trigger(HostId, PeerID, IP, Port) ->
    Server = gproc:where({n, l, {enet_disconnector, HostId}}),
    gen_server:call(Server, {unset_trigger, PeerID, IP, Port}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([HostId]) ->
    true = gproc:reg({n, l, {enet_disconnector, HostId}}),
    {ok, #state{port = HostId}}.

handle_call({unset_trigger, PeerID, IP, Port}, {PeerPid, _}, S) ->
    Key = {n, l, {PeerID, IP, Port}},
    Ref = gproc:get_value(Key, PeerPid),
    ok = gproc:demonitor(Key, Ref),
    true = gproc:unreg_other(Key, PeerPid),
    {reply, ok, S}.

handle_cast({set_trigger, PeerPid, PeerID, IP, Port}, State) ->
    Key = {n, l, {PeerID, IP, Port}},
    true = gproc:reg_other(Key, PeerPid),
    Ref = gproc:monitor(Key),
    updated = gproc:ensure_reg_other(Key, PeerPid, Ref),
    {noreply, State}.

handle_info({gproc, unreg, _Ref, {n, l, {PeerID, IP, Port}}}, S) ->
    #state{port = HostId} = S,
    {CH, Command} = enet_command:unsequenced_disconnect(),
    HBin = enet_protocol_encode:command_header(CH),
    CBin = enet_protocol_encode:command(Command),
    Data = [HBin, CBin],
    Host = gproc:where({n, l, {enet_host, HostId}}),
    enet_host:send_outgoing_commands(Host, Data, IP, Port, PeerID),
    {noreply, S}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
