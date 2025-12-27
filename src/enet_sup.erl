-module(enet_sup).
-behaviour(supervisor).

%% API
-export([
    start_link/0,
    start_host_supervisor/3,
    start_host_dtls_supervisor/3,
    stop_host_supervisor/1
]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_host_supervisor(Port, ConnectFun, Options) ->
    Child = #{
        id => Port,
        start => {enet_host_sup, start_link, [Port, ConnectFun, Options]},
        restart => temporary,
        shutdown => infinity,
        type => supervisor,
        modules => [enet_host_sup]
    },
    supervisor:start_child(?MODULE, Child).

start_host_dtls_supervisor(Port, ConnectFun, Options) ->
    %%Port = 5684,
    %% Generate unique ID for this host instance (supports multiple clients on port 0)
    %% Use timestamp + random to ensure uniqueness
    HostId = case Port of
        0 -> erlang:unique_integer([positive, monotonic]);
        _ -> Port
    end,
    %% Listener: the socket listener gen_server (needs both Port for socket and HostId for connections)
    Listener = #{
        id => {listener, HostId},
        start => {dtls_echo_listener, start_link, [Port, HostId, ConnectFun, Options]},
        restart => permanent,
        shutdown => 5000, %%infinity,
        type => worker,
        modules => [dtls_echo_listener]
    },
    %% ConnSup: dynamic supervisor for connections
    ConnSup = #{
        id => {connection_sup, HostId},
        start => {dtls_echo_conn_sup, start_link, [HostId, ConnectFun, Options]},
        restart => permanent,
        shutdown => 5000, %%infinity,
        type => supervisor,
        modules => [dtls_echo_conn_sup]
    },
    EnetHost = #{
        id => {enet_host_sup, HostId},
        start => {enet_host_sup, start_link, [HostId, ConnectFun, Options]},
        restart => temporary,
        shutdown => infinity,
        type => supervisor,
        modules => [enet_host_sup]
    },
    case supervisor:start_child(?MODULE, Listener) of
        {ok, _} ->
            case supervisor:start_child(?MODULE, ConnSup) of
                {ok, _} ->
                    case supervisor:start_child(?MODULE, EnetHost) of
                        {ok, _} -> {ok, HostId};
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

stop_host_supervisor(HostSup) ->
    supervisor:terminate_child(?MODULE, HostSup).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 1, %% try 10,10
        period => 5
    },
    {ok, {SupFlags, []}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
