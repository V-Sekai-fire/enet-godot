%% src/dtls_echo_conn_sup.erl
%% Supervisor of each hosted ssl port using raw sockets.
-module(dtls_echo_conn_sup).
-behaviour(supervisor).

-export([start_link/3, init/1, start_child/3, start_child_connect/5]).

start_link(HostId, ConnectFun, Options) ->
    io:format("Start dtls_echo_conn_sup link ~p~n", [HostId]),
    supervisor:start_link(spec_name(HostId), ?MODULE, [HostId, ConnectFun, Options]).

spec_name(HostId) ->
    {via, gproc, {n, l, {?MODULE, HostId}}}.

init([HostId, ConnectFun, Options]) ->
    %% Each connection is a dtls_echo_server child,
    ConnChild = {
      dtls_conn,
      {dtls_echo_server, start_link, [HostId, ConnectFun, Options]},
      transient,
      5000,
      worker,
      [dtls_echo_server]
    },

    {ok, {{simple_one_for_one, 5, 10}, [ConnChild]}}.

%% Called by listener when a new socket arrives
start_child(Transport, Socket, HostId) ->
    io:format("Starting new session socket ~p~n", [Socket]),
    supervisor:start_child(spec_name(HostId), [Transport, Socket]).

%% Called by user API to connect to a server
start_child_connect(HostId, IP, RemotePort, ChannelCount, Data) ->
    io:format("Starting new client session socket ~p ~p~n", [IP, RemotePort]),
    supervisor:start_child(spec_name(HostId), [IP, RemotePort, ChannelCount, Data]).
