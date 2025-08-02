%% src/dtls_echo_listener.erl
-module(dtls_echo_listener).
-behaviour(gen_server).

-export([start_link/3]).
-export([open_port/3, close_port/2]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).

-record(state, {
  port
}).

%%% API
start_link(Port, _ConnectFun, _Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Port, []).

%%% gen_server callbacks
init(Port) ->
    ok = esockd:start(),
    PrivDir = code:priv_dir(esockd),
    DtlsOpts = [
      {mode, binary}, {reuseaddr, true}, {active, 100},
      {certfile, filename:join(PrivDir, "cert.pem")}, %%"demo.crt")},
      {keyfile,  filename:join(PrivDir, "key.pem")} %%"demo.key")}
    ],
    Opts = [
      {acceptors, 4},
      {max_connections, 1000},
      {dtls_options, DtlsOpts}
    ],

    %% Tell esockd to use our connection‐sup to spawn each handler
    MFArgs = {dtls_echo_conn_sup, start_child, [Port]},
    {ok, _ListenSock} = esockd:open_dtls('echo/dtls', Port, Opts, MFArgs),

    {ok, #state{port=Port}}.

handle_info(_Info, State) ->
    %% We don’t expect “normal” messages here
    {noreply, State}.

handle_cast(_Msg, State) ->
    %% No action taken; just continue
    {noreply, State}.

handle_call(_Request, _From, State) ->
    %% Respond with a default reply
    {reply, ok, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Functions
open_port(dtls, Port, Opts) ->
    MFArgs = {dtls_echo_conn_sup, start_child, [Port]},
    case esockd:open_dtls('echo/dtls', Port, Opts, MFArgs) of
        {ok, ListenSock} ->
            io:format("DTLS port ~p opened successfully.~n", [Port]),
            {ok, ListenSock};
        {error, Reason} ->
            io:format("Failed to open DTLS port ~p: ~p~n", [Port, Reason]),
            {error, Reason}
    end;

open_port(udp, Port, Opts) ->
    MFArgs = {dtls_echo_conn_sup, start_child, [Port]},
    case esockd:open_udp('echo/udp', Port, Opts, MFArgs) of
        {ok, ListenSock} ->
            io:format("UDP (insecure) port ~p opened successfully.~n", [Port]),
            {ok, ListenSock};
        {error, Reason} ->
            io:format("Failed to open UDP port ~p: ~p~n", [Port, Reason]),
            {error, Reason}
    end.

close_port(Proto, Port) ->
    case esockd:close(Proto, Port) of
        ok ->
            io:format("Port ~p ~p closed successfully.~n", [Proto, Port]),
            {ok, Port};
        {error, Reason} ->
            io:format("Failed to close port ~p ~p: ~p~n", [Proto, Port, Reason]),
            {error, Reason}
    end.

