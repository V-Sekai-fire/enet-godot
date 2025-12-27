%% src/dtls_echo_listener.erl
-module(dtls_echo_listener).
-behaviour(gen_server).

-export([start_link/4]).
-export([open_port/3, close_port/2]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).

-record(state, {
  port,
  esockd_name
}).

%%% API
start_link(Port, HostId, _ConnectFun, _Options) ->
    %% Use unique name per HostId to support multiple clients
    Name = {via, gproc, {n, l, {?MODULE, HostId}}},
    gen_server:start_link(Name, ?MODULE, {Port, HostId}, []).

%%% gen_server callbacks
init({Port, HostId}) ->
    %% Clients (Port=0) don't need a listener - they connect to servers
    %% Only servers (Port>0) need to listen for incoming connections
    case Port of
        0 ->
            %% Client mode: no listener needed
            {ok, #state{port=Port, esockd_name=undefined}};
        _ ->
            %% Server mode: start DTLS listener
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
            %% Use HostId (not Port) so multiple clients can connect on port 0
            %% Use HostId in the esockd name to support multiple server instances
            MFArgs = {dtls_echo_conn_sup, start_child, [HostId]},
            EsockdName = list_to_atom("echo/dtls/" ++ integer_to_list(HostId)),
            %% Try to close any existing listener on this port/name
            %% Ignore errors - listener might not exist
            catch esockd:close(EsockdName, Port),
            %% Wait a bit for cleanup to complete
            timer:sleep(100),
            %% Try to open the listener
            case esockd:open_dtls(EsockdName, Port, Opts, MFArgs) of
                {ok, _ListenSock} ->
                    {ok, #state{port=Port, esockd_name=EsockdName}};
                {error, {{shutdown, {failed_to_start_child, _Listener, already_listening}}, _}} = Error ->
                    %% Listener already exists - this is OK if it's the same one
                    %% Try to verify it's our listener by checking if we can get info about it
                    %% For now, just accept it and continue
                    io:format("DTLS listener already exists on port ~p, assuming it's ours~n", [Port]),
                    {ok, #state{port=Port, esockd_name=EsockdName}};
                {error, already_listening} ->
                    %% Simpler error format - listener already exists
                    io:format("DTLS listener already exists on port ~p, assuming it's ours~n", [Port]),
                    {ok, #state{port=Port, esockd_name=EsockdName}};
                Error ->
                    io:format("Failed to open DTLS listener: ~p~n", [Error]),
                    {stop, {failed_to_open_dtls, Error}}
            end
    end.

handle_info(_Info, State) ->
    %% We don’t expect “normal” messages here
    {noreply, State}.

handle_cast(_Msg, State) ->
    %% No action taken; just continue
    {noreply, State}.

handle_call(_Request, _From, State) ->
    %% Respond with a default reply
    {reply, ok, State}.

terminate(_Reason, State) ->
    %% Close the esockd listener if it exists
    case State#state.esockd_name of
        undefined -> ok;
        EsockdName ->
            case State#state.port of
                0 -> ok;  %% Clients don't have listeners
                Port ->
                    esockd:close(EsockdName, Port),
                    ok
            end
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Functions
open_port(dtls, Port, Opts) ->
    %% For server-side, use Port as HostId (servers use fixed ports)
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

