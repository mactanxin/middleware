'use strict';
restrict: 'A';

/* Controllers */

function LoginController($scope, $location, $routeParams, $route, $rootScope) {
    var sock = new middleware.DispatcherClient(document.domain);
    $scope.login = function() {
        var username = $scope.username;
        var password = $scope.password;
        //try onConnect
        sock.onConnect = function() {
            sock.login(
                $scope.username,
                $scope.password
            );
        };
        sock.onLogin = function(){
            if (!sock.token) {
                $scope.login_status = false;
                console.log("login failed");
                $("#err_msg").html("Username or password is incorrect");
            }else {
                $rootScope.username = username;
                sessionStorage.setItem("freenas:username", username);
                sessionStorage.setItem("freenas:password", password);
                if ($routeParams.nextRoute) {
                    $location.path('/'+$routeParams.nextRoute);
                    $route.reload();
                }else {
                    $location.path('/rpc');
                    $route.reload();
                }
            }
        }
        sock.onError = function(err){
            console.log(err);
        }
        sock.connect();
    }
}

function RpcController($scope, $location, $routeParams, $route, $rootScope, ModalService) {
    document.title = "RPC Page";
    if (!sessionStorage.getItem("freenas:username")){
        $location.path('/login'+$route.current.$$route.originalPath);
    }
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $("#result").hide();
    $scope.init = function () {
        sock.onError = function(err) {
            try {
                $location.path('/login'+$route.current.$$route.originalPath);
            } catch (e) {
                console.log(e);
                $("#socket_status").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            if ($rootScope.username) {
                $("#login_username").html($rootScope.username);
            }
        };

        sock.onLogin = function() {
            sock.call("discovery.get_services", null, function (services) {
                $scope.$apply(function(){
                    $scope.services = services;
                });
                var service_dict = {};
                $.each(services, function(idx, i) {
                    var temp_list = [];
                    sock.call("discovery.get_methods", [i], function(methods) {
                        for(var tmp = 0; tmp < methods.length; tmp++) {
                           temp_list.push(methods[tmp]);
                        }
                    service_dict[i] = temp_list;
                      $scope.$apply(function(){
                        $scope.service_dict = service_dict;
                      });
                    });
                });
            });
        };
    }
    $scope.getServiceList = function(service_name){
        $scope.current_methods = $scope.service_dict[service_name];
        $scope.current_service = service_name;
    }
    $scope.setInput = function(method_name) {
      clearInputText();
      $("#method").val($("#current_service").html() + "." + method_name);
      setParams();
    }
    function setParams() {
      $("#args").val('[]');
    }

    $scope.submitForm = function() {
        console.log('button clicked, loading data, please wait for a sec');
        sock.call(
            $("#method").val(),
            JSON.parse($("#args").val()),
            function(result) {
                $("#result").html(JSON.stringify(result, null, 4));
                $("#result").show("slow");
            }
        );
    }
    function clearInputText() {
      $("#method").val('');
      $("#result").val('');
    }
}

function DispatcherDumpstackController($scope, $location, $routeParams, $route, $rootScope) {
    document.title = "Dispatcher dumpstack";
    if (!sessionStorage.getItem("freenas:username")){
        $location.path('/login'+$route.current.$$route.originalPath);
    }
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $scope.init = function () {
        sock.onError = function(err) {
            try {
                $location.path('/login'+$route.current.$$route.originalPath);
            } catch (e) {
                console.log(e);
                $("#socket_status").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
        };
        sock.onLogin = function() {
            sock.call("debug.dump_stacks", null, function (result) {
                var dump_stacks = [];
                $.each(result, function(idx, i) {
                    dump_stacks.push(i);
                });
                $scope.$apply(function(){
                    $scope.dump_stacks = dump_stacks;
                });
            });
        };
    }
}

function TermController($scope, synchronousService, $location, $routeParams, $route, $rootScope) {
    document.title = "System Events";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    function connect_term(client, command){
        var conn = new middleware.ShellClient(client);
        conn.connect(command);
        conn.onOpen = function() {
            var term = new Terminal({
                cols: 80,
                rows: 24,
                screenKeys: true
            });

            term.on('data', function (data) {
                conn.send(data);
            });

            conn.onData = function (data) {
                term.write(data);
            };

            term.open($("#terminal")[0])
            $scope.$apply(function(){
                $scope.term = term;
            });
        }
    }
    $scope.init = function () {
        var syncUrl = "/static/term.js";
        synchronousService(syncUrl);
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
    };

    sock.onConnect = function() {
        if (!sessionStorage.getItem("freenas:username")) {
            $location.path('/login'+$route.current.$$route.originalPath);
        }

        sock.login(
            sessionStorage.getItem("freenas:username"),
            sessionStorage.getItem("freenas:password")
        );
        $("#login_username").html($rootScope.username);
    };
    sock.onLogin = function() {
        sock.call("shell.get_shells", null, function(response) {
            var dataSource_list = [];
            $.each(response, function(idx, i) {
                dataSource_list.push(i);
            });
            $scope.$apply(function(){
                $scope.dataSource_list = dataSource_list;
            });
        });

        connect_term(sock, "/bin/sh")
    };
    $scope.loadShell = function(source_name) {
        $("#terminal").html("");
        connect_term(sock, source_name);
    }

}

function EventsController($scope, $location, $routeParams, $route, $rootScope) {
    document.title = "System Events";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    sock.onError = function(err) {
        try {
            $route.reload();
        } catch (e) {
            console.log(e);
            $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
            $("#refresh_page_glyph").show();
        }
    };
    sock.onConnect = function() {
        if (!sessionStorage.getItem("freenas:username")) {
            $location.path('/login'+$route.current.$$route.originalPath);
        }

        sock.login(
            sessionStorage.getItem("freenas:username"),
            sessionStorage.getItem("freenas:password")
        );
    };
    sock.onLogin = function() {
        sock.subscribe("*.changed");
        sock.subscribe("migration.status");
        console.log("getting system events, plz wait");
        var item_list = [];
        sock.onEvent = function(name, args) {
            var ctx = {
                name: name,
                args: angular.toJson(args, 4)
            };
            item_list.push(ctx);
            $scope.$apply(function(){
              $scope.item_list = item_list;
            });
        };
    };

    $scope.clearEvents = function() {
        $scope.item_list = [];
    }
}
function SyslogController($scope, $location, $routeParams, $route, $rootScope) {
    document.title = "System Logs";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $scope.init = function () {
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")) {
                $location.path('/login'+$route.current.$$route.originalPath);
            }

            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            $("#login_username").html($rootScope.username);
        };
        sock.onLogin = function(result) {
            var syslog_list = [];
            sock.call("syslog.query", [[], {"sort": ["-id"], "limit": 50}], function(result) {
                $.each(result, function(idx, i) {
                    syslog_list.push(i);
                });

                sock.registerEventHandler("entity-subscriber.syslog.changed", function(args) {
                    $.each(args.entities, function(idx, i) {
                        syslog_list.push(i);
                    });
                });
                $scope.$apply(function(){
                    $scope.syslog_list = syslog_list;
                });
            });
        };
    }
}

function StatsController($scope, $location, $routeParams, $route, $rootScope) {
    document.title = "Stats Charts";
    var sock = new middleware.DispatcherClient(document.domain);
    var chart;
    sock.connect();
    function render_chart(data){
        chart = c3.generate({
            bindto: "#chart",
            data: {
                rows: [["value"]].concat(data)
            },
            colors: {
                rows: ['#1f77b4', '#aec7e8', '#ff7f0e', '#ffbb78', '#2ca02c', '#98df8a', '#d62728', '#ff9896', '#9467bd', '#c5b0d5', '#8c564b', '#c49c94', '#e377c2', '#f7b6d2', '#7f7f7f', '#c7c7c7', '#bcbd22', '#dbdb8d', '#17becf', '#9edae5']
            }
        })
    }

    function update_chart(event){
        console.log(event);
        chart.flow({
            rows: [["x", "value"], [event.timestamp, event.value]]
        })
    }

    function load_chart(name){
        $("#title").text(name);
        sock.subscribe("statd." + name + ".pulse");
        sock.call("stat.get_stats", [name, {
            start: {"$date": moment().subtract($("#timespan").val(), "minutes").format()},
            end: {"$date": moment().format()},
            frequency: $("#frequency").val()
        }], function (response) {
            console.log(response.data);
            render_chart(response.data);
        });
    }
    $scope.init = function () {
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")){
                $location.path('/login'+$route.current.$$route.originalPath);
            }

            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            $("#login_username").html($rootScope.username);
        };
        //onLogin function do everyting you need to render a chart
        sock.onLogin = function() {
            sock.onEvent = function(name, args) {
                if (name == "statd." + $("#title").text() + ".pulse")
                    update_chart(args);
            };

            sock.call("statd.output.get_data_sources", [], function(response) {
                var dataSource_list = [];
                $.each(response, function(idx, i) {
                    dataSource_list.push(i);
                });
                $scope.$apply(function(){
                    $scope.dataSource_list = dataSource_list;
                });
            });
        };
        $scope.loadSource = function(source_name) {
                load_chart(source_name);
        }

        $("#call").click(function() {
            load_chart($("#title").text())
        })
    }
}

function FileBrowserController($scope, $location, $routeParams, $route, $rootScope) {
    document.title = "File Browser";
    var BUFSIZE = 1048576;
    var sock = new middleware.DispatcherClient( document.domain );
    sock.connect();
    $scope.init = function () {
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };

        sock.onConnect = function ( ) {
            if (!sessionStorage.getItem("freenas:username")){
                $location.path('/login'+$route.current.$$route.originalPath);
            }

          sock.login
          ( sessionStorage.getItem( "freenas:username" )
          , sessionStorage.getItem( "freenas:password" )
          );

          $("#login_username").html($rootScope.username);
        };

        sock.onLogin = function ( ) {
          listDir( "/root" );
        };
    }
    // Utility Helper functions
    function pathJoin ( parts, sep ) {
      var separator = sep || "/";
      var replace   = new RegExp( separator + "{1,}", "g" );
      return parts.join( separator ).replace( replace, separator );
    }

    function humanFileSize ( bytes, si ) {
      var thresh = si ? 1000 : 1024;
      if ( Math.abs( bytes ) < thresh ) {
        return bytes + " B";
      }
      var units = si
          ? [ "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" ]
          : [ "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" ];
      var u = -1;
      do {
        bytes /= thresh;
        ++u;
      } while ( Math.abs( bytes ) >= thresh && u < units.length - 1 );
      return bytes.toFixed( 1 ) + " " + units[u];
    };
    // Utility Helper functions

    function humanizeDirItem(item) {
        var date = new Date( 0 );
        item.modified = new Date( date.setUTCSeconds( item.modified ) );
        item.size = humanFileSize( item.size, false );
        return item
    }

    function sendBlob ( fileconn, file, optStartByte, optStopByte ) {
      var start = parseInt( optStartByte ) || 0;
      var stop = parseInt( optStopByte ) || file.size;

      if (stop > file.size) {
        stop = file.size;
      };

      var reader = new FileReader();

      reader.onloadend = function ( evt ) {
        if ( evt.target.readyState == FileReader.DONE ) { // DONE == 2
          console.log
            ( "readBlob byte_range: Read bytes: "
            , start
            , " - "
            , stop
            , " of "
            , file.size
            , " byte file"
          );
          fileconn.send( evt.target.result );
          if ( stop == file.size ) {
              fileconn.send("");
          } else if ( stop + BUFSIZE < file.size ) {
            sendBlob( fileconn, file, stop, stop + BUFSIZE );
          } else {
            sendBlob( fileconn, file, stop, file.size);
          };
        }
      };

      var blob = file.slice( start, stop );
      reader.readAsArrayBuffer( blob );
    }

    function uploadToSocket ( file ) {
      console.log( "uploadToSocket: Initializing FileClient now" );
      var fileconn = new middleware.FileClient( sock );
      fileconn.onOpen = function ( ) {
        console.log( "FileConnection opened, Websocket resdyState: ", fileconn.socket.readyState );
        sendBlob(fileconn, file, 0, 0 + BUFSIZE);
      };
      fileconn.onData = function ( msg ) {
        console.log( "FileConnection message recieved is ", msg );
      };
      fileconn.onClose = function ( ) {
        console.log( "FileConnection closed" );
      };
      fileconn.upload(
          pathJoin(
            [ sessionStorage.getItem( "filebrowser:cwd" ), file.name ]
          )
        , file.size
        , "777"
      );

    }

    var listDir = function ( path, relative ) {
      if ( relative === true ) {
        path = pathJoin( [ sessionStorage.getItem( "filebrowser:cwd" ), path ] );
      }
      if ( path === "" ) { path = "/"; }
      sock.call( "filesystem.list_dir", [ path ], function ( dirs ) {
        $( "#dirlist tbody" ).empty();
        $( "#cwd" ).html( "Current Path: " + path );
        $( "#cdup" ).on( "click", function ( e ) {
          if ( path !== "/" ) {
            listDir( path.substring( 0, path.lastIndexOf( "/" ) ) );
          };
        });
        sessionStorage.setItem( "filebrowser:cwd", path );
        $scope.$apply(function(){
            $scope.current_dir_items = dirs.map(humanizeDirItem);
        });
      });

      $scope.uploadFiles = function() {
          $scope.uploadFileList.map(uploadToSocket);
      }

      $scope.browseFolder = function(foldername) {
          listDir(foldername, true);
      }

      $scope.downloadFile = function(filename) {
          downloadFromHttp( filename );
      }

      function handleFileSelect ( evt ) {
        evt.stopPropagation();
        evt.preventDefault();

        var files = evt.dataTransfer.files; // FileList object.

        $( "#outputfilelist" ).empty();
        console.log(files);
        $scope.uploadFileList = [];
        $.each( files, function ( key, file ) {
          var date = file.lastModifiedDate ? file.lastModifiedDate.toLocaleDateString() : "n/a";
            $scope.uploadFileList.push(file);
        });
        $scope.$apply(function(){
            $scope.hasFileSelected = true;
            $scope.uploadFileList;
        });
      }

      function handleDragOver ( evt ) {
        evt.stopPropagation();
        evt.preventDefault();
        evt.dataTransfer.dropEffect = "copy"; // Explicitly show this is a copy.
      }

      function downloadFromHttp ( filename ) {
        console.log( "downloadFromHttp: Starting download of file: ", filename );
        var path = pathJoin(
              [ sessionStorage.getItem( "filebrowser:cwd" ), filename ]
          );
        var fileconn = new middleware.FileClient( sock );
        fileconn.download ( path, filename, "static" );
      }

      function downloadFromSocket ( filename ) {
        console.log( "downloadFromSocket: Initializing FileClient now" );
        var path = pathJoin(
              [ sessionStorage.getItem( "filebrowser:cwd" ), filename ]
          );
        fileconn = new middleware.FileClient( sock );
        fileconn.onOpen = function ( ) {
          console.log( "FileConnection opened, Websocket resdyState: ", fileconn.socket.readyState );
        };
        fileconn.onData = function ( msg ) {
          console.log( "FileConnection message recieved is ", msg );
        };
        fileconn.onClose = function ( ) {
          console.log( "FileConnection closed" );
        };
        fileconn.download( path, filename, "stream" );
      }

      // Setup the dnd listeners.
      var dropZone = document.getElementById( "drop_zone" );
      dropZone.addEventListener( "dragover", handleDragOver, false );
      dropZone.addEventListener( "drop", handleFileSelect, false );

    };
}

function TasksController($scope, $interval, $location, $routeParams, $route, $rootScope) {
    document.title = "System Tasks";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $("#result").hide();
    function refresh_tasks(){
        $("#tasklist tbody").empty();
        sock.call("task.query", [[["state", "in", ["CREATED", "WAITING", "EXECUTING"]]]], function (tasks) {
            var tmp_list = [];
            $.each(tasks, function(idx, i) {
                tmp_list.push(i);
            });
            $scope.$apply(function(){
                $scope.pending_tasks = tmp_list;
            });
        });
    }
    $scope.init = function() {
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onEvent = function(name, args) {
            if (name == "task.created") {
                $scope.$apply(function(){
                    $scope.pending_tasks.push(args);
                });
            }
            if (name == "task.updated") {
                var tr = $("#tasklist").find("tr[data-id='" + args.id + "']");
                tr.find(".status").text(args.state);
            }

            if (name == "task.progress") {
                var tr = $("#tasklist").find("tr[data-id='" + args.id + "']");
                tr.find(".progress .progress-bar").css("width", args.percentage.toFixed(2) + "%");
                tr.find(".progress .progress-bar").text(args.percentage.toFixed() + "%");
                tr.find(".message").text(args.message);
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")) {
                $location.path('/login'+$route.current.$$route.originalPath);
            }

            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            if ($rootScope.username) {
                $("#login_username").html($rootScope.username);
            }
        };
        sock.onLogin = function() {
            sock.subscribe("task.*");
            refresh_tasks();
            var item_list = [];
            var service_list = [];
            sock.call("discovery.get_tasks", null, function (tasks) {
                $.each(tasks, function(key, value) {
                    value['name'] = key;
                    value['schema'] = angular.toJson(value['schema'], 4);
                    item_list.push(value);
                    service_list.push(key);
                });
                $scope.$apply(function(){
                  $scope.item_list = item_list;
                  $scope.services = service_list;
                });
            });
        }
    }
    $("#submit").click(function () {
        console.log("task submitted");
        var task_args = JSON.parse("[" + $("#args").val().trim()+ "]");
        sock.call("task.submit", [$("#task").val()].concat(task_args), function(result) {
            $("#result").html("Task: "+JSON.stringify(result, null, 4)+" is added to pending list");
            $("#result").show("slow");
            refresh_tasks();
        });
    });
    $scope.setTask = function(task_name){
        $scope.userInput = task_name;
        $("#task").val(task_name);
    }
    $scope.abortTask = function(task_id){
        console.log(task_id);
        if (confirm("Abort this task? ")) {
            sock.call("task.abort", [task_id], function (result) {
            });
            refresh_tasks();
        }
    }
}

function VMController($scope, $location, $routeParams, $route, $rootScope) {
    var sock = new middleware.DispatcherClient(document.domain);
    var term;
    var conn;
    var currentId = null;
    sock.connect();

    function connect_term(client, vm) {
        conn = new middleware.ContainerConsoleClient(client);
        conn.connect(vm);
        conn.onOpen = function() {
            term = new Terminal({
                cols: 80,
                rows: 24,
                screenKeys: true
            });

            term.on('data', function (data) {
                conn.send(data);
            });

            conn.onData = function (data) {
                term.write(data);
            };

            term.open($("#terminal")[0])
        }
    }
    $scope.init = function() {
        var syncUrl = "/static/term.js";
        synchronousService(syncUrl);
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")){
                $location.path('/login'+$route.current.$$route.originalPath);
            }

            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
        };
    }
    $("#containers").on("click", "a.container-entry", function() {
        sock.call("containerd.management.get_status", [$(this).attr("data-id")], function (response) {
            $("#state").text("State: " + response.state);
        });

        if (term) {
            term.destroy();
            conn.disconnect();
        }

        currentId = $(this).attr("data-id");
        connect_term(sock, currentId);
    });
    $("#start-container").on("click", function() {
        sock.call("task.submit", ["vm.start", [currentId]]);
    });

    $("#stop-container").on("click", function() {
        sock.call("task.submit", ["vm.stop", [currentId]]);
    });
}

function Four04Controller($scope) {

}

function Five00Controller($scope) {

}

function HTTPStatusController($scope, $http, $routeParams, $location) {
    $scope.status_code = $routeParams.status_code;
}

function RPCdocController($scope, $location, $routeParams, $route, $rootScope) {
    document.title = "RPC API Page";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $scope.init = function() {
        $(".json").each(function() {
            $(this).JSONView($(this).text(), { "collapsed": true });
            $(this).JSONView('expand', 1);
        });
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")){
                $location.path('/login'+$route.current.$$route.originalPath);
            }

            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            $("#login_username").html($rootScope.username);
        };
        sock.onLogin = function() {
            sock.call("discovery.get_services", null, function (services) {
                $scope.$apply(function(){
                    $scope.services = services;
                });
                var service_dict = {};
                $.each(services, function(idx, i) {
                    var temp_list = [];
                    sock.call("discovery.get_methods", [i], function(methods) {
                        for(var tmp = 0; tmp < methods.length; tmp++) {
                           temp_list.push(methods[tmp]);
                        }
                    service_dict[i] = temp_list;
                      $scope.$apply(function(){
                        $scope.service_dict = service_dict;
                      });
                    });
                });
            });
        };
    }
    $scope.getServiceList = function(service_name){
        $scope.current_methods = $scope.service_dict[service_name];
        $scope.current_service = service_name;
    }
}

function TaskDocController($scope, $location, $routeParams, $route, $rootScope){
    document.title = "Task API Page";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $scope.init = function() {
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")){
                $location.path('/login'+$route.current.$$route.originalPath);
            }
            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            $("#login_username").html($rootScope.username);
        };
        sock.onLogin = function() {
            sock.call("discovery.get_tasks", null, function (tasks) {
                var temp_list = [];
                $.each(tasks, function(task_name, i) {
                    temp_list.push(task_name);
                })
                $scope.$apply(function(){
                  $scope.services = temp_list;
                  $scope.task_dict = tasks;
                });
            });
        };
    }
    $scope.getTaskList = function(task_name) {
        $scope.current_methods = $scope.task_dict[task_name];
        $scope.current_service = task_name;
        $scope.schema_list = [];
        $scope.schema_list.push($scope.current_methods['schema']);
        $("#schema_pretty").html(JSON.stringify($scope.schema_list,null, 4));
    }
}

function EventsDocController($scope, $location, $routeParams, $route, $rootScope){
    document.title = "Events API Page";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $scope.init = function() {
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")){
                $location.path('/login'+$route.current.$$route.originalPath);
            }

            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            $("#login_username").html($rootScope.username);
        };
        sock.onLogin = function() {
            sock.call("discovery.get_event_types", null, function (events) {
                var temp_list = [];
                $.each(events, function(event_name, i) {
                    temp_list.push(event_name);
                })
                $scope.$apply(function(){
                  $scope.events = temp_list;
                  $scope.event_dict = events;
                });
            });
        };
    }
    $scope.getEvent = function(event_name) {
        $scope.current_service = event_name
        if ($scope.event_dict[event_name]['event_schema']!= undefined) {
            $("#schema_pretty").html(JSON.stringify($scope.event_dict[event_name]['event_schema'],null, 4))
        }else {
            $("#schema_pretty").html('No doc found');
        }
    }
}

function SchemaController($scope, $location, $routeParams, $route, $rootScope){
    document.title = "Schema API Page";
    var sock = new middleware.DispatcherClient(document.domain);
    sock.connect();
    $scope.init = function() {
        sock.onError = function(err) {
            try {
                $route.reload();
            } catch (e) {
                console.log(e);
                $("#socket_status ").attr("src", "/static/images/service_issue_diamond.png");
                $("#refresh_page_glyph").show();
            }
        };
        sock.onConnect = function() {
            if (!sessionStorage.getItem("freenas:username")){
                $location.path('/login'+$route.current.$$route.originalPath);
            }
            sock.login(
                sessionStorage.getItem("freenas:username"),
                sessionStorage.getItem("freenas:password")
            );
            $("#login_username").html($rootScope.username);
        };
        sock.onLogin = function() {
            sock.call("discovery.get_schema", null, function (tasks) {
                var temp_list = [];
                $.each(tasks['definitions'], function(task_name, i) {
                    temp_list.push(task_name);
                })
                $scope.$apply(function(){
                  $scope.services = temp_list;
                  $scope.task_dict = tasks['definitions'];
                });
            });
        };
    }
    $scope.getTaskList = function (task_name) {
        $scope.current_service = task_name;
        console.log($scope.task_dict[task_name]);
        $scope.current_methods = $scope.task_dict[task_name];
        if ($scope.task_dict[task_name] != undefined) {
            $("#schema_pretty").html(JSON.stringify($scope.task_dict[task_name],null,4));
        } else {
            $("#schema_pretty").html('No doc found');
        }
    }
}

function AprilFoolController($scope) {
    console.log("I said don't click");
    console.log("you just can't control yourself, don't you?");
    console.log("Congrats, you found him");
    console.log("This is ｼｬｷｰﾝ(Shakin),");
    console.log("my little alien kitten");
}
