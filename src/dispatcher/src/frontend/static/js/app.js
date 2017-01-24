'use strict';

/* App Module */

var DebuggerApp = angular.module('Debugger', [
  'angularModalService',
  'ngRoute',
  'ui.bootstrap',
  'ngCookies',
  'ngAnimate',
  'pascalprecht.translate'
]);

DebuggerApp.config(['$translateProvider', function ($translateProvider) {
  $locationProvider.html5Mode(true);
  $translateProvider.translations('en', {
    'TITLE': 'Hello',
    'FOO': 'This is a paragraph'
  });
 
  $translateProvider.translations('de', {
    'TITLE': 'Hallo',
    'FOO': 'Dies ist ein Absatz'
  });
 
  $translateProvider.preferredLanguage('en');
}]);


DebuggerApp.config(['$routeProvider', function($routeProvider) {
  $routeProvider.
    when('/', {
      templateUrl: '../static/partials/rpc.html',
      controller: RpcController
    }).
    when('/login',{
        templateUrl: '../static/partials/login.html',
        controller: LoginController
    }).
    when('/login/:nextRoute',{
        templateUrl: '../static/partials/login.html',
        controller: LoginController
    }).
    when('/rpc',{
      templateUrl: '../static/partials/rpc.html',
      controller: RpcController
    }).
    when('/term',{
      templateUrl: '../static/partials/term.html' ,
      controller: TermController
    }).
    when('/events',{
      templateUrl: '../static/partials/events.html',
      controller: EventsController
    }).
    when('/syslog',{
      templateUrl: '../static/partials/syslog.html',
      controller: SyslogController
    }).
    when('/stats', {
      templateUrl: '../static/partials/stats.html',
      controller: StatsController
    }).
    when('/tasks', {
      templateUrl: '../static/partials/tasks.html' ,
      controller: TasksController
    }).
    when('/filebrowser',{
      templateUrl: '../static/partials/filebrowser.html' ,
      controller: FileBrowserController
    }).
    when('/dispatcher_dumpstack',{
      templateUrl: '../static/partials/dispatcher_dumpstack.html',
      controller: DispatcherDumpstackController
    }).
    when('/apidocs/rpc', {
      templateUrl: '../static/partials/apidoc_rpc.html',
      controller: RPCdocController
    }).
    when('/apidocs/tasks', {
      templateUrl: '../static/partials/apidoc_tasks.html',
      controller: TaskDocController
    }).
    when('/apidocs/events', {
      templateUrl: '../static/partials/apidoc_events.html',
      controller: EventsDocController
    }).
    when('/apidocs/schema',{
      templateUrl: '../static/partials/apidoc_schema.html',
      controller: SchemaController
    }).
    when('/404',{
      templateUrl: '../static/partials/404.html',
      controller: Four04Controller
    }).
    when('/500', {
      templateUrl: '../static/partials/500.html',
      controller: Five00Controller
    }).
    when('/status/:status_code/',{
      templateUrl: '../static/partials/status.html',
      controller: HTTPStatusController
    }).
    when('/topsecret', {
      templateUrl: '../static/partials/apidocs.html',
      controller: AprilFoolController
    }).
    otherwise({redirectTo: '/'});
}]);


DebuggerApp.controller('ModalController',['$scope', '$element', 'close', function($scope, $element, close){
    $scope.username = null;
    $scope.password = null;
    //  This close function doesn't need to use jQuery or bootstrap, because
    //  the button has the 'data-dismiss' attribute.
    $scope.close = function() {
        close({
            username: $scope.username,
            password: $scope.password
        }, 500);
    };
    //
    $scope.hide = function() {
        //  Manually hide the modal.
        $element.modal('hide');

        //  Now call close, returning control to the caller.
        close({
            username: $scope.username,
            password: $scope.password
        }, 500); // close, but give 500ms for bootstrap to animate
    };
}]);
