/**
 * @file
 * @author  Tomas Ingram <tomingram87@hotmail.co.uk>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * https://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * The Datum.Auth module defines methods for authentication and authorisation
 */

var Datum = (function (datum, window, document, undefined) {
  "use strict";

  var auth = {};

  var login = function (username, password) {
    fetch("https://localhost:8888/login", {
    	method: "post",
      headers: {
        "authorization": "basic " + btoa(username + ":" + password),
        "content-type": "application/x-www-form-urlencoded"
        //"x-xsrf-token": cookies.xsrfid,
      },
    }).then(function(response) {
    	console.log(response);
    }).catch(function(err) {
    	console.log(err);
    });
  };

  var authenticated = function () {
    fetch("https://localhost:8888/authenticated", {
      method: "post",
      credentials: "same-origin"
    }).then(function(response) {
      console.log(response);
    }).catch(function(err) {
      console.log(err);
    });
  };

  var logout = function () {
    fetch("https://localhost:8888/logout", {
    	method: "get",
      credentials: "same-origin"
    }).then(function(response) {
    	console.log(response);
    }).catch(function(err) {
    	console.log(err);
    });
  };

  Object.defineProperty(auth, "login", {
    value: login,
    writable: false
  });

  Object.defineProperty(auth, "authenticated", {
    value: authenticated,
    writable: false
  });

  Object.defineProperty(auth, "logout", {
    value: logout,
    writable: false
  });

  Object.defineProperty(datum, "Auth", {
    value: auth,
    writable: false
  });

  return datum;

}(Datum || {}, window, document));
