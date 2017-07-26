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
 * The Datum namespace loads all other modules
 */

var Datum = (function (datum, window, document, undefined) {
  "use strict";

  const modules = ['auth','core','flow','plot','stat','view'];

  for (var i=0, len=modules.length; i < len; i++) {
    var element = document.createElement('script');
    element.setAttribute('type','text/javascript');
    element.setAttribute('src','/js/datum-'+modules[i]+'.js');
    document.getElementsByTagName('head')[0].appendChild(element);
  }

  return datum;

})(Datum || {}, window, document)
