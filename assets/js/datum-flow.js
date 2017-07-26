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
 * The Datum.Flow module defines methods for data processing
 */

var Datum = (function (datum, window, document, undefined) {
  "use strict";

  var flow = {};

  Object.defineProperty(datum, "Flow", {
    value: flow,
    writable: false
  });

  return datum;

}(Datum || {}, window, document));
