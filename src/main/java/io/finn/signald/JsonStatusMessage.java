/**
 * Copyright (C) 2018 Finn Herzfeld
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.finn.signald;

public class JsonStatusMessage {
  public int msg_number;
  public String message;
  public boolean error;
  public JsonRequest request;

  public JsonStatusMessage(int msgNumber, String message) {
    this.msg_number = msgNumber;
    this.message = message;
    this.error = false;
  }

  public JsonStatusMessage(int msgNumber, String message, JsonRequest request) {
    this.msg_number = msgNumber;
    this.message = message;
    this.error = true;
    this.request = request;
  }
}
