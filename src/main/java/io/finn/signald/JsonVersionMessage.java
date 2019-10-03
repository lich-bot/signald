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
import io.finn.signald.BuildConfig;

public class JsonVersionMessage {
  public String name;
  public String version;
  public String branch;
  public String commit;

  public JsonVersionMessage() {
    this.name = BuildConfig.NAME;
    this.version = BuildConfig.VERSION;
    this.branch = BuildConfig.BRANCH;
    this.commit = BuildConfig.COMMIT;
  }

}
