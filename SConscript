#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.
import os

Import('env')

env.Replace(debug=ARGUMENTS.get("debug",0))
env.Append(CFLAGS=" -DUSE_ELFIO ")
env.Append(CXXFLAGS=" -DUSE_ELFIO ")
if int(env['debug']) == 1:
        print "Setting debug mode"
        env.Append(CFLAGS=" -g ")
        env.Append(CXXFLAGS=" -g ")
        env.Append(LINKFLAGS=" -g ")
else:
        print "Setting release mode"
        env.Append(CFLAGS=" -O3 ")
        env.Append(CXXFLAGS=" -O3 ")
        env.Append(LINKFLAGS=" -O3 ")


lib=SConscript("src/SConscript")

Return('lib')

