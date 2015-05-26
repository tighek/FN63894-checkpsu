#!/usr/bin/python
#
# Check for FN63894 PSU issue on 6296 Fabric Interconnects
#
# Copyright 2015 Rusty Buzhardt
#
# Licensed under the Apache License, Version 2.0 (the "License") available
# at  http://www.apache.org/licenses/LICENSE-2.0.  You may not use this
# script except in compliance with the License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Usage:  FN63894-CheckPsu.py [options]
# -h, --help                          Show this help information and exit.
# -i IP, --ip=IP                      UCSM IP Address
# -u Username, --username=Username    Read Only User Name
# -p Password, --password=Password    Password for Read Only Username
#

from pprint import pprint
from UcsSdk import *
from UcsSdk.MoMeta.EquipmentPsu import EquipmentPsu
import getpass
import optparse
import platform

def getpassword(prompt):
  if platform.system() == "Linux":
    return getpass.unix_getpass(prompt=prompt)
  elif platform.system() == "Windows" or platform.system() == "Microsoft":
    return getpass.win_getpass(prompt=prompt)
  elif platform.system() == "Macintosh":
    return getpass.unix_getpass(prompt=prompt)
  else:
    return getpass.getpass(prompt=prompt)

if __name__ == "__main__":
  try:

    parser = optparse.OptionParser()
    parser.add_option('-i', '--ip', dest="ip", help="UCSM IP Address")
    parser.add_option('-u', '--username', dest="userName", help="Read Only Username For UCS Manager")
    parser.add_option('-p', '--password', dest="password", help="Read Only Password For UCS Manager")
    (options, args) = parser.parse_args()

    # Check for a command line FI IP, if not prompt for it.

    print ""
    print "Check for: FN63894 UCS-PSU-6296UP-AC PSU Silent Reload"
    print ""

    if options.ip:
      print "Connecting to UCS Manager at address " + options.ip
    elif not options.ip:
      options.ip = raw_input("UCS Manager IP Address: ")

    # Check for a command line username, if not prompt for it.

    if options.userName:
      print "Logging in as " + options.userName
    elif not options.userName:
      options.userName = raw_input("UCS Manager Read Only Username: ")

    # Check for a command line password, if not prompt for it.

    if options.password:
      print "Thanks for providing the password."
    elif not options.password:
      options.password = getpassword("UCS Manager Password: ")

    handle = UcsHandle()
    handle.Login(options.ip, options.userName, options.password)

      # Check for the effected PSU.

    print "Checking..."
    for psu in handle.GetManagedObject(None, EquipmentPsu.ClassId()):
        if ("sys/switch" in psu.Dn) and ("UCS-PSU-6296UP-AC" in psu.Model):
           if "-A0" in psu.Revision:
               print "Please contact Cisco TAC.  The PSU in " + psu.Dn + \
                     " needs to be replaced per FN63894.  "
           elif ("-B0" in psu.Revision) and ("UCS-PSU-6296UP-AC" in psu.Model):
               print "Please contact Cisco TAC.  The PSU in " + psu.Dn + \
                     " needs to be replaced per FN63894."
           else:
              print "Thepower supply in " + psu.Dn + " is not affected by FN63894."
        else:
            print ".",
    print "Done"
    print ""
    print "If you have a PSU effected by FN63894, More information can be found here:\n"
    print "http://www.cisco.com/c/en/us/support/docs/field-notices/638/fn63894.html"
    print ""
    print ""

    handle.Logout()

  except Exception, err:
    print "Exception:", str(err)
    import traceback, sys
    print '-'*60
    traceback.print_exc(file=sys.stdout)
    print '-'*60
    handle.Logout()
