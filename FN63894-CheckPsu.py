#!/usr/bin/python
#
# Check for FN63894 PSU issue on 6296 Fabric Interconnects
#
# Copyright 2015 Rusty Buzhardt and Tighe Kuykendall
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
# May 26, 2015
# Initial release.
#
# June 3, 2015
# Updated check for Part Number per the revised Field Notice.
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

    suspect_psu=0
    good_psu=0
    unknown_psu=0
    non_6296=0

    print "Checking..."
    for psu in handle.GetManagedObject(None, EquipmentPsu.ClassId()):
        if ("sys/switch" in psu.Dn) and ("UCS-PSU-6296UP-AC" in psu.Model):
          if "341-0495-01" in psu.PartNumber:
            print "341-0495-01 " + psu.Dn + psu.PartNumber + psu.Revision
            if "C" not in psu.Revision:
              print "Please contact Cisco TAC.  The PSU in " + psu.Dn + \
                    " is Part Number 341-0495-01 and needs to be replaced per FN63894.  "
              suspect_psu += 1
            elif "C" in psu.Revision:
              print "The PSU in " + psu.Dn + \
                    " is Part Number 341-0495-01 Revision \"C\" and not impacted by FN63894."
              good_psu += 1
          elif "341-0523-01" in psu.PartNumber:
            print "341-0523-01 " + psu.Dn + psu.PartNumber + psu.Revision
            print "The PSU in " + psu.Dn + \
                  " is Part Number 341-0523-01 and not impacted by FN63894."
            good_psu += 1
          else:
            print "The PSU in " + psu.Dn + " can not be evaluated by Part Number." + \
                  " Please check manually."
            unknown_psu += 1
        elif ("sys/switch" in psu.Dn) and ("UCS-PSU-6296UP-AC" not in psu.Model):
            print ".",
            non_6296 += 1
    print "Done"
    print ""
    print "Found the following about your UCS Domain"
    print ""
    print "PSU's impaced by FN63894: " + str(suspect_psu)
    print "PSU's not impacted by FN63894: " + str(good_psu)
    print "PSU's not evaluated due to no Revision information: " + str(unknown_psu)
    print "Non UCS-PSU-6296UP-AC PSU's: " + str(non_6296)
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
