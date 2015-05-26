#!/usr/bin/python

from pprint import pprint
from UcsSdk import *
from UcsSdk.MoMeta.EquipmentPsu import EquipmentPsu

if __name__ == "__main__":
   try:
      handle = UcsHandle()
      IP = raw_input("FI IP address: ")
      username = raw_input("Username: ")
      import getpass
      password = getpass.getpass("Password: ")

      handle = UcsHandle()
      handle.Login(IP, username, password)
      for psu in handle.GetManagedObject(None, EquipmentPsu.ClassId()):
          if ("sys/switch" in psu.Dn) and ("UCS-PSU-6296UP-AC" in psu.Model):
             if "-A0" in psu.Revision:
                 print "Please contact Cisco TAC.  The PSU in " + psu.Dn + \
                       " needs to be replaced per FN63894.  More information can be found here:\n" +  \
                       "http://www.cisco.com/c/en/us/support/docs/field-notices/638/fn63894.html"
             elif ("-B0" in psu.Revision) and ("UCS-PSU-6296UP-AC" in psu.Model):
                 print "Please contact Cisco TAC.  The PSU in " + psu.Dn + \
                       " needs to be replaced per FN63894.  More information can be found here:\n" + \
                       "http://www.cisco.com/c/en/us/support/docs/field-notices/638/fn63894.html"
             else:
                print "Thepower supply in " + psu.Dn + " is not affected by FN63894."
      handle.Logout()

   except Exception, err:
      print "Exception:", str(err)
      import traceback, sys
      print '-'*60
      traceback.print_exc(file=sys.stdout)
      print '-'*60
      handle.Logout()
