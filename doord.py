#!/usr/bin/python3
# doord
# connects to a local civi instance so that an internet outage
# won't prevent anyone from entering. Using sql calls wherever
# possible for speed.
#
# IMPORTANT: adjust myqsl server config to have a sizable timeout
# otherwise application conncition will drop.
# wait_timeout = 604800
# interactive_timeout = 14400

import sys,os
import re
import MySQLdb
import MySQLdb.cursors
import configparser
import json
import time
import arpreq
from flask import Flask, request, url_for, abort
from pythoncivicrm import CiviCRM
from pythoncivicrm import CivicrmError
import urllib3.contrib.pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()
from slacker import Slacker

config = configparser.ConfigParser()
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
config.read(os.path.join(__location__, 'doord-secrets.conf'))
civicrm_url = config.get('civi-connect', 'url')
civicrm_site_key = config.get('civi-connect', 'site_key')
civicrm_api_key = config.get('civi-connect', 'api_key')
slack = Slacker(config.get('slack', 'slackapi'))
doord_host = config.get('doord', 'host')
doord_port= config.get('doord', 'port')

hostname = config.get('dbconnect', 'host')
username = config.get('dbconnect', 'user')
password = config.get('dbconnect', 'passwd')
database  = config.get('dbconnect', 'db')

api_key = config.get('mstk', 'api_key')

db = MySQLdb.connect(host=hostname, # your host, usually localhost
user=username, # your username
passwd=password, # your password
db=database) # name of the data base
db.autocommit(True)
cur = db.cursor(MySQLdb.cursors.DictCursor)

slack_enabled = True 
api_key_enabled = False

civicrm = CiviCRM(civicrm_url, civicrm_site_key, civicrm_api_key, use_ssl=False, timeout=10 )

# Initialize the Flask application
app = Flask(__name__)
#app.config['DEBUG'] = True
app.config.update(
    JSONIFY_PRETTYPRINT_REGULAR=False
)

daemon = os.path.basename(__file__).rstrip(".py")

# this log is also used for slack and it's #doorbot channel
accesslogfile = ('/var/log/%s.access.log' % daemon)
open(accesslogfile,'a').close()
# this log is for any bs we may encounter, unauthorized APs etc
activity_logfile = ('/var/log/%s.activity.log' % daemon) 
open(activity_logfile, 'a').close()

# relevent for ap_lookup function
context = os.path.basename(__file__)

log_level = 5

def debug_message(current_log_level, message_level, message):
    timestamp = time.strftime('%Y%m%d_%H:%M:%S')
    if message_level <= current_log_level:
       print("%s - %s" % (timestamp, message))
       logfile = open(activity_logfile, "a");
       logfile.write("%s - %s" % (timestamp, message))
       logfile.write("\n")
       logfile.close()



def logsearch(entrydate, entryname, statuscode):
   today = time.strftime("%m/%d/%Y")
   currenttime  = time.strftime("%H:%M:%S")
   datevalue = None
   for dates in open(accesslogfile,encoding="latin-1"):
      namevalue = None
      if entrydate in dates:
         datevalue = 1
         for names in dates.splitlines():
            if entryname in names:
               namevalue = 1
               #print ('the name %s is found' % entryname )
               return
   else:
      if not datevalue or not namevalue:
          loglist = [entrydate,currenttime,entryname,statuscode]
          logline = str(loglist).replace('[','').replace(']','').replace("'","")
          if slack_enabled:
             slack.chat.post_message('#doorbot', logline, as_user=False)


def ap_success(dev,cmd):
   try:
      f = open("/dev/%s" % dev, "w");
      f.write("%s\n" % cmd)
      f.close()
   except:
      debug_message(log_level,0, "non-existant access control device /dev/%s" % str(dev))



'''
    Retreive user's memeber status. Returns bool
'''

def membership_check(contact_id):
    membership_status = 0
    search_dict = {
                  "contact_id":contact_id,
                  "sort":"status_id ASC",
                  }
    try:
       cur.execute("SELECT * FROM civicrm_membership WHERE contact_id = %s ORDER BY status_id ASC", (contact_id,))
       member = cur.fetchone()
       # map CiviCRM member states to boolean
       membership_status = 0 if int(member['status_id']) >= 3 else 1
    except:
       # no member record
       return 0

    return membership_status

'''
    card_lookup returns a dictionary of user info
'''
def card_lookup (card_number, **access_point):
   clientip = request.environ['REMOTE_ADDR']
   # set some defaults
   member_status = 0
   contact_id = 0
   if not cur.execute("SELECT * FROM civicrm_accesscard_cards WHERE card_id = %s", (card_number,)):
      today = time.strftime("%m/%d/%Y")
      currenttime  = time.strftime("%H:%M:%S")
      logfile = open(accesslogfile, "a");
      logfile.write("%s,%s,unknowncard-%s,0\n" % (str(today), str(currenttime), str(card_number)))
      logfile.close()
      debug_message(log_level,0, "unknown card id %s at accesspoint %s" % (card_number, access_point['id']))
      display_name = "Unknown Card"
      access = 0
      error_code = "x80"
      user_dict = {
                  "display_name":str(display_name),
                  "contact_id":str(contact_id),
                  "access_point":str(access_point['id']),
                  "access":str(access),
                  "member_status":str(member_status),
                  "error_code":str(error_code)
                  }
      print ("unknown card id")
      return user_dict
   else:
      card_record = cur.fetchone()
      contact_id = card_record['contact_id']
      #print('contact id is %s' % contact_id)
      cur.execute("SELECT * FROM civicrm_contact WHERE id = %s", (contact_id,))
      contact = cur.fetchone()
      #print(json.dumps(contact))
      member_status = membership_check(contact_id)
      print('member status is %s' % member_status)
      display_name= contact['display_name']
      today = time.strftime("%m/%d/%Y")
      currenttime  = time.strftime("%H:%M:%S")
      debug_message(log_level, 3, "member status for %s is %s" % (contact_id,member_status))
      access = acl_check("UserAcls",contact_id,**access_point)
      print("access is %s" % access)
      if access == 1 and member_status == 1:
         logsearch(today,display_name,1)
         logfile = open(accesslogfile, "a");
         logfile.write("%s,%s,%s,1\n" % (str(today), str(currenttime), str(display_name)))
         logfile.close()
         error_code = "x00"
         user_dict = {
           "display_name":str(display_name),
           "contact_id":str(contact_id),
           "access_point":str(access_point['id']),
           "access":str(access),
           "member_status":str(member_status),
           "error_code":str(error_code)
         }
         return user_dict
      else:
         logsearch(today,display_name,0)
         logfile = open(accesslogfile, "a");
         logfile.write("%s,%s,%s,0\n" % (str(today), str(currenttime), str(display_name)))
         logfile.close()
         access = 0 
         error_code = "x01"
         user_dict = {
           "display_name":str(display_name),
           "contact_id":str(contact_id),
           "access_point":str(access_point['id']),
           "access":str(access),
           "member_status":str(member_status),
           "error_code":str(error_code)
         }
         return user_dict

'''
   Fucnction to check if contact has requested permission. Accepts contact id and door Id. Returns bool.
'''

def acl_check(entity,iD,**access_point):
   # returns bool. this is where we check permissions
   # order is useracl for AP, useracl for parent APs,
   # groupacls for AP, groupacls for parent APs.
   aco_record = {}

   if entity == "UserAcls":
      search_param = 'contact_id'
      search_table = 'civicrm_mstk_user_acls'
   elif entity == "GroupAcls":
      search_param = "group_id"
      search_table = "civicrm_mstk_group_acls"
   print('in acl_check, ap is %s, iD is %s and entity is %s' % (access_point['id'],iD,entity))
   select_query ="""SELECT * FROM  %s WHERE aco = %s AND %s = %%s;""" % (search_table,access_point['id'], search_param)
   if cur.execute(select_query,(iD,)):
      aco_record = cur.fetchone()
      #print('aco record is %s' % aco_record)
      print('acl status is %s' % aco_record['status_id'])
      if int(aco_record['status_id']) > 1:
         print('revoked or expired')
         return 0 
      elif int(aco_record['status_id']) == 1:
         print('direct acl found and active')
         return 1

   else:
      print("no direct %s" % entity )
      pass

   # no match yet, let's see if the ap has a parent where an acl exists.

   ap_parent_id = access_point['parent_id']
   print('ap_parent_id is %s' % ap_parent_id)
   if ap_parent_id:
      print("ap parent id is %s"  % ap_parent_id)
      cur.execute("SELECT * FROM civicrm_mstk_access_points WHERE id = %s", (ap_parent_id,))
      parent_access_point = cur.fetchone()
     # infinite recursion \o/
      access = acl_check(entity,iD,**parent_access_point)
      if str(access) == "1":
        return 1
   else:
      print("no parent aps for aco %s"  % access_point)
      pass

   print('access point should not be parent, it is %s' % access_point)

   # no match yet, let's move on to groupacls. First find what groups user belongs to.
   # there's no way to directly find smart group membership. so we're getting all groups
   # with Contact api

   if entity == "UserAcls":
      search_dict = {
          "id":str(iD),
           "return":"group",
      }
      try:
         search_results = civicrm.get("Contact", **search_dict)
         print(json.dumps(search_results))
         groups_string = search_results[0]['groups']
         groups = groups_string.split(",")
         # ouch, to give precedence to child groups we have to figure our relationships first.
         # get the whole list of gids, order the list and process.
         for group_title in groups:
            print('group title is %s' % group_title)
            cur.execute("SELECT * FROM civicrm_group  WHERE title = %s", (group_title,))
            gid_search = cur.fetchone()
            gid = gid_search['id']
            print('gid is %s' % gid)
            access = acl_check("GroupAcls",gid,**access_point)
            if str(access) == "1":
               print('group acl is good')
               return 1
            else:

               # check for parent group
               if cur.execute("SELECT * FROM civicrm_group_nesting  WHERE child_group_id = %s", (gid,)):
                  parent_search = cur.fetchone()
                  print('parent civi group id is %s' % parent_search['parent_group_id'])
                  # more recursion
                  access = acl_check("GroupAcls",parent_search['parent_group_id'],**access_point)
                  if str(access) == "1":
                     print('civi parent group %s match with ap %s' % (parent_search['parent_group_id'],access_point['id']))
                     return 1
               else:
                  print('no parent groups found')
                  pass
      except:
         #no direct groups
         return 0

      return 0

'''
ap_lookup returns a dictionary of ap info appending an error code.
this authenticates the user as well as the machine against the mstk
access points in our db.

'''
def ap_lookup(client_ip, context):
   requesting_mac = arpreq.arpreq(client_ip) 
   if not cur.execute("SELECT * FROM civicrm_mstk_access_points WHERE mac_address = %s", (requesting_mac,)):
      debug_message(log_level, 0, "UNAUTHORIZED AP REQUEST: by ip address %s with mac address %s" % (client_ip, requesting_mac))
      return {'error_code' :'x10'}
   else:
      requesting_ap = cur.fetchone()
      #print('requesting ap is %s' % requesting_ap)
      if not requesting_ap['dev'] or not requesting_ap['cmd']:
         debug_message(log_level,0, "misconfigured accesspoint %s" % str(requesting_ap['id']))
         error_code = 'x30' 
         requesting_ap.update({
            "error_code":str(error_code)
         })
         return requesting_ap

   if requesting_ap['ip_address'] == client_ip:
      # Ok, this is a legit ap.
      if str(requesting_ap['maintenance_mode']) == "1":
         error_code = 'x20' 
         requesting_ap.update({
           "error_code":str(error_code)
         })
      else:
         # keeping it agnostic to use this function in doord and machinetimed if this
         # goes into a shared module
         if re.search('doord',context):
            try:
               requesting_ap['dev']
               requesting_ap['cmd']
            except:
               debug_message(log_level,0, "misconfigured accesspoint %s" % str(requesting_ap['id']))
               error_code = 'x30'
               requesting_ap.update({
                  "error_code":str(error_code)
               })
               return requesting_ap
         try:
            requesting_ap.update({
               "parent_ap":str(requesting_ap['parent_id'])
            })
         except:
            # no parent
            pass

         error_code = 'x00'
         requesting_ap.update({
           "error_code":str(error_code)
         })

      return requesting_ap
   else:
      debug_message(log_level, 0, "UNAUTHORIZED AP REQUEST: ip/mac don't agree. ip %s, mac %s" % (client_ip, requesting_mac))
      return {'error_code' :'x10'}


@app.route('/login', methods = ['GET', 'POST'])
def accept_card_uid():
   if request.method == 'POST':
      if api_key_enabled:
         try:
            received_apikey = request.form['apikey']
            if received_apikey != apikey:
               abort(404)
               return str(404)
            else:
               print('api key is %s' % received_apikey)
         except:
            abort(404)
            return str(404)
       # Find the requesting AP.
      client_ip = request.environ['REMOTE_ADDR']
      ap_auth = ap_lookup(client_ip,context)
      #print('ap auth is %s' % ap_auth)

      # doord can be terse about errors becuase doors generally don't have UIs.
      # And we wouldn't want to leak info about denied attempts anyway, unless it was
      # to say that memeber dues failed to process.
      if str(ap_auth['error_code']) != 'x00':
         return str('{"access":"0"}')

      card_serial = (request.form['uuid'])
      #print('type of card_serial is %s' % type(card_serial))
      #print(' accesspoint_id is %s and card_serial is %s' % (ap_auth['id'], card_serial))
      if len(card_serial) ==  10 or  8:
         access_request = card_lookup(card_serial,**ap_auth)
         # print("access_request members status is %s" % access_request['member_status'])
         if access_request['member_status'] == "1" and access_request['access'] == "1":
            # make the stuff happen
            ap_success(ap_auth['dev'],ap_auth['cmd'])
            return str('{"access":"1"}')
         else:
            return str('{"access":"0"}')

      else:
         print ("wrong number of characters")
         print (card_serial)
         return str('{"access":"0"}')
   else:
       return str('{"status":"1"}')



if __name__ == '__main__':
  app.run(
        host=doord_host,
        port=int(doord_port)
  )


