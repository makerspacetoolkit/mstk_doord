#!/usr/bin/python3
# doord
# connects to a local civi instance so that an internet outage
# won't prevent anyone from entering. Using sql calls wherever
# possible for speed.
#

import os
import pythonmstk
import configparser
import json
import time
from flask import Flask, request, url_for, abort
import urllib3.contrib.pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()

secrets_file = 'doord-secrets.conf'

config = configparser.ConfigParser()
secrets_path = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
config.read(os.path.join(secrets_path, secrets_file))

doord_host = config.get('doord', 'host')
doord_port= config.get('doord', 'port')
api_key_enabled = config.get('doord','api_key_enabled')
api_key = config.get('doord', 'api_key')


# Initialize the Flask application
app = Flask(__name__)
#app.config['DEBUG'] = True
app.config.update(
    JSONIFY_PRETTYPRINT_REGULAR=False
)

class Doord(pythonmstk.MstkServer):

   def ap_success(self,dev,cmd):
      try:
         f = open("/dev/%s" % dev, "w");
         f.write("%s\n" % cmd)
         f.close()
      except:
         self.debug_message(log_level,0, "non-existant access control device /dev/%s" % str(dev))

doord  =  Doord(secrets_path,secrets_file)

@app.route('/login', methods = ['GET', 'POST'])
def accept_card_uid():
   if request.method == 'POST':
      if api_key_enabled == 'True':
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
      access_point = doord.ap_lookup(client_ip)
      # make sure there are door controller commands to run
      try:
         access_point['dev']
         access_point['cmd']
      except:
         debug_message(log_level,0, "misconfigured accesspoint %s" % str(access_pointp['id']))
         error_code = 'x30'
         requesting_ap.update({
            "error_code":str(error_code)
         })
         return requesting_ap

      # doord can be terse about errors because doors generally don't have UIs.
      # And we wouldn't want to leak info about denied attempts anyway, unless it was
      # to say that memeber dues failed to process.
      if str(access_point['error_code']) != 'x00':
         return str('{"access":"0"}')

      card_serial = (request.form['uuid'])
      #print('type of card_serial is %s' % type(card_serial))
      #print(' accesspoint_id is %s and card_serial is %s' % (access_point['id'], card_serial))
      if len(card_serial) ==  10 or  8:
         access_request = doord.card_lookup(card_serial,**access_point)
         # print("access_request members status is %s" % access_request['member_status'])
         if access_request['member_status'] == "1" and access_request['access'] == "1":
            # make the stuff happen
            doord.ap_success(access_point['dev'],access_point['cmd'])
         else:
            return str('{"access":"0"}')
         today = time.strftime("%m/%d/%Y")
         currenttime  = time.strftime("%H:%M:%S")
         if access_request['display_name'] != "Unknown Card":
            doord.logsearch(today,access_request['display_name'],access_request['access'],doord.slack_channel)
            logfile = open(doord.accesslogfile, "a");
            logfile.write("%s,%s,%s,%s\n" % (str(today), str(currenttime), str(access_request['display_name']), access_request['access']))
            logfile.close()
         else:
            # send to private card_reader slack channel to help admin provision cards
            pass
         return str('{"access":"%s"}' % access_request['access'])

      else:
         print ("wrong number of characters")
         print (card_serial)
         return str('{"access":"0"}')
   else:
       # GET request for door client heartbeat
       return str('{"status":"1"}')



if __name__ == '__main__':
  app.run(
        host=str(doord_host),
        port=int(doord_port)
  )


