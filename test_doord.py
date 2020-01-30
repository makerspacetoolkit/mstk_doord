#!/usr/bin/python3

import unittest
import doord 
import os
import inspect
import configparser
from pythoncivicrm import CiviCRM 
from pythoncivicrm import CivicrmError
import requests
import arpreq

import json

config = configparser.ConfigParser()
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
config.read(os.path.join(__location__, 'doord-secrets.conf'))
civicrm_url = config.get('civi-connect', 'url')
civicrm_site_key = config.get('civi-connect', 'site_key')
civicrm_api_key = config.get('civi-connect', 'api_key')
civicrm = CiviCRM(civicrm_url, civicrm_site_key, civicrm_api_key, use_ssl=False, timeout=10 )
ap_ip = config.get('doord','host')
# during testing the server host and "ap" share an ip address
host = ap_ip
port = config.get('doord','port')
ap_mac =  arpreq.arpreq(ap_ip)

class TestACLs(unittest.TestCase):
   
   @classmethod
   def setUpClass(cls):
      contact_dict = {
        "first_name":"Testy",
       "last_name":"McTesterson",
        "contact_type":"Individual"
      }
      membership_type_dict = {
        "domain_id": "Fat Cat Fab Lab",
        "member_of_contact_id": "1",
        "financial_type_id": "Member Dues",
        "duration_unit": "month",
        "duration_interval": "1",
        "period_type": "rolling",
        "name": "membership_test_type"
      }
      parent_ap_dict = {
        "ap_name":"DoorsGroup",
        "ap_short_name": "DoorGroup",
        "maintenance_mode": 0
      }
      cls.civi_contact = civicrm.create('Contact', **contact_dict)
      cls.contact_id = cls.civi_contact[0]['id']
      cls.civi_parent_group = civicrm.create('Group', **{'title':'test_admin_group'})
      cls.pgid = cls.civi_parent_group[0]['id']
      cls.civi_group = civicrm.create('Group', **{'title':'test_event_admin_group','parents':str(cls.pgid)})
      cls.gid = cls.civi_group[0]['id']
      cls.membership_type = civicrm.create('MembershipType', **membership_type_dict)
      cls.mem_type_id =cls.membership_type[0]['id']
      membership_dict = {
        "contact_id":cls.contact_id,
        "membership_type":cls.mem_type_id,
        "is_override": "1",
        "status_id":"Current"
      }
      cls.membership = civicrm.create('Membership', **membership_dict)
      cls.mem_id = cls.membership[0]['id']
      cls.card = civicrm.create('Cards', **{'contact_id':cls.contact_id,'card_id':'31415927'})
      cls.parent_ap = civicrm.create('AccessPoints', **parent_ap_dict)
      cls.parent_ap_id = cls.parent_ap[0]['id']
      ap_dict = {
        "ap_name":"Test Main Door",
        "ap_short_name": "TMD",
        "ip_address": str(ap_ip),
        "mac_address": str(ap_mac),
        "dev": "ttyACM0",
        "cmd": "1",
        "parent_id":str(cls.parent_ap_id),
        "maintenance_mode": 0
      }
      cls.ap = civicrm.create('AccessPoints', **ap_dict,)
      cls.ap_id = cls.ap[0]['id']
      print('setupClass')
      print ('membership id is %s and status is %s' % (cls.mem_id, cls.membership[0]['status_id']))

   @classmethod
   def tearDownClass(cls):
      civicrm.delete('AccessPoints', cls.ap_id)
      civicrm.delete('AccessPoints', cls.parent_ap_id)
      civicrm.delete('Cards', cls.card[0]['id'])
      civicrm.delete('Membership', cls.membership[0]['id'])
      civicrm.delete('MembershipType', cls.mem_type_id)
      civicrm.delete('Group', cls.civi_group[0]['id'])
      civicrm.delete('Group', cls.pgid)
      civicrm.delete('Contact', cls.civi_contact[0]['id'])
      print('tearDownClass')

   def setUp(self):
      print('setUp')
      pass


   def tearDown(self):
      print('tearDown')
      pass
    
   def test_user_to_requested_ap(self):
      print(inspect.currentframe().f_code.co_name)
      acl_dict = {
        'aco':self.ap_id,
        'contact_id':self.contact_id,
        'status_id':'1'
      }
      self.user_acl = civicrm.create('UserAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('UserAcls', self.user_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"1"}')
      response = requests.post(url, data = {'uuid':'31415927'})
      self.assertEqual(response.text,'{"access":"0"}')
    
   def test_user_to_requested_ap_revoked(self):
      print(inspect.currentframe().f_code.co_name)
      acl_dict = {}
      acl_dict = {
        "aco":self.ap_id,
        "contact_id":self.contact_id,
        "status_id":"3"
      }
      self.user_acl = civicrm.create('UserAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('UserAcls', self.user_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"0"}')
   
   def test_user_to_parent_of_requested_ap(self):
      print(inspect.currentframe().f_code.co_name)
      acl_dict = {
        'aco':self.parent_ap_id,
        'contact_id':self.contact_id,
        'status_id':'1'
      }
      self.user_acl = civicrm.create('UserAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('UserAcls', self.user_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"1"}')
      response = requests.post(url, data = {'uuid':'31415927'})
      self.assertEqual(response.text,'{"access":"0"}')
    
   def test_user_to_parent_of_requested_ap_revoked(self):
      print(inspect.currentframe().f_code.co_name)
      acl_dict = {
        'aco':self.parent_ap_id,
        'contact_id':self.contact_id,
        'status_id':'3'
      }
      self.user_acl = civicrm.create('UserAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('UserAcls', self.user_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"0"}')
    
   def test_user_group_to_requested_ap(self):
      print(inspect.currentframe().f_code.co_name)
      group_contact = civicrm.create("GroupContact", **{"group_id":self.gid,"contact_id":self.contact_id})
      acl_dict = {
        'aco':self.ap_id,
        'group_id':self.gid,
        'status_id':'1'
      }
      self.group_acl = civicrm.create('GroupAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('GroupAcls', self.group_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"1"}')
      response = requests.post(url, data = {'uuid':'31415927'})
      self.assertEqual(response.text,'{"access":"0"}')
    
   def test_user_group_to_requested_ap_revoked_useracl(self):
      print(inspect.currentframe().f_code.co_name)
      group_contact = civicrm.create("GroupContact", **{"group_id":self.gid,"contact_id":self.contact_id})
      acl_dict = {
        'aco':self.ap_id,
        'group_id':self.gid,
        'status_id':'1'
      }
      self.group_acl = civicrm.create('GroupAcls', **acl_dict)
      acl_dict = {
        'aco':self.ap_id,
        'contact_id':self.contact_id,
        'status_id':'3'
      }
      self.user_acl = civicrm.create('UserAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('GroupAcls', self.group_acl[0]['id'])
      civicrm.delete('UserAcls', self.user_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"0"}')
    
   def test_user_group_to_parent_of_requested_ap(self):
      print(inspect.currentframe().f_code.co_name)
      group_contact = civicrm.create("GroupContact", **{"group_id":self.gid,"contact_id":self.contact_id})
      acl_dict = {
        'aco':self.parent_ap_id,
        'group_id':self.gid,
        'status_id':'1'
      }
      self.group_acl = civicrm.create('GroupAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('GroupAcls', self.group_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"1"}')
      response = requests.post(url, data = {'uuid':'31415927'})
      self.assertEqual(response.text,'{"access":"0"}')
    
   def test_user_parent_group_to_requested_ap(self):
      print(inspect.currentframe().f_code.co_name)
      group_contact = civicrm.create("GroupContact", **{"group_id":self.gid,"contact_id":self.contact_id})
      acl_dict = {
        'aco':self.ap_id,
        'group_id':self.pgid,
        'status_id':'1'
      }
      self.group_acl = civicrm.create('GroupAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('GroupAcls', self.group_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"1"}')
      response = requests.post(url, data = {'uuid':'31415927'})
      self.assertEqual(response.text,'{"access":"0"}')
   @unittest.skip("not ready yet")   
   def test_user_parent_group_and_revoked_child_group_to_requested_ap(self):
      print(inspect.currentframe().f_code.co_name)
      group_contact = civicrm.create("GroupContact", **{"group_id":self.gid,"contact_id":self.contact_id})
      group_contact = civicrm.create("GroupContact", **{"group_id":self.pgid,"contact_id":self.contact_id})
      acl_dict = {
        'aco':self.ap_id,
        'group_id':self.pgid,
        'status_id':'1'
      }
      self.parent_group_acl = civicrm.create('GroupAcls', **acl_dict)
      acl_dict = {
        'aco':self.ap_id,
        'group_id':self.gid,
        'status_id':'3'
      }
      self.child_group_acl = civicrm.create('GroupAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('GroupAcls', self.parent_group_acl[0]['id'])
      civicrm.delete('GroupAcls', self.child_group_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"0"}')
    
   def test_user_parent_group_to_parent_of_requested_ap(self):
      print(inspect.currentframe().f_code.co_name)
      group_contact = civicrm.create("GroupContact", **{"group_id":self.gid,"contact_id":self.contact_id})
      acl_dict = {
        'aco':self.parent_ap_id,
        'group_id':self.pgid,
        'status_id':'1'
      }
      self.group_acl = civicrm.create('GroupAcls', **acl_dict)
      url = ("http://%s:%s/login" % (host,port))
      response = requests.post(url, data = {'uuid':'31415927'})
      civicrm.delete('GroupAcls', self.group_acl[0]['id'])
      self.assertEqual(response.text,'{"access":"1"}')
      response = requests.post(url, data = {'uuid':'31415927'})
      self.assertEqual(response.text,'{"access":"0"}')
    


if __name__ == '__main__':
   unittest.main()


