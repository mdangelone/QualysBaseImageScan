# Python script https://kube-jenkins.inday.io/vuln-mgmt/job/Bare%20Metal%20Base%20Image%20Scan/
# Initiate Qualys Scan from target IP and Jira ticket.
# Download and parse the Qualys report to search for sev 4 and 5 vulns
# Attach report to jira ticket and add comment about next step
#Author Marcello D'Angelone

#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET
import csv
import time
import requests
import re
import ipaddress
from atlassian import Jira


quser = os.getenv('QUSER')
qpassw = os.getenv('QPASSW')
key = os.getenv('JIRA_TICKET')
ip = os.getenv('IP')
qurl = "https://qualysapi.qualys.com/api/2.0/fo/scan/"
headers = {
  'X-Requested-With': 'QualysPOSTMAN'
}
jira = Jira(
  url="<Type your Jira Instance>",
  username= os.getenv('JIRA_USERNAME'),
  password= os.getenv('JIRA_PW')
)


def jiraTicketcomment(key, comment, attachment):

  jira.issue_add_comment(key, comment)
  jira.add_attachment(key, attachment)

def parseReport():
  sev4 = []
  sev5 = []
  csvfile = open("/tmp/" + ip + "-VULNReport.csv", "r")
  attachment = "/tmp/" + ip + "-VULNReport.csv"

  for i, line in enumerate(csv.reader(csvfile, delimiter=','), 1):

    try:

      if ((line[8]) == "4" or (line[8]) == "5"):

        #status.append(line[4] == "Finished (No host alive)")
        sev4.append(line[8] == "4")
        sev5.append(line[8] == "5")


    except:
      pass
    continue

# if True in status:
#   comment = {"body": "HOST NOT ALIVE, please check the target IP"}
  if (sum(sev4) != 0) or (sum(sev5) != 0):
    comment = "scan completed for host " + ip + ":*{color:red} " + str(sum(sev5)) +" Sev 5 and " + str(sum(sev4)) + " Sev4 Vulnerabilities found.{color}* Please review column I on the attached report and remediate any Severity 4 and 5 Vulns found"

  elif (sum(sev4) == 0) and (sum(sev5) == 0):
    comment = "scan completed for host " + ip + " no sev 4 or 5 Vulns found. Final approval from the Vuln Mgmt team is required prior release to production. Please contact #vuln-mgmt-public"
  print("Sending " + ip + "-VULNReport.csv to Jira: " + key)
  jiraTicketcomment(key, comment, attachment)


def qualysLaunchScan(key, ip):
  match = re.search(r"INF-\d+", key)
  if match:
    pass
  else:
    sys.exit("INVALID Jira Ticket Number")
    
  if ipaddress.ip_address(ip) in ipaddress.ip_network('10.0.0.0/8'):
      scanner_name = 'pdx_eng'
  elif ipaddress.ip_address(ip) in ipaddress.ip_network('10.140.0.0/16'):
      scanner_name = 'pdx-eng-az'
  else:
      print("INVALID IP ADDRESS")
      sys.exit("The IP address is not in a valid range: '10.96.0.0/16' or '10.140.0.0/16'")

  launchpayload={'action': 'launch',
  'scan_title': key,
  'ip': ip,
  'iscanner_name' : scanner_name,
  'priority': 1,
  'option_title': 'Full Internal Authenticated Scan'}
  
  try:
    scanlaunch = requests.request("POST", qurl, headers=headers, data=launchpayload, auth=(quser, qpassw))
    scanlaunch.raise_for_status()
  except requests.exceptions.RequestException as err:
    print('Error ' + str(err))
    sys.exit(1)
    return ('Error ' + str(err))
  else:
    print(scanlaunch.text)
    tree = ET.ElementTree(ET.fromstring(scanlaunch.content))
    scandetails = tree.getroot()
    scanvalue = [scan[1].text for scan in scandetails.iter('ITEM')]
    scanref = scanvalue[1]
    print(scanref)
    return scanref


def qualysDownReport(scanref):

  reportpayload={'action': 'fetch',
  'scan_ref': scanref,
  'mode': 'extended',
  'output_format': 'csv_extended'}
  try:
    report = requests.request("POST", qurl, headers=headers, data=reportpayload, auth=(quser, qpassw))
  except requests.exceptions.RequestException as err:
    print('Error ' + str(err))
    sys.exit(1)
    return ('Error ' + str(err))
  else:
    csvfile = open("/tmp/" + ip + "-VULNReport.csv", "w")
    csvfile.write(report.text)
    csvfile.close()
    parseReport()

def qualysScanStatus(scanref):

  statuspayload={'action': 'list',
  'scan_ref': scanref,
  'show_status': '1'}

  while True:
    time.sleep(60)
    try:
      statuslaunch = requests.request("POST", qurl, headers=headers, data=statuspayload, auth=(quser, qpassw))
      statuslaunch.raise_for_status()
    except requests.exceptions.RequestException as err:
      print('Error ' + str(err))
      sys.exit(1)
      return ('Error ' + str(err))
    else:
      tree = ET.ElementTree(ET.fromstring(statuslaunch.content))
      root = tree.getroot()
      for status in root.iter('SCAN'):
        if status[8][0].text == "Running":
          print("Scan status: " + status[8][0].text)
          continue
        elif status[8][0].text == "Paused":
          print("Scan status: " + status[8][0].text)
          continue
        elif status[8][0].text == "Cancelled":
          print("Scan status: " + status[8][0].text)
          sys.exit(1)

        elif status[8][0].text == "Finished":
          print("Scan status: " + status[8][0].text)
          qualysDownReport(scanref)
          sys.exit(0)
          break
        elif status[8][0].text == "Error":
          print("Scan status: " + status[8][0].text)
          sys.exit(1)
        elif status[8][0].text == "Queued":
          print("Scan status: " + status[8][0].text)
          continue
        elif status == '':
          status[8][0].text = ''
          break
        else:
          sys.exit(1)

def main():
  scanref = qualysLaunchScan(key, ip)
  qualysScanStatus(scanref)
if __name__ == "__main__":
  main()
