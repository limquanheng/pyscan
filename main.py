#  -*- coding: utf-8 -*-
#Build a python script
#That reads apache logs (the link to the sample file provided below) line by line and returns the following information to file(s):
#list of unique IP addresses as a flat text file
#list of unique IP addresses with country and number of hits as a flat text file
#list of all activity per IP address to individual flat text files per IP
#detect SQLi with found entries to flat text file
#detect remote file inclusion with found entries to flat text file
#detect web shells with found entries to flat text file
#The project will be assessed based exiting results collected manually, the quality of the code,  the number of tasks completed, and associated documentation. If the candidate is unable to complete a particular task, a brief description of why should be included when the assignment is turned in.
#The sample file can be found at this link:
#https://horangi.box.com/s/9dj3vl4ikzt19td7a9520t7xp4fp1km9
#Deliverables: source code in github, developer guide, user guide.

import os
import re
import sys
from time import gmtime, strftime
import urllib.request
#import pygeoip
#Switch to better DB pip install python-geoip
#from geoip import open_database
#switch to Py3 support
import json
import xml.etree.ElementTree
import collections
import maxminddb
import socket

#Method for 1)
def uniqueIP():
    resultSet = []
    cwd = os.getcwd()
    for root, dirs, files in os.walk(cwd):
        for file in files:
            if file.endswith(".log"):
                print('Processing files... Please wait.')
                with open(file) as f:
                    f = f.readlines()
                for line in f:
                    ip = re.findall(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}', line[33:])
                    for a in ip:
                        if valid_ip(a):
                            resultSet.append(str(a))
                writeSetToFile("IP_List", sorted(list(set(resultSet))))

#Method for 2)
def uniqueIPCountry():
    resultDict = dict()
    requerySet = collections.OrderedDict()
    requerySet["IP,Country,Region,City,Postal Code"] = "count"
    cwd = os.getcwd()

    # GeoIPDatabase = cwd + '/data/GeoLiteCity.dat'
    # ipData = pygeoip.GeoIP(GeoIPDatabase)
    #Switch to better DB pip install python-geoip
    #ipData = open_database('data/GeoLite2City.mmdb')
    #Switch to maxminddb-geolite2 DB
    #reader = geolite2.reader()
    reader = maxminddb.open_database('data/GeoLite2City.mmdb')
    for root, dirs, files in os.walk(cwd):
        for file in files:
            if file.endswith(".log"):
                print('Processing files... Please wait.')
                with open(file) as f:
                    f = f.readlines()
                for line in f:
                    ip = re.findall(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}', line[33:])
                    for countryString in ip:
                        if valid_ip(countryString):
                            if countryString in resultDict:
                                resultDict[countryString] += 1
                            else:
                                resultDict[countryString] = 1
                for key,value in resultDict.items():
                    countryString = key
                    entry = reader.get(key)
                    try:
                        # Switch to better DB
                        #record = ipData.lookup(key)
                        # Switch to maxminddb-geolite2 DB
                        #print(reader.get(key))
                        countryName = entry["country"]["names"]["en"]
                        subDivName = entry.get("subdivisions", [{0: 0}])[0].get("names", {}).get("en", "")
                        cityName = entry.get("city", {}).get("names", {}).get("en", "")
                        postalCode = entry.get("postal", {}).get("code", "")

                        countryString = key + ',' + countryName + ',' +subDivName+ ',' +cityName+ ',' +postalCode
                        count = resultDict[key]
                        #resultDict.pop(key, None)
                        requerySet[countryString] = count
                    except:
                        try:
                            response = urllib.request.urlopen(
                                "http://ip-api.com/json/{0}".format(key)).read()
                            locationInfo = json.loads(response.decode('utf-8'))

                            countryString = key + ',' + locationInfo['country']+ ',' +locationInfo['regionName']+ ',' +locationInfo['city']+ ',' +locationInfo['zip'] #{'region': 'IL', 'status': 'success', 'country': 'United States', 'as': 'AS15169 Google Inc.', 'org': 'Google', 'city': 'Chicago', 'timezone': 'America/Chicago', 'countryCode': 'US', 'regionName': 'Illinois', 'lon': -87.6298, 'isp': 'Google', 'lat': 41.8781, 'query': '66.249.81.239', 'zip': ''}
                            count = resultDict[key]
                            #resultDict.pop(key, None)
                            requerySet[countryString] = count
                        except:
                            print(
                                "IP information for " + key + " could not be found in both local DB(maxmind city2 Free) and ip-api.com. Entry will still be written.") #http://ip-api.com/docs/unban
                            count = resultDict[key]
                            requerySet[key + ',' + "" + ',' +""+ ',' +""+ ',' +""] = count

                            # This product includes GeoLite2 data created by MaxMind, available from
                            # <a href="http://www.maxmind.com">http://www.maxmind.com</a>.
                        count = resultDict[key]
                        #resultDict.pop(key, None)
                        requerySet[countryString] = count

                print('Processing done. Writing results.')
                writeDictToFile("IP_country_List", requerySet)
                reader.close()


# Method for 3). Write to file integrated
# list of all activity per IP address to individual flat text files per IP
def activityPerAddress():
    cwd = os.getcwd()
    for root, dirs, files in os.walk(cwd):
        for file in files:
            if file.endswith(".log"):
                print('Processing files... Please wait.')
                with open(file) as f:
                    f = f.readlines()
                print(
                    'Processing done. Writing will begin. Do not modify or open files while generation is in progress.')
                for line in f:
                    ip = re.findall(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}', line[33:])
                    for a in ip:
                        if valid_ip(a):
                            fileName = a + ".txt"
                            try:
                                file = open(fileName, 'a', encoding='utf-8')
                                file.write("%s\n" % line)
                                file.close()
                            except:
                                print("Error occured! Process did not complete")
                                sys.exit(0)

# Method for 4). Write to file integrated
# detect SQLi with found entries to flat text file
def sqli():
    cwd = os.getcwd()
    root = xml.etree.ElementTree.parse('data/default_filter_fixed.xml').getroot()
    filename= "SQLi_detection.txt"
    fileWrite = open(filename, 'a', encoding='utf-8')

    #filters = root[0]
    print('Processing files... Please wait.')
    for filter in root:
        containsSQLI = 0
        for tag in filter[3].iter('tag'):
            #print(tag.text)
            #print(tag.tag)
            if tag.text == "sqli":
                containsSQLI = 1
        if containsSQLI==1:
            regex = filter.find('rule')
            #print(regex)
            description = filter.find('description')
            try:
                fileWrite.write("%s\n\n" % description.text + "\n\n")
            except Exception as e:
                print("Error occured during write. Attempting to proceed...")
                print (e)
            for root, dirs, files in os.walk(cwd):
                for file in files:
                    if file.endswith(".log"):
                        with open(file) as f:
                            f = f.readlines()
                        for line in f:
                            if re.search(re.compile(regex.text), line):
                                try:
                                    fileWrite.write("%s\n" % line)
                                except Exception as e:
                                    print("Error occured during write. Attempting to proceed...")
                                    print(e)
    try:
        fileWrite.close()
        print(
            'Processing done. Writing done to ' + filename)
    except:
        print("Error occured! File close failed.")
        sys.exit(0)
        #if child.tag("filter").tag("tags").tag("tag").attrib("sqli"):
        #    print("true")

    #callFilters = xmlRoot.findall('tags')
    #for node in callFilters:
        #print(node.keys())
     #   if node.attrib['filter'] == sqli:
        #if 'Reference' in current_element.attrib:
      #      print("true")

# Method for 5). Write to file integrated
def rfi():
    cwd = os.getcwd()
    root = xml.etree.ElementTree.parse('data/default_filter_fixed.xml').getroot()
    filename= "rfi_rfe_detection.txt"
    fileWrite = open(filename, 'a', encoding='utf-8')

    for filter in root:
        containsRFE = 0
        for tag in filter[3].iter('tag'):
            # print(tag.text)
            # print(tag.tag)
            if tag.text == "rfi":
                containsRFE = 1
        if containsRFE == 1:
            regex = filter.find('rule')
            description = filter.find('description')
            try:
                fileWrite.write("%s\n\n" % description.text + "\n\n")
            except Exception as e:
                print("Error occured during write. Attempting to proceed...")
                print(e)
            for root, dirs, files in os.walk(cwd):
                for file in files:
                    if file.endswith(".log"):
                        with open(file) as f:
                            f = f.readlines()
                        for line in f:
                            if re.search(re.compile(regex.text),line):
                                try:
                                    fileWrite.write("%s\n" % line)
                                except Exception as e:
                                    print("Error occured during write. Attempting to proceed...")
                                    print(e)
    try:
        fileWrite.close()
        print(
            'Processing done. Writing done to ' + filename)
    except:
        print("Error occured! File close failed.")
        sys.exit(0)
        #if child.tag("filter").tag("tags").tag("tag").attrib("sqli"):
        #    print("true")

    #callFilters = xmlRoot.findall('tags')
    #for node in callFilters:
        #print(node.keys())
     #   if node.attrib['filter'] == sqli:
        #if 'Reference' in current_element.attrib:
      #      print("true")



# Method for 6).
def wsd():
    cwd = os.getcwd()
    #webshellRegex = xml.etree.ElementTree.parse('data/rfi_regex_tw.xml').getroot()
    filename= "webshell_detection.txt"
    fileWrite = open(filename, 'a', encoding='utf-8')
    c_reg = re.compile(r'(?si)(preg_replace.*\/e|`.*?\$.*?`|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)')

    for root, dirs, files in os.walk(cwd):
            for file in files:
                if file.endswith(".log"):
                    with open(file) as f:
                        f = f.readlines()
                    for line in f:
                        if re.search(c_reg, line):
                            try:
                                fileWrite.write("%s\n" % line)
                            except Exception as e:
                                print("Error occured during write. Attempting to proceed...")
                                print(e)
    try:
        fileWrite.close()
        print(
            'Processing done. Writing done to ' + filename)
    except:
        print("Error occured! File close failed.")
        sys.exit(0)
        #if child.tag("filter").tag("tags").tag("tag").attrib("sqli"):
        #    print("true")

#Global write set to txt
def writeSetToFile(fileName, resultSet):
    fileName = fileName + "_" + strftime("%Y-%m-%d_%H-%M-%S", gmtime())+".txt"
    print('Writing to ' + fileName + '.')
    try:
        file = open(fileName, 'a', encoding='utf-8')
        for item in resultSet:
            file.write("%s\n" % item)
        file.close()
    except:
        print("Error occured!")
        sys.exit(0)

# Global write dict to CSV
def writeDictToFile(fileName, resultSet):
    fileName = fileName + "_" + strftime("%Y-%m-%d_%H-%M-%S", gmtime()) + ".csv"
    print('Writing to ' + fileName + '.')
    try:
        file = open(fileName, 'a', encoding='utf-8')
        for key, value in resultSet.items():
            file.write('%s,%s\n' % (key, value))
        file.close()
    except Exception as e:
        print("Error occured during write. Attempting to proceed...")
        print(key + " " + value)
        print(e)
        sys.exit(0)

def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except Exception as e:
        print(e)
        return False

#Menu
ans=True
while ans:
    print ("""
    1.List of unique IPs
    2.List of unique IPs with country and no. hits
    3.Unique IP activity per address
	4.SQLi entries
	5.Remote file inclusion
	6.Web shells
    7.Exit/Quit
    """)
    ans=input("What would you like to do? ")
    if ans=="1":
        uniqueIP()
        print("Write unique IPs done")
    elif ans=="2":
        uniqueIPCountry()
        print("Write unique country IPs done")
    elif ans=="3":
        activityPerAddress()
        print("Writing IP activity done")
    elif ans == "4":
        sqli()
        print("SQLi detection done")
    elif ans == "5":
        rfi()
        print("RFI detection done")
    elif ans == "6":
        wsd()
        print("Web shell done")
    elif ans=="7":
        print("\n Goodbye")
        sys.exit(0)
    elif ans !="":
        print("\n Not Valid Choice Try again")




