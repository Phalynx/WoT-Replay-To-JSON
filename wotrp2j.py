#!/usr/bin/env python
# -*- coding: utf-8 -*-

#################################
# World of Tanks Replay to JSON #
# Phalynx www.vbaddict.net      #
###############################'#

import struct, json, time, sys, os, shutil, datetime, re, codecs

VEHICLE_DEVICE_TYPE_NAMES = ('engine', 'ammoBay', 'fuelTank', 'radio', 'track', 'gun', 'turretRotator', 'surveyingDevice')
VEHICLE_TANKMAN_TYPE_NAMES = ('commander', 'driver', 'radioman', 'gunner', 'loader')

def main():

	parserversion = "0.9.8.0"

	global option_console, option_advanced, option_chat, option_server, filename_source
	option_console = 0
	option_advanced = 0
	option_chat = 0
	option_server = 0
	
	filename_source = ""
	
	replay_version = "0.0.0.0"
	replay_version_dict = ['0', '0', '0', '0']
	

	for argument in sys.argv:
			if argument == "-c":
				option_console = 1
				
			if argument == "-a":
				option_advanced = 1

			if argument == "-chat":
				option_chat = 1
				
			if argument == "-s":
				option_server = 1
			

	printmessage('###### WoT-Replay-To-JSON ' + parserversion + " by vBAddict.net")

	if len(sys.argv)==1:
				printmessage('Please specify filename and options')
				sys.exit(2)

	filename_source = str(sys.argv[1])
	
	printmessage('Processing ' + filename_source)
	
	result_blocks = dict()
	result_blocks['common'] = dict()
	result_blocks['common']['parser'] = "WoT-Replay-To-JSON " + parserversion + " by http://www.vbaddict.net"

	result_blocks['identify'] = dict()
	result_blocks['identify']['arenaUniqueID'] = 0
	
	if not os.path.exists(filename_source) or not os.path.isfile(filename_source) or not os.access(filename_source, os.R_OK):
		result_blocks['common']['message'] = 'cannot read file ' + filename_source
		dumpjson(result_blocks, filename_source, 1)

	f = open(filename_source, 'rb')
	
	try:
		f.seek(4)
		numofblocks = struct.unpack("I",f.read(4))[0]
		printmessage("Found Blocks: " + str(numofblocks))
		blockNum = 1
		datablockPointer = {}
		datablockSize = {}
		startPointer = 8
	except Exception, e:
		result_blocks['common']['message'] = e.message
		dumpjson(result_blocks, filename_source, 1)

	if numofblocks == 0:
		result_blocks['common']['message'] = "unknown file structure"
		dumpjson(result_blocks, filename_source, 1)

	if numofblocks > 5:

		result_blocks['common']['message'] = "uncompressed replay"
		result_blocks['datablock_advanced'] = extract_advanced(filename_source)
			
		if result_blocks['datablock_advanced']['valid'] == 1:
			
			result_blocks['identify']['accountDBID'] = 0
			result_blocks['identify']['internaluserID'] = 0
			if result_blocks['datablock_advanced']['playername'] in result_blocks['datablock_advanced']['roster']:
				rosterdata = dict()			
				rosterdata = result_blocks['datablock_advanced']['roster'][result_blocks['datablock_advanced']['playername']]
				result_blocks['identify']['accountDBID'] = rosterdata['accountDBID'] 
				result_blocks['identify']['countryid'] = rosterdata['countryID']
				result_blocks['identify']['internaluserID'] = rosterdata['internaluserID']
				result_blocks['identify']['tankid'] = rosterdata['tankID']
		
			
			result_blocks['identify']['arenaUniqueID'] = result_blocks['datablock_advanced']['arenaUniqueID']
			result_blocks['identify']['arenaCreateTime'] = result_blocks['datablock_advanced']['arenaCreateTime']
			
			mapsdata = get_json_data("maps.json")
			mapname='unknown'
			for mapdata in mapsdata:
				if mapdata['mapid'] == result_blocks['datablock_advanced']['arenaTypeID']:
						mapname = mapdata['mapidname']
						break

			result_blocks['identify']['mapName'] = mapname
			
			
			result_blocks['identify']['mapid'] = result_blocks['datablock_advanced']['arenaTypeID']
			result_blocks['identify']['playername'] = result_blocks['datablock_advanced']['playername']
			result_blocks['identify']['replay_version'] = result_blocks['datablock_advanced']['replay_version']
			
			result_blocks['identify']['error'] = "none"
			result_blocks['identify']['error_details'] = "none"

			result_blocks['common']['datablock_advanced'] = 1

			if option_chat==1:
				result_blocks['chat'] = extract_chats(filename_source)
				result_blocks['common']['datablock_chat'] = 1
		else:
			result_blocks['common']['message'] = "replay incompatible"
			dumpjson(result_blocks, filename_source, 1)
		
		
		dumpjson(result_blocks, filename_source, 0)

	
	

	while numofblocks >= 1:
		try:
			printmessage("Retrieving data for block " + str(blockNum))
			f.seek(startPointer)
			size = f.read(4)
			datablockSize[blockNum] = struct.unpack("I", size)[0]
			datablockPointer[blockNum] = startPointer + 4
			startPointer=datablockPointer[blockNum]+datablockSize[blockNum]
			blockNum += 1
			numofblocks -= 1
		except Exception, e:
			result_blocks['common']['message'] = e.message
			dumpjson(result_blocks, filename_source, 1)
		
	processing_block = 0
	
	for i in datablockSize:
		
		processing_block += 1
		
		try:
			pass
		except Exception, e:
			result_blocks['common']['message'] = e.message
			dumpjson(result_blocks, filename_source, 1)
			
		printmessage("Retrieving block " + str(processing_block))
		f.seek(datablockPointer[i])
							
		myblock = f.read(int(datablockSize[i]))

		if 'arenaUniqueID' in myblock:

			if version_check(replay_version, "0.8.11.0") > -1 or myblock[0]=='[':
				br_json_list = dict()
		
				try:
					br_json_list = json.loads(myblock)
				except Exception, e:
					printmessage("Error with JSON: " + e.message)
				
				if len(br_json_list)==0:
					continue

				br_block = br_json_list[0]
				br_block['parser'] = dict()
				br_block['parser']['battleResultVersion'] = 14

				if version_check(replay_version, "0.9.8.0") > -1:
					br_block['parser'] = dict()
					br_block['parser']['battleResultVersion'] = 15
					if 'personal' in br_block:
						for vehTypeCompDescr, ownResults in br_block['personal'].copy().iteritems():
							if 'details' in ownResults:
								ownResults['details'] = decode_details(ownResults['details'])
								print ownResults['details']
								br_block['personal'][vehTypeCompDescr] = ownResults

					
				if 'datablock_1' in result_blocks:
					if len(br_json_list) > 0:
						result_blocks['datablock_1']['vehicles'] = br_json_list[1]

					if len(br_json_list) > 1:
						result_blocks['datablock_1']['kills'] = br_json_list[2]

			else:

				try:
					from SafeUnpickler import SafeUnpickler
					br_block = SafeUnpickler.loads(myblock)
					br_block['parser'] = dict()
					br_block['parser']['battleResultVersion'] = 14
				except Exception, e:
					printmessage("Error with unpickling myblock: " + e.message)

			if int(br_block['parser']['battleResultVersion']) < 15:
				if 'personal' in br_block:
					br_block['personal']['details'] = decode_details(br_block['personal']['details'])
					if 'vehicles' in br_block:
						for key, value in br_block['vehicles'].items():
							if 'details' in br_block['vehicles'][key]:
								del br_block['vehicles'][key]['details']
						
					
			result_blocks['datablock_battle_result'] = br_block

			result_blocks['common']['datablock_battle_result'] = 1
			result_blocks['identify']['arenaUniqueID'] = result_blocks['datablock_battle_result']['arenaUniqueID']

				
		else:
			blockdict = dict()
			try:
				blockdict = json.loads(myblock)
			except Exception, e:
				printmessage("Error with JSON: " + e.message)
			
			
			if 'clientVersionFromExe' in blockdict:
				replay_version = cleanReplayVersion(blockdict['clientVersionFromExe'])
				result_blocks['common']['replay_version'] = replay_version
				result_blocks['identify']['replay_version'] = replay_version
				replay_version_dict = replay_version.split('.')
				printmessage("Replay Version: " + str(replay_version))
			
			result_blocks['datablock_' + str(i)] = blockdict
			result_blocks['common']['datablock_' + str(i)] = 1

		result_blocks['common']['message'] = "ok"
	
	result_blocks = get_identify(result_blocks)
		
	if option_advanced==1 or option_chat==1:

		decfile = decrypt_file(filename_source, startPointer)
		uncompressed = decompress_file(decfile)
		if option_advanced==1:
			
			with open(uncompressed, 'rb') as f:
				if is_supported_replay(f):
					result_blocks['datablock_advanced'] = extract_advanced(uncompressed)
					result_blocks['common']['datablock_advanced'] = 1
				else:
					result_blocks['common']['datablock_advanced'] = 0
					result_blocks['common']['message'] = "Unsupported binary replay"
					dumpjson(result_blocks, filename_source, 0)

		if option_chat==1:
			import legacy
			result_blocks['chat_timestamp'] = legacy.Data(open(uncompressed, 'rb')).data[legacy.KEY.CHAT]
			result_blocks['chat'] = "<br/>".join([msg.encode("string-escape") for msg, timestamp in result_blocks['chat_timestamp']])
			result_blocks['common']['datablock_chat'] = 1

			result_blocks['bindata'] = legacy.Data(open(uncompressed, 'rb')).data
			
			
		
	dumpjson(result_blocks, filename_source, 0)

# Create block to identify replay even without arenaUniqueID, needed for vBAddict.net
def get_identify(result_blocks):
	
	internaluserID = 0
	
	if not 'datablock_1' in result_blocks:
		return result_blocks
	
	for key, value in result_blocks['datablock_1']['vehicles'].items():
		
		if result_blocks['datablock_1']['vehicles'][key]['name'] == result_blocks['datablock_1']['playerName']:
			internaluserID = key
			break
	
	result_blocks['identify']['internaluserID'] = internaluserID
	
	try:
		result_blocks['identify']['arenaCreateTime'] = int(time.mktime(datetime.datetime.strptime(result_blocks['datablock_1']['dateTime'], "%d.%m.%Y %H:%M:%S").timetuple()))
	except Exception, e:
		result_blocks['identify']['arenaCreateTime'] = int(time.time())
		
	result_blocks['identify']['playername'] = result_blocks['datablock_1']['playerName']
	result_blocks['identify']['accountDBID'] = result_blocks['datablock_1']['playerID']
	result_blocks['identify']['mapName'] = result_blocks['datablock_1']['mapName']
	
	
	# Convert string based tank to countryid/tankid
	tank = result_blocks['datablock_1']['playerVehicle']
	tankSlug = tank
	countryid = 0
	if "ussr-" in tank:
		countryid = 0
		tankSlug = tankSlug.replace('ussr-', '')
	
	if "germany-" in tank:
		countryid = 1
		tankSlug = tankSlug.replace('germany-', '')
	
	if "usa-" in tank:
		countryid = 2
		tankSlug = tankSlug.replace('usa-', '')
	
	if "china-" in tank:
		countryid = 3
		tankSlug = tankSlug.replace('china-', '')
	
	if "france-" in tank:
		countryid = 4
		tankSlug = tankSlug.replace('france-', '')
	
	if "uk-" in tank:
		countryid = 5
		tankSlug = tankSlug.replace('uk-', '')
	
	if "japan-" in tank:
		countryid = 6
		tankSlug = tankSlug.replace('japan-', '')
	
	tankSlug = tankSlug.replace('-', '_')
	
	mapsdata = get_json_data("maps.json")
	mapid=0
	for mapdata in mapsdata:
		if mapdata['mapidname'] == result_blocks['identify']['mapName']:
				mapid = mapdata['mapid']
				break
	
	result_blocks['identify']['mapid'] = mapid
	
	tanksdata = get_json_data("tanks.json")
	tankid=0
	for tankdata in tanksdata:
		if tankdata['icon'] == tankSlug.lower():
			tankid = tankdata['tankid']
			break
	
	result_blocks['identify']['tankid'] = tankid
	result_blocks['identify']['countryid'] = countryid
		
	result_blocks['identify']['error'] = 'none'
	result_blocks['identify']['error_details'] = 'none'


	return result_blocks
	
def make_typeCompDescr(countryid, tankid):
	countryshift = 1 + (countryid << 4)
	return (tankid << 8) + countryshift
	

def version_check(version_check, version_desired):
	def normalize(v):
		return [int(x) for x in re.sub(r'(\.0+)*$','', v).split(".")]
	
	return cmp(normalize(version_check), normalize(version_desired))

def cleanReplayVersion(replay_version):
	replay_version = replay_version.replace(', ', '.')
	replay_version = replay_version.replace(' ', '.')
	#return replay_version.split('.')[:3]
	return replay_version


def decode_crits(details_data):
	"""
	Decodes the crits introduced in 0.8.6.0
	Refer also to http://wiki.vbaddict.net/pages/Crits
	"""
	for vehicleid, detail_values in details_data.items():

		if detail_values['crits']>0:
			destroyedTankmen = detail_values['crits'] >> 24 & 255
			destroyedDevices = detail_values['crits'] >> 12 & 4095
			criticalDevices = detail_values['crits'] & 4095
			critsCount = 0
			
			criticalDevicesList = []
			destroyedDevicesList = []
			destroyedTankmenList = []
			
			for shift in range(len(VEHICLE_DEVICE_TYPE_NAMES)):
				if 1 << shift & criticalDevices:
					critsCount += 1
					criticalDevicesList.append(VEHICLE_DEVICE_TYPE_NAMES[shift])
			
				if 1 << shift & destroyedDevices:
					critsCount += 1
					destroyedDevicesList.append(VEHICLE_DEVICE_TYPE_NAMES[shift])
			
			for shift in range(len(VEHICLE_TANKMAN_TYPE_NAMES)):
				if 1 << shift & destroyedTankmen:
					critsCount += 1
					destroyedTankmenList.append(VEHICLE_TANKMAN_TYPE_NAMES[shift])
	
			details_data[vehicleid]['critsCount'] = critsCount
			details_data[vehicleid]['critsDestroyedTankmenList'] = destroyedTankmenList
			details_data[vehicleid]['critsCriticalDevicesList'] = criticalDevicesList
			details_data[vehicleid]['critsDestroyedDevicesList'] = destroyedDevicesList
		
	return details_data
	
  
def write_to_log(logtext): 
    import datetime, os 
      
    global option_server, filename_source
      
   # print logtext 
    now = datetime.datetime.now() 
      
      
    if option_server == 1: 
        logFile = open("/var/log/wotdc2j/wotdc2j.log", "a+b") 
        logFile.write(str(now.strftime("%Y-%m-%d %H:%M:%S")) + " # " + str(logtext) + " # " + str(filename_source) + "\r\n") 
        logFile.close() 

def printmessage(message):
	global option_console
	
	if option_console==0:
		print message


def dumpjson(mydict, filename_source, exitcode):
	
	global option_console
	
	if exitcode == 0:
		mydict['common']['status'] = "ok"
	else:
		mydict['common']['status'] = "error"
		printmessage("Errors occurred: " + str(mydict['common']['message']))
		write_to_log("WOTRP2J: Err on " + str(mydict['common']['message']))
	
	
	if option_console==0:
		filename_target = os.path.splitext(filename_source)[0]
		filename_target = filename_target + '.json'
		
		if option_advanced==0 and option_chat==0 :
			try:
				finalfile = open(filename_target, 'w')
				finalfile.write(json.dumps(mydict, sort_keys=True, indent=4)) 		
				finalfile.close()
			except Exception, e:
				print mydict
				printmessage("Error saving JSON: " + str(e.message))
				write_to_log("WOTRP2J: Err on " + str(e.message))
			
		else:
			# Patch by kuzyara
			reload(sys)
			sys.setdefaultencoding("utf-8")
			jsondata = json.dumps(mydict, sort_keys=True, indent=4)
			jsondata = jsondata.replace('\\\\x','\\x')
			
			#convert unicode codepoint to char
			jsondata = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: unichr(int(m.group(1), 16)).encode('utf8'), jsondata)
			#convert utf8 hex to char
			jsondata = re.sub(r'\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})',lambda m: (m.group(1)+m.group(2)).decode('hex').decode('utf-8') ,str(jsondata))
			
			finalfile = codecs.open(filename_target, "w", "utf-8")
			#write BOM
			finalfile.write(u'\ufeff')
			finalfile.write(jsondata)
			finalfile.close()
 
	else:
		print json.dumps(mydict, sort_keys=True, indent=4)

	deleteFile(filename_source + ".tmp")
	deleteFile(filename_source + ".tmp.out")
	
		
	sys.exit(exitcode)

def deleteFile(filename):
	if os.path.exists(filename):
		try:
			os.unlink(filename)
		except Exception, e:
			printmessage("Cannot delete file " + filename + ": " + e.message)

	
def get_current_working_path():
	#workaround for py2exe
	import sys, os
	
	try:
		if hasattr(sys, "frozen"):
			return os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding( )))
		else:
			return sys.path[0]
	except Exception, e:
		print e.message
		
def get_json_data(filename):
	import json, time, sys, os

	current_working_path = get_current_working_path()

	os.chdir(current_working_path)
		
	if not os.path.exists(filename) or not os.path.isfile(filename) or not os.access(filename, os.R_OK):
		catch_fatal(filename + " does not exists!")
		sys.exit(1)

	file_json = open(filename, 'r')

	try:
		file_data = json.load(file_json)
	except Exception, e:
		catch_fatal(filename + " cannot be loaded as JSON: " + e.message)
		sys.exit(1)
		
		
	file_json.close()

	return file_data

def catch_fatal(message):
	printmessage(message)
	
		


# Contributions from other projects
#####################################################################################

# Thanks to https://github.com/raszpl/wotdecoder
# 20130729 Phalynx, Changes for 0.8.6, 0.8.7
def decode_details(data):
    detail = [
      "spotted",
      "deathReason",
      "hits",
      "he_hits",
      "pierced",
      "damageDealt",
      "damageAssistedTrack",
      "damageAssistedRadio",
      "crits",
      "fire"
    ]
    details = {}

    binlen = len(data) // 22
    datalen = 20
		
    try:
        for x in range(0, binlen):
            offset = 4*binlen + x*datalen
            vehic = struct.unpack('i', data[x*4:x*4+4])[0]
            detail_values = struct.unpack('<BbHHHHHHIH', data[offset:offset + datalen])
            details[vehic] = dict(zip(detail, detail_values))
    except Exception, e:
        printmessage("Cannot decode details: " + e.message)
    return details
	
def encodeUtf8(string):
	import types
	from encodings import utf_8
	
	if isinstance(string, types.UnicodeType):
		return string.encode('utf-8', 'ignore')
	return string
	
	
def is_supported_replay(f):
	f.seek(12)
	versionlength = struct.unpack("B",f.read(1))[0]

	if not versionlength in (10, 11):
		return False
		
	return True
	
# Thanks to https://github.com/benvanstaveren/wot-replays
def extract_advanced(fn):
	advanced = dict()
	with open(fn, 'rb') as f:

		f.seek(12)
		versionlength = struct.unpack("B",f.read(1))[0]
	
		if not is_supported_replay(f):
			advanced['valid'] = 0
			printmessage('Unsupported replay: Versionlength: ' + str(versionlength))
			return advanced

		f.read(3)
	
		advanced['replay_version'] = f.read(versionlength)
		advanced['replay_version'] = advanced['replay_version'].replace(', ', '.').strip()
		advanced['replay_version'] = advanced['replay_version'].replace('. ', '.').strip()
		advanced['replay_version'] = advanced['replay_version'].replace(' ', '.').strip()

		f.seek(51 + versionlength)	
		playernamelength = struct.unpack("B",f.read(1))[0]

		advanced['playername'] = f.read(playernamelength)
		advanced['arenaUniqueID'] = struct.unpack("Q",f.read(8))[0]
		advanced['arenaCreateTime'] = advanced['arenaUniqueID'] & 4294967295L
		
		advanced['arenaTypeID'] = struct.unpack("I",f.read(4))[0]
		advanced['gameplayID'] = advanced['arenaTypeID'] >> 16
		advanced['arenaTypeID'] = advanced['arenaTypeID'] & 32767
		
		advanced['bonusType'] = struct.unpack("B",f.read(1))[0]
		advanced['guiType'] = struct.unpack("B",f.read(1))[0]
	
		
		advanced['more'] = dict()
		advancedlength = struct.unpack("B",f.read(1))[0]

		if advancedlength==255:
			advancedlength = struct.unpack("H",f.read(2))[0]
			f.read(1)

		try:
			advanced_pickles = f.read(advancedlength)
			from SafeUnpickler import SafeUnpickler
			advanced['more'] = SafeUnpickler.loads(advanced_pickles)	
		except Exception, e:
			printmessage('cannot load advanced pickle: ' + e.message)
			printmessage('Position: ' + str(f.tell()) + ", Length: " + str(advancedlength))

	
		f.seek(f.tell()+29)
		
		advancedlength = struct.unpack("B",f.read(1))[0]

		if advancedlength==255:
			advancedlength = struct.unpack("H",f.read(2))[0]
			f.read(1)
			
		#try:
		rosters = []
		try:
			advanced_pickles = f.read(advancedlength)
			from SafeUnpickler import SafeUnpickler
			rosters = SafeUnpickler.loads(advanced_pickles)		
		except Exception, e:
			printmessage('cannot load roster pickle: ' + e.message)
			printmessage('Position: ' + str(f.tell()) + ", Length: " + str(advancedlength))
		
		rosterdata = dict()
		for roster in rosters:
			rosterdata[roster[2]] = dict()
			rosterdata[roster[2]]['internaluserID'] = roster[0]
			rosterdata[roster[2]]['playerName'] = roster[2]
			rosterdata[roster[2]]['team'] = roster[3]
			rosterdata[roster[2]]['accountDBID'] = roster[7]
			rosterdata[roster[2]]['clanAbbrev'] = roster[8]
			rosterdata[roster[2]]['clanID'] = roster[9]
			rosterdata[roster[2]]['prebattleID'] = roster[10]
			
			bindata = struct.unpack('<BBHHHHHH', roster[1][:14])
			rosterdata[roster[2]]['countryID'] = bindata[0] >> 4 & 15
			rosterdata[roster[2]]['tankID'] = bindata[1]
			compDescr = (bindata[1] << 8) + bindata[0]
			rosterdata[roster[2]]['compDescr'] = compDescr
			
			rosterdata[roster[2]]['vehicle'] = dict()
			
			# Does not make sense, will check later
			# rosterdata[roster[2]]['vehicle']['chassisID'] = bindata[2]
			# rosterdata[roster[2]]['vehicle']['engineID'] = bindata[3]
			# rosterdata[roster[2]]['vehicle']['fueltankID'] = bindata[4]
			# rosterdata[roster[2]]['vehicle']['radioID'] = bindata[5]
			# rosterdata[roster[2]]['vehicle']['turretID'] = bindata[6]
			# rosterdata[roster[2]]['vehicle']['gunID'] = bindata[7]

			
			# Thanks to Rembel
			flags = struct.unpack('B', roster[1][14])[0]
			
			optional_devices_mask = flags & 15

			idx = 2

			pos = 15
			
		
			while optional_devices_mask:
				if optional_devices_mask & 1:
					try:
						if len(roster[1]) >= pos+2:
							m = struct.unpack('H', roster[1][pos:pos+2])[0]
							rosterdata[roster[2]]['vehicle']['module_' + str(idx)] = m
					except Exception, e:
						printmessage('error on processing player [' + str(roster[2]) + ']: '  + e.message)
				else:
					rosterdata[roster[2]]['vehicle']['module_' + str(idx)] = -1
				
				optional_devices_mask = optional_devices_mask >> 1
				idx = idx - 1
				pos = pos + 2
	
			
		advanced['roster'] = rosterdata
	
	advanced['valid'] = 1
	return advanced
			
	
# Thanks to https://github.com/marklr/wotanalysis
def extract_chats(fn):
	chat = dict()
	with open(fn, 'rb') as f:
	    s = f.read()
	    p = re.compile(r'<font.*>.*?</font>')
	    chat = p.findall(s)
	
	# Prepare Chat for usage on vBAddict
	extracted_chat = ''
	for line in chat: 
		line = line.encode("string-escape")
		#repr(line)
		extracted_chat = extracted_chat + line + '<br/>'
		
	return extracted_chat
		
	    

# Thanks to https://github.com/marklr/wotanalysis
def decrypt_file(fn, offset=0):
	key = ''.join(['\xDE', '\x72', '\xBE', '\xA0', '\xDE', '\x04', '\xBE', '\xB1', '\xDE', '\xFE', '\xBE', '\xEF', '\xDE', '\xAD', '\xBE', '\xEF'])
	bc = 0
	pb = None
	from blowfish import Blowfish
	from binascii import b2a_hex
	bf = Blowfish(key)
	printmessage("Decrypting from offset {}".format(offset))
	of = fn + ".tmp"
	with open(fn, 'rb') as f:

		f.seek(offset)
		with open(of, 'wb') as out:
			while True:
				b = f.read(8)
				if not b:
					break
	
				if len(b) < 8:
					b += '\x00' * (8 - len(b))  # pad for correct blocksize
	
				if bc > 0:
					db = bf.decrypt(b)
					if pb:
						db = ''.join([chr(int(b2a_hex(a), 16) ^ int(b2a_hex(b), 16)) for a, b in zip(db, pb)])
	
					pb = db
					out.write(db)
				bc += 1
	        return of
	return None


# Thanks to https://github.com/marklr/wotanalysis
def decompress_file(fn):
	printmessage("Decompressing")
	import zlib
	with open(fn, 'rb') as i:
	    with open(fn + '.out', 'wb') as o:
	        o.write(zlib.decompress(i.read()))
	        return fn + ".out"
	    deleteFile(fn)

if __name__ == '__main__':
	main()
