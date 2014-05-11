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

	parserversion = "0.9.0.6"

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
	result_blocks['identify'] = dict()
	result_blocks['identify']['arenaUniqueID'] = 0
	
	result_blocks['common']['parser'] = "WoT-Replay-To-JSON " + parserversion + " by http://www.vbaddict.net"
	
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
			printmessage("Retrieving block " + str(processing_block))
			f.seek(datablockPointer[i])
								
			myblock = f.read(int(datablockSize[i]))


			if 'arenaUniqueID' in myblock:

				if (int(replay_version_dict[1]) == 8 and int(replay_version_dict[2]) > 10) or int(replay_version_dict[1]) > 8 or myblock[0]=='[':
					br_json_list = dict()
					try:
						br_json_list = json.loads(myblock)
					except Exception, e:
						printmessage("Error with JSON: " + e.message)
					
					br_block = br_json_list[0]

					if len(br_json_list) > 0:
						result_blocks['datablock_1']['vehicles'] = br_json_list[1]

					if len(br_json_list) > 1:
						result_blocks['datablock_1']['kills'] = br_json_list[2]

				else:

					try:
						from SafeUnpickler import SafeUnpickler
						br_block = SafeUnpickler.loads(myblock)				
					except Exception, e:
						printmessage("Error with unpickling myblock: " + e.message)
					
				if 'vehicles' in br_block:
					for key, value in br_block['vehicles'].items():
						
						if br_block['vehicles'][key]['typeCompDescr'] > 0:
							br_block['vehicles'][key]['tankID'] = br_block['vehicles'][key]['typeCompDescr'] >> 8 & 65535
							br_block['vehicles'][key]['countryID'] = br_block['vehicles'][key]['typeCompDescr'] >> 4 & 15
						
						if 'details' in br_block['vehicles'][key]:
							del br_block['vehicles'][key]['details']
					
						
						#br_block['vehicles'][key]['details'] = decode_details(value['details'])
						#br_block['vehicles'][key]['details'] = decode_crits(br_block['vehicles'][key]['details'])
						
					br_block['personal']['details'] = decode_crits(br_block['personal']['details'])
					
					br_block['personal'] = keepCompatibility(br_block['personal'])
					
					result_blocks['datablock_battle_result'] = br_block
					result_blocks['datablock_battle_result']['common']['gameplayID'] = result_blocks['datablock_battle_result']['common']['arenaTypeID'] >> 16
					result_blocks['datablock_battle_result']['common']['arenaTypeID'] = result_blocks['datablock_battle_result']['common']['arenaTypeID'] & 32767
					
					result_blocks['datablock_battle_result']['personal']['achievements'] = decodeDossierPopups(result_blocks['datablock_battle_result']['personal'])
				
					for key, value in result_blocks['datablock_battle_result']['players'].items(): 
						for vkey, vvalue in result_blocks['datablock_battle_result']['vehicles'].items(): 
							if result_blocks['datablock_battle_result']['vehicles'][vkey]['accountDBID'] == key: 
								result_blocks['datablock_battle_result']['players'][key]['vehicleid'] = vkey 
								break

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

		except Exception, e:
			result_blocks['common']['message'] = e.message
			dumpjson(result_blocks, filename_source, 1)

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
			result_blocks['chat'] = extract_chats(uncompressed)
			result_blocks['common']['datablock_chat'] = 1

		
	dumpjson(result_blocks, filename_source, 0)


def cleanReplayVersion(replay_version):
	replay_version = replay_version.replace(', ', '.')
	replay_version = replay_version.replace(' ', '.')
	#return replay_version.split('.')[:3]
	return replay_version

# Create block to identify replay even without arenaUniqueID, needed for vBAddict.net
def get_identify(result_blocks):
	
	internaluserID = 0
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


	if not "datablock_battle_result" in result_blocks['common']:
		return result_blocks

	result_blocks['datablock_battle_result']['personal']['tankid'] = tankid
	result_blocks['datablock_battle_result']['personal']['countryid'] = countryid
	result_blocks['datablock_battle_result']['personal']['countryid'] = countryid
	result_blocks['datablock_battle_result']['personal']['won'] = True if result_blocks['datablock_battle_result']['common']['winnerTeam'] == result_blocks['datablock_battle_result']['personal']['team'] else False

	for key, value in result_blocks['datablock_battle_result']['players'].items(): 
	    result_blocks['datablock_battle_result']['players'][key]['platoonID'] = result_blocks['datablock_battle_result']['players'][key]['prebattleID'] 
	    del result_blocks['datablock_battle_result']['players'][key]['prebattleID'] 
	      
	    for vkey, vvalue in result_blocks['datablock_battle_result']['vehicles'].items(): 
	        if result_blocks['datablock_battle_result']['vehicles'][vkey]['accountDBID'] == key: 
	            result_blocks['datablock_battle_result']['players'][key]['vehicleid'] = vkey 
	            break


	correct_battle_result = 1;
	

	if result_blocks['identify']['mapid'] != result_blocks['datablock_battle_result']['common']['arenaTypeID']:
		correct_battle_result = 0
	
	typeCompDescr = make_typeCompDescr(result_blocks['identify']['countryid'], result_blocks['identify']['tankid'])

	if typeCompDescr != result_blocks['datablock_battle_result']['personal']['typeCompDescr']:
		correct_battle_result = 0


	if correct_battle_result == 0:
		printmessage('Incorrect Battle Result')
		del result_blocks['datablock_battle_result']
		result_blocks['common']['datablock_battle_result'] = -1
		result_blocks['identify']['arenaUniqueID'] = 0


	return result_blocks
	
def make_typeCompDescr(countryid, tankid):
	countryshift = 1 + (countryid << 4)
	return (tankid << 8) + countryshift
	
def keepCompatibility(structureddata):
	# Compatibility with older versions
	# Some names changed in WoT 0.9.0
		
	if 'directHits' in structureddata:
		structureddata['hits'] = structureddata['directHits']
		
	if 'explosionHits' in structureddata:
		structureddata['he_hits'] = structureddata['explosionHits']
		
	if 'piercings' in structureddata:
		structureddata['pierced'] = structureddata['piercings']
				
	if 'explosionHitsReceived' in structureddata:
		structureddata['heHitsReceived'] = structureddata['explosionHitsReceived']
		
	if 'directHitsReceived' in structureddata:
		structureddata['shotsReceived'] = structureddata['directHitsReceived']
		
	if 'noDamageDirectHitsReceived' in structureddata:
		structureddata['noDamageShotsReceived'] = structureddata['noDamageDirectHitsReceived']
		

	return structureddata



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
		write_to_log("WOTRP2J: " + str(mydict['common']['message']))
	
	
	if option_console==0:
		filename_target = os.path.splitext(filename_source)[0]
		filename_target = filename_target + '.json'
		
		if option_advanced==0 and option_chat==0 :
			finalfile = open(filename_target, 'w')
			finalfile.write(json.dumps(mydict, sort_keys=True, indent=4)) 		
			finalfile.close()
			
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
			
			# Does not make sense, will check later
			# rosterdata[roster[2]]['vehicle'] = dict()
			# rosterdata[roster[2]]['vehicle']['chassisID'] = bindata[2]
			# rosterdata[roster[2]]['vehicle']['engineID'] = bindata[3]
			# rosterdata[roster[2]]['vehicle']['fueltankID'] = bindata[4]
			# rosterdata[roster[2]]['vehicle']['radioID'] = bindata[5]
			# rosterdata[roster[2]]['vehicle']['turretID'] = bindata[6]
			# rosterdata[roster[2]]['vehicle']['gunID'] = bindata[7]

					
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

		
def decodeDossierPopups(personal):
	personal_achievements = []
	if not 'dossierPopUps' in personal:
		return personal_achievements
		
	all_achievements = listAchievements()
		
	for achievement in personal['dossierPopUps']:
		user_achievement = all_achievements[achievement[0]], achievement[1]
		personal_achievements.append(user_achievement)

	return personal_achievements

		
def listAchievements():
	achievements = dict()
	achievements[1] = 'xp'
	achievements[2] = 'maxXP'
	achievements[3] = 'battlesCount'
	achievements[4] = 'wins'
	achievements[5] = 'losses'
	achievements[6] = 'survivedBattles'
	achievements[7] = 'lastBattleTime'
	achievements[8] = 'battleLifeTime'
	achievements[9] = 'winAndSurvived'
	achievements[10] = 'battleHeroes'
	achievements[11] = 'frags'
	achievements[12] = 'maxFrags'
	achievements[13] = 'frags8p'
	achievements[14] = 'fragsBeast'
	achievements[15] = 'shots'
	achievements[16] = 'directHits'
	achievements[17] = 'spotted'
	achievements[18] = 'damageDealt'
	achievements[19] = 'damageReceived'
	achievements[20] = 'treesCut'
	achievements[21] = 'capturePoints'
	achievements[22] = 'droppedCapturePoints'
	achievements[23] = 'sniperSeries'
	achievements[24] = 'maxSniperSeries'
	achievements[25] = 'invincibleSeries'
	achievements[26] = 'maxInvincibleSeries'
	achievements[27] = 'diehardSeries'
	achievements[28] = 'maxDiehardSeries'
	achievements[29] = 'killingSeries'
	achievements[30] = 'maxKillingSeries'
	achievements[31] = 'piercingSeries'
	achievements[32] = 'maxPiercingSeries'
	achievements[34] = 'warrior'
	achievements[35] = 'invader'
	achievements[36] = 'sniper'
	achievements[37] = 'defender'
	achievements[38] = 'steelwall'
	achievements[39] = 'supporter'
	achievements[40] = 'scout'
	achievements[41] = 'medalKay'
	achievements[42] = 'medalCarius'
	achievements[43] = 'medalKnispel'
	achievements[44] = 'medalPoppel'
	achievements[45] = 'medalAbrams'
	achievements[46] = 'medalLeClerc'
	achievements[47] = 'medalLavrinenko'
	achievements[48] = 'medalEkins'
	achievements[49] = 'medalWittmann'
	achievements[50] = 'medalOrlik'
	achievements[51] = 'medalOskin'
	achievements[52] = 'medalHalonen'
	achievements[53] = 'medalBurda'
	achievements[54] = 'medalBillotte'
	achievements[55] = 'medalKolobanov'
	achievements[56] = 'medalFadin'
	achievements[57] = 'tankExpert'
	achievements[58] = 'titleSniper'
	achievements[59] = 'invincible'
	achievements[60] = 'diehard'
	achievements[61] = 'raider'
	achievements[62] = 'handOfDeath'
	achievements[63] = 'armorPiercer'
	achievements[64] = 'kamikaze'
	achievements[65] = 'lumberjack'
	achievements[66] = 'beasthunter'
	achievements[67] = 'mousebane'
	achievements[68] = 'creationTime'
	achievements[69] = 'maxXPVehicle'
	achievements[70] = 'maxFragsVehicle'
	achievements[72] = 'evileye'
	achievements[73] = 'medalRadleyWalters'
	achievements[74] = 'medalLafayettePool'
	achievements[75] = 'medalBrunoPietro'
	achievements[76] = 'medalTarczay'
	achievements[77] = 'medalPascucci'
	achievements[78] = 'medalDumitru'
	achievements[79] = 'markOfMastery'
	achievements[80] = 'xp'
	achievements[81] = 'battlesCount'
	achievements[82] = 'wins'
	achievements[83] = 'losses'
	achievements[84] = 'survivedBattles'
	achievements[85] = 'frags'
	achievements[86] = 'shots'
	achievements[87] = 'directHits'
	achievements[88] = 'spotted'
	achievements[89] = 'damageDealt'
	achievements[90] = 'damageReceived'
	achievements[91] = 'capturePoints'
	achievements[92] = 'droppedCapturePoints'
	achievements[93] = 'xp'
	achievements[94] = 'battlesCount'
	achievements[95] = 'wins'
	achievements[96] = 'losses'
	achievements[97] = 'survivedBattles'
	achievements[98] = 'frags'
	achievements[99] = 'shots'
	achievements[100] = 'directHits'
	achievements[101] = 'spotted'
	achievements[102] = 'damageDealt'
	achievements[103] = 'damageReceived'
	achievements[104] = 'capturePoints'
	achievements[105] = 'droppedCapturePoints'
	achievements[106] = 'medalLehvaslaiho'
	achievements[107] = 'medalNikolas'
	achievements[108] = 'fragsSinai'
	achievements[109] = 'sinai'
	achievements[110] = 'heroesOfRassenay'
	achievements[111] = 'mechanicEngineer'
	achievements[112] = 'tankExpert0'
	achievements[113] = 'tankExpert1'
	achievements[114] = 'tankExpert2'
	achievements[115] = 'tankExpert3'
	achievements[116] = 'tankExpert4'
	achievements[117] = 'tankExpert5'
	achievements[118] = 'tankExpert6'
	achievements[119] = 'tankExpert7'
	achievements[120] = 'tankExpert8'
	achievements[121] = 'tankExpert9'
	achievements[122] = 'tankExpert10'
	achievements[123] = 'tankExpert11'
	achievements[124] = 'tankExpert12'
	achievements[125] = 'tankExpert13'
	achievements[126] = 'tankExpert14'
	achievements[127] = 'mechanicEngineer0'
	achievements[128] = 'mechanicEngineer1'
	achievements[129] = 'mechanicEngineer2'
	achievements[130] = 'mechanicEngineer3'
	achievements[131] = 'mechanicEngineer4'
	achievements[132] = 'mechanicEngineer5'
	achievements[133] = 'mechanicEngineer6'
	achievements[134] = 'mechanicEngineer7'
	achievements[135] = 'mechanicEngineer8'
	achievements[136] = 'mechanicEngineer9'
	achievements[137] = 'mechanicEngineer10'
	achievements[138] = 'mechanicEngineer11'
	achievements[139] = 'mechanicEngineer12'
	achievements[140] = 'mechanicEngineer13'
	achievements[141] = 'mechanicEngineer14'
	achievements[142] = 'gold'
	achievements[143] = 'medalBrothersInArms'
	achievements[144] = 'medalCrucialContribution'
	achievements[145] = 'medalDeLanglade'
	achievements[146] = 'medalTamadaYoshio'
	achievements[147] = 'bombardier'
	achievements[148] = 'huntsman'
	achievements[149] = 'alaric'
	achievements[150] = 'sturdy'
	achievements[151] = 'ironMan'
	achievements[152] = 'luckyDevil'
	achievements[153] = 'fragsPatton'
	achievements[154] = 'pattonValley'
	achievements[155] = 'xpBefore8_8'
	achievements[156] = 'battlesCountBefore8_8'
	achievements[157] = 'originalXP'
	achievements[158] = 'damageAssistedTrack'
	achievements[159] = 'damageAssistedRadio'
	achievements[160] = 'mileage'
	achievements[161] = 'directHitsReceived'
	achievements[162] = 'noDamageDirectHitsReceived'
	achievements[163] = 'piercingsReceived'
	achievements[164] = 'explosionHits'
	achievements[165] = 'piercings'
	achievements[166] = 'explosionHitsReceived'
	achievements[167] = 'mechanicEngineerStrg'
	achievements[168] = 'tankExpertStrg'
	achievements[169] = 'originalXP'
	achievements[170] = 'damageAssistedTrack'
	achievements[171] = 'damageAssistedRadio'
	achievements[173] = 'directHitsReceived'
	achievements[174] = 'noDamageDirectHitsReceived'
	achievements[175] = 'piercingsReceived'
	achievements[176] = 'explosionHitsReceived'
	achievements[177] = 'explosionHits'
	achievements[178] = 'piercings'
	achievements[179] = 'originalXP'
	achievements[180] = 'damageAssistedTrack'
	achievements[181] = 'damageAssistedRadio'
	achievements[183] = 'directHitsReceived'
	achievements[184] = 'noDamageDirectHitsReceived'
	achievements[185] = 'piercingsReceived'
	achievements[186] = 'explosionHitsReceived'
	achievements[187] = 'explosionHits'
	achievements[188] = 'piercings'
	achievements[189] = 'xp'
	achievements[190] = 'battlesCount'
	achievements[191] = 'wins'
	achievements[192] = 'losses'
	achievements[193] = 'survivedBattles'
	achievements[194] = 'frags'
	achievements[195] = 'shots'
	achievements[196] = 'directHits'
	achievements[197] = 'spotted'
	achievements[198] = 'damageDealt'
	achievements[199] = 'damageReceived'
	achievements[200] = 'capturePoints'
	achievements[201] = 'droppedCapturePoints'
	achievements[202] = 'originalXP'
	achievements[203] = 'damageAssistedTrack'
	achievements[204] = 'damageAssistedRadio'
	achievements[206] = 'directHitsReceived'
	achievements[207] = 'noDamageDirectHitsReceived'
	achievements[208] = 'piercingsReceived'
	achievements[209] = 'explosionHitsReceived'
	achievements[210] = 'explosionHits'
	achievements[211] = 'piercings'
	achievements[212] = 'xpBefore8_9'
	achievements[213] = 'battlesCountBefore8_9'
	achievements[214] = 'xpBefore8_9'
	achievements[215] = 'battlesCountBefore8_9'
	achievements[216] = 'winAndSurvived'
	achievements[217] = 'frags8p'
	achievements[218] = 'maxDamage'
	achievements[219] = 'maxDamageVehicle'
	achievements[220] = 'maxXP'
	achievements[221] = 'maxXPVehicle'
	achievements[222] = 'maxFrags'
	achievements[223] = 'maxFragsVehicle'
	achievements[224] = 'maxDamage'
	achievements[225] = 'maxDamageVehicle'
	achievements[226] = 'battlesCount'
	achievements[227] = 'sniper2'
	achievements[228] = 'mainGun'
	achievements[229] = 'wolfAmongSheep'
	achievements[230] = 'wolfAmongSheepMedal'
	achievements[231] = 'geniusForWar'
	achievements[232] = 'geniusForWarMedal'
	achievements[233] = 'kingOfTheHill'
	achievements[234] = 'tacticalBreakthroughSeries'
	achievements[235] = 'maxTacticalBreakthroughSeries'
	achievements[236] = 'armoredFist'
	achievements[237] = 'tacticalBreakthrough'
	achievements[238] = 'potentialDamageReceived'
	achievements[239] = 'damageBlockedByArmor'
	achievements[240] = 'potentialDamageReceived'
	achievements[241] = 'damageBlockedByArmor'
	achievements[242] = 'potentialDamageReceived'
	achievements[243] = 'damageBlockedByArmor'
	achievements[244] = 'potentialDamageReceived'
	achievements[245] = 'damageBlockedByArmor'
	achievements[246] = 'battlesCountBefore9_0'
	achievements[247] = 'battlesCountBefore9_0'
	achievements[248] = 'battlesCountBefore9_0'
	achievements[249] = 'battlesCountBefore9_0'
	achievements[250] = 'xp'
	achievements[251] = 'battlesCount'
	achievements[252] = 'wins'
	achievements[253] = 'winAndSurvived'
	achievements[254] = 'losses'
	achievements[255] = 'survivedBattles'
	achievements[256] = 'frags'
	achievements[257] = 'frags8p'
	achievements[258] = 'shots'
	achievements[259] = 'directHits'
	achievements[260] = 'spotted'
	achievements[261] = 'damageDealt'
	achievements[262] = 'damageReceived'
	achievements[263] = 'capturePoints'
	achievements[264] = 'droppedCapturePoints'
	achievements[265] = 'originalXP'
	achievements[266] = 'damageAssistedTrack'
	achievements[267] = 'damageAssistedRadio'
	achievements[268] = 'directHitsReceived'
	achievements[269] = 'noDamageDirectHitsReceived'
	achievements[270] = 'piercingsReceived'
	achievements[271] = 'explosionHitsReceived'
	achievements[272] = 'explosionHits'
	achievements[273] = 'piercings'
	achievements[274] = 'potentialDamageReceived'
	achievements[275] = 'damageBlockedByArmor'
	achievements[276] = 'maxXP'
	achievements[277] = 'maxXPVehicle'
	achievements[278] = 'maxFrags'
	achievements[279] = 'maxFragsVehicle'
	achievements[280] = 'maxDamage'
	achievements[281] = 'maxDamageVehicle'
	achievements[282] = 'guardsman'
	achievements[283] = 'makerOfHistory'
	achievements[284] = 'bothSidesWins'
	achievements[285] = 'weakVehiclesWins'
	achievements[286] = 'godOfWar'
	achievements[287] = 'fightingReconnaissance'
	achievements[288] = 'fightingReconnaissanceMedal'
	achievements[289] = 'willToWinSpirit'
	achievements[290] = 'crucialShot'
	achievements[291] = 'crucialShotMedal'
	achievements[292] = 'forTacticalOperations'
	achievements[293] = 'battleCitizen'
	achievements[294] = 'movingAvgDamage'
	achievements[295] = 'marksOnGun'
	achievements[296] = 'medalMonolith'
	achievements[297] = 'medalAntiSpgFire'
	achievements[298] = 'medalGore'
	achievements[299] = 'medalCoolBlood'
	achievements[300] = 'medalStark'
	achievements[301] = 'histBattle1_battlefield'
	achievements[302] = 'histBattle1_historyLessons'
	achievements[303] = 'histBattle2_battlefield'
	achievements[304] = 'histBattle2_historyLessons'
	achievements[305] = 'histBattle3_battlefield'
	achievements[306] = 'histBattle3_historyLessons'
	achievements[307] = 'histBattle4_battlefield'
	achievements[308] = 'histBattle4_historyLessons'

	return achievements



if __name__ == '__main__':
	main()
