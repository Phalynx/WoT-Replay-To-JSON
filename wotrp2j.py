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

	parserversion = "0.9.0.3"

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

	if numofblocks > 4:
		f.seek(0)
		firstbytes = struct.unpack("B",f.read(1))[0]
		if firstbytes==14:
			result_blocks['common']['message'] = "uncompressed replay"
			result_blocks['datablock_advanced'] = extract_advanced(filename_source)
			result_blocks['identify']['arenaUniqueID'] = result_blocks['datablock_advanced']['arenaUniqueID']
			result_blocks['common']['datablock_advanced'] = 1

		if option_chat==1:
			result_blocks['chat'] = extract_chats(filename_source)
			result_blocks['common']['datablock_chat'] = 1
		
		dumpjson(result_blocks, filename_source, 0)

	
	

	while numofblocks >= 1:
		try:
			printmessage("Getting Block " + str(blockNum))
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
		

	for i in datablockSize:
		
		try:
			f.seek(datablockPointer[i])
								
			myblock = f.read(int(datablockSize[i]))

			js = json.loads(myblock)

			if 'arenaUniqueID' in myblock:

				#print type(replay_version_dict), replay_version_dict
				if (int(replay_version_dict[1]) == 8 and int(replay_version_dict[2]) > 10) or int(replay_version_dict[1]) > 8 or myblock[0]=='[':
					br_json_list = json.loads(myblock)
					
					br_block = br_json_list[0]

					if len(br_json_list) > 0:
						result_blocks['datablock_1']['vehicles'] = br_json_list[1]

					if len(br_json_list) > 1:
						result_blocks['datablock_1']['kills'] = br_json_list[2]

				else:


					from SafeUnpickler import SafeUnpickler
					br_block = SafeUnpickler.loads(myblock)				
					
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
					
					for key, value in result_blocks['datablock_battle_result']['players'].items(): 
						for vkey, vvalue in result_blocks['datablock_battle_result']['vehicles'].items(): 
							if result_blocks['datablock_battle_result']['vehicles'][vkey]['accountDBID'] == key: 
								result_blocks['datablock_battle_result']['players'][key]['vehicleid'] = vkey 
								break

					result_blocks['common']['datablock_battle_result'] = 1
					result_blocks['identify']['arenaUniqueID'] = result_blocks['datablock_battle_result']['arenaUniqueID']
					
			else:
				blockdict = dict()
				blockdict = json.loads(myblock)
				
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
			result_blocks['datablock_advanced'] = extract_advanced(uncompressed)
			result_blocks['common']['datablock_advanced'] = 1

		if option_chat==1:
			result_blocks['chat'] = extract_chats(uncompressed)
			result_blocks['common']['datablock_chat'] = 1
			
		os.unlink(decfile)
		os.unlink(uncompressed)
	
		
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

	sys.exit(exitcode)


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

# Thanks to https://github.com/benvanstaveren/wot-replays
def extract_advanced(fn):
	advanced = dict()
	with open(fn, 'rb') as f:
		f.seek(61)

		playernamelength = struct.unpack("B",f.read(1))[0]
		advanced['playername'] = f.read(playernamelength)
		advanced['arenaUniqueID'] = struct.unpack("Q",f.read(8))[0]
		advanced['battleStartTime'] = advanced['arenaUniqueID'] & 4294967295L
		advanced['arenaTypeID'] = struct.unpack("I",f.read(4))[0]
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
			printmessage('cannot load pickle: ' + e.message)
	
		f.seek(f.tell()+29)
		
		advancedlength = struct.unpack("B",f.read(1))[0]

		if advancedlength==255:
			advancedlength = struct.unpack("H",f.read(2))[0]
			f.read(1)
			
		#try:
		rosters = []
		advanced_pickles = f.read(advancedlength)
		from SafeUnpickler import SafeUnpickler
		rosters = SafeUnpickler.loads(advanced_pickles)		
		rosterdata = dict()
		for roster in rosters:
			rosterdata[roster[0]] = dict()
			rosterdata[roster[0]]['internaluserid'] = roster[0]
			rosterdata[roster[0]]['playerName'] = roster[2]
			rosterdata[roster[0]]['team'] = roster[3]
			rosterdata[roster[0]]['playerID'] = roster[7]
			rosterdata[roster[0]]['clanAbbrev'] = roster[8]
			rosterdata[roster[0]]['clanID'] = roster[9]
			rosterdata[roster[0]]['prebattleID'] = roster[10]
			
			binstruct = '<BBHHHHHH'
			bindata = struct.unpack(binstruct, roster[1][:14])
			rosterdata[roster[0]]['countryID'] = bindata[0] >> 4 & 15
			rosterdata[roster[0]]['tankID'] = bindata[1]
			compDescr = (bindata[1] << 8) + bindata[0]
			rosterdata[roster[0]]['compDescr'] = compDescr
			
			# Does not make sense, will check later
			#rosterdata[roster[0]]['vehicle'] = dict()
			#rosterdata[roster[0]]['vehicle']['chassisID'] = bindata[2]
			#rosterdata[roster[0]]['vehicle']['engineID'] = bindata[3]
			#rosterdata[roster[0]]['vehicle']['fueltankID'] = bindata[4]
			#rosterdata[roster[0]]['vehicle']['radioID'] = bindata[5]
			#rosterdata[roster[0]]['vehicle']['turretID'] = bindata[6]
			#rosterdata[roster[0]]['vehicle']['gunID'] = bindata[7]
			
		advanced['roster'] = rosterdata

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
	    os.unlink(fn)






if __name__ == '__main__':
	main()
