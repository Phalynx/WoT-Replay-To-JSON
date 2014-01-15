WoT-Replay-To-JSON v8.10.0 
==============================================================

* wotrp2j.py
* Author: Marius Czyz aka Phalynx
* Contact: marius.czyz@gmail.com
* Website: http://www.vbaddict.net
* Wiki: http://wiki.vbaddict.net
* Repo: https://github.com/Phalynx/WoT-Replay-To-JSON

# Supported Versions
* WoT 0.7.x and higher. 
* Latest tested version: WoT 0.8.10.

# Python
* You need Python 2.7, or just use the compiled version wotrp2j.exe

# Usage
* wotrp2j.pyc <replay.wotreplay>
		creates a text file with the name of the replay where the extension has been replaced by ".json"
	
* wotrp2j.pyc <replay.wotreplay> -c
		Console mode, suppress all messages and print parsed replay to the console window

* wotrp2j.pyc <replay.wotreplay> -chat
		Include chat. Increasing the processing time as the binary part of the replay is decrypted and uncompressed

	Example:
		python.exe wotrp2j.pyc 20130126_2329_ussr-Object_704_07_lakeville.wotreplay

	Example:
		python.exe wotrp2j.pyc 20130619_2232_ussr-SU-101_02_malinovka.wotreplay -c

	Without installing Python, you can use wotrp2j.exe instead of wotrp2j.pyc

# Structure:
* common[status] = "ok" or "error"
* common[message] = detailed error, otherwise "ok"
* common[parser] = Version of used script
* common[datablock_1] = Datablock 1 exists
* common[datablock_2] = Datablock 2 exists
* common[datablock_battle_result] = Battle Result exists
	
	
	If the replay can be read, the file will contain additional blocks:
* datablock_1
* datablock_2 - not always available
* datablock_battle_result - available only for replays created by WoT 0.8.2 or higher
	Value of -1 is indicating a corrupt/wrong inserted Battle Result due to a bug in WoT
* chat - Available only with the option -chat
* identify - Contains data used by vBAddict to identify a replay
	
# Credits
* https://github.com/marklr/wotanalysis
* https://github.com/raszpl/wotdecoder
* Parser for replays of WoT 0.7.2 by Vit@liy and Aborche, http://aborche.com/tst/WoT/parser072.py
