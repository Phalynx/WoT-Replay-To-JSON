# parser for "unpacked" wotreplay files
# (C) 2014 by Vitaly Bogomolov mail@vitaly-bogomolov.ru
# based on:
# https://github.com/Phalynx/WoT-Replay-To-JSON
# https://github.com/evido/wotreplay-parser

import struct

# source: https://github.com/evido/wotreplay-parser
class Packet:
    
    # Replay version
    # * int32: length of the string
    # * char[]: version string
    VERSION = 0x14

    # This packet is related to the spotting of tanks, it will occurr together with packet type 0x05 when the tank appears for the user (each time).
    SPOTTING1 = 0x03
    SPOTTING2 = 0x05

    # Complex packet with subtypes
    # common field:
    # * player_id: the subject of the data
    # * sub_type: the sub-type of the packet
    #
    # SubType 0x03
    # * health: the health of the referenced player
    # This packet seems to be a health update which is sent relatively frequently, it only contains the following properties.
    #
    # SubType 0x07
    # * destroyed_track_id`: the id of the track that is still destroyed, possible values here are 0x00 (tank is not tracked), 0x1D (left track) and 0x1E (right track)
    # This packet seems to be sent when a player's tracks are repaired, it also indicates which track is still destroyed.
    HEALTH = 0x07

    # Complex packet with subtypes
    # common field:
    # * player_id: the subject of the data
    # * sub_type: the sub-type of the packet
    #
    # SubType 0x01
    # * source: player causing the damage
    # * health: new health of the player
    # This packet indicates a player doing damage to another player and will most likely be accompanied by another packet indicating the type of damage such as SubType 0x05
    #
    # SubType 0x05
    # * source: source of the shell
    # This packet indicates that a player was shot by another player. When this is not accompanied by a damage packet (SubType_0x01), the player bounced the shell.
    #
    # SubType 0x0B
    # * source: player dealing damage to the moduel
    # * target: player receiving the damage
    # Most likely the indicator of a module being damaged.
    #
    # SubType 0x11
    # Indicator that a shot was fired by a player.
    #
    # SubType 0x17
    # Unclear.
    DAMAGE = 0x08

    # This is the most frequent type of packet, it tells the player about the positions of any other player.
    # * player_id: the subject of the track status
    # * position: 
    # * hull_orientation: 
    POSITION = 0x0A

    # This packet contains a message sent to the battlelog during the game. The owner information is encoded inside the message.
    # <font color='#DA0400'>SmurfingBird[RDDTX] (VK 36.01 H)&nbsp;:&nbsp;</font><font color='#FFFFFF'>so far so good</font>
    # * int32: length of the message
    # * char[]: a html encoded message
    CHAT = 0x1F

    # This packet indicates that a player's tank was tracked.
    TRACKED = 0x20

    # Common replay info
    CREDENTIAL_MARK = 0x0E
    CREDENTIAL = 0x00
    
    # Unknown packet types
    PKT_1E = 0x1E
    PKT_02 = 0x02
    PKT_01 = 0x01
    PKT_11 = 0x11
    PKT_0B = 0x0B
    PKT_13 = 0x13
    PKT_12 = 0x12
    PKT_1C = 0x1C
    PKT_1B = 0x1B
    PKT_1D = 0x1D
    PKT_04 = 0x04
    PKT_22 = 0x22
    PKT_25 = 0x25
    PKT_17 = 0x17
    PKT_16 = 0x16
    PKT_19 = 0x19
    PKT_18 = 0x18

class KEY:
    """dictionary keys for result data"""
    HEADER          = 'header'
    CHAT            = 'chat'

    VERSION         = 'version'
    PLAYER          = 'playerID'
    ARENA_ID        = 'arenaUniqueID'
    ARENA_TYPE      = 'arenaTypeID'
    ARENA_TIME      = 'arenaCreateTime'
    BONUS_TYPE      = 'bonusType'
    GUI_TYPE        = 'guiType'
    GAMEPLAY        = 'gameplayID'
    BATTLE_LEVEL    = 'battleLevel'

# legacy replay packet header structure
# total size: 12 bytes
# fields:
# int32 (4 bytes) - size of packet body
# int32 (4 bytes) - packet ID (see class Packet)
# float (4 bytes) - packet timestamp in seconds
packet_head = "IIf"
packet_head_size = struct.calcsize(packet_head)

def read_string(buff):
    size, = struct.unpack_from("I", buff)
    return buff[4:4+size]

#######################
# packet read functions

def pkt_version(self, buff, clock):
    """extract data from body of packet 0x14"""
    self.data[KEY.HEADER] = {}
    self.data[KEY.HEADER][KEY.VERSION] = read_string(buff)

def pkt_chat(self, buff, clock):
    """extract data from body of packet 0x1F"""
    data = (read_string(buff), clock)
    if KEY.CHAT in self.data:
        self.data[KEY.CHAT].append(data)
    else:
        self.data[KEY.CHAT] = [data]

def pkt_credential(self, buff, clock):
    """extract data from header"""

    # skip unknown leading 10 bytes
    dat = buff[10:]
    size, = struct.unpack_from("B", dat)
    playerID = str(dat[1:1+size])
    dat = dat[1+size:]

    bin_data = "QIBBB"
    bin_data_size = struct.calcsize(bin_data)

    arenaUniqueID, arenaTypeID, bonusType, guiType, advancedlength = struct.unpack_from(bin_data, dat)
    dat = dat[bin_data_size:]

    if advancedlength==255:
        bin_data_adv = "HB"
        bin_data_adv_size = struct.calcsize(bin_data_adv)
        advancedlength, tmp = struct.unpack_from(bin_data_adv, dat)
        dat = dat[bin_data_adv_size:]

    ext_data = {'battleLevel': 0}
    try:
        advanced_pickles = dat[:advancedlength]
        from SafeUnpickler import SafeUnpickler
        ext_data = SafeUnpickler.loads(advanced_pickles)
    except Exception, e:
        pass

    dat = self.data[KEY.HEADER]

    dat[KEY.PLAYER] = playerID
    dat[KEY.ARENA_ID] = arenaUniqueID
    dat[KEY.ARENA_TYPE] = arenaTypeID & 32767
    dat[KEY.ARENA_TIME] = arenaUniqueID & 4294967295L
    dat[KEY.BONUS_TYPE] = bonusType
    dat[KEY.GUI_TYPE] = guiType
    dat[KEY.GAMEPLAY] = arenaTypeID >> 16
    dat[KEY.BATTLE_LEVEL] = 0
    if 'battleLevel' in ext_data:
        dat[KEY.BATTLE_LEVEL] = ext_data['battleLevel']

    self.data[KEY.HEADER] = dat

# map reader functions to known packets
packet_readers = {
    Packet.VERSION:     pkt_version,
    Packet.CHAT:        pkt_chat,
    Packet.CREDENTIAL:  pkt_credential,
}

class Data(object):

    def __init__(self, input_stream):
        self.data = {}
        buff = input_stream.read(packet_head_size)
        while buff:
            size, pkt_type, clock = struct.unpack_from(packet_head, buff)
            buff = input_stream.read(size)
            reader = packet_readers.get(pkt_type, None)
            if reader:
                reader(self, buff, clock)
            #else:
            #    print "%02X %.2f %d" % (pkt_type, clock, size)
            buff = input_stream.read(packet_head_size)

def main():

    import sys, json

    if len(sys.argv) > 1:

        try:
            rep = Data(open(sys.argv[1], 'rb'))

        except Exception, e:
            print "Error: %s" % e
            return

        print json.dumps(rep.data, sort_keys=True, indent=4)

    else:
        print "Usage:\npython legacy.py filename"

if __name__ == "__main__":
    main()
