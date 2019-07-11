#ifndef WLAN_SNIFF_H
#define WLAN_SNIFF_H

/*
 * Authored by
 * Dennis Krummacker (25.06.15-)
 */

#include <sys/stat.h>
#include <linux/types.h>
#include <sys/types.h>
#include <stdint.h>
#include <pcap.h>
#include <ieee80211.h>




#define ERR_WLAN_SNIFF_BAD_DEVICE 666
#define ERR_WLAN_SNIFF_BAD_PACKAGE 667


struct sigkill_wlanmon_struct {
	pcap_t *handlectrl;
	pthread_t thread_wlan_mon;
	char cancel;
};



//-------------------------------------------------------------------
//		Section for Wireless Packages Sniffing / Parsing
//-------------------------------------------------------------------


/* ugly shortcuts - Defining our header types */
#define ETH_HEADER_SIZE 14
#define AVS_HEADER_SIZE 64                 /* AVS capture header size */
#define DATA_80211_FRAME_SIZE 24           /* header for 802.11 data packet */
#define LLC_HEADER_SIZE 8                  /* LLC frame for encapsulation */



enum WifiSnifferHeadType {
	WLANSNIFF_LINKTYPE_ETHERNET,
	WLANSNIFF_LINKTYPE_IEEE802_11,
	WLANSNIFF_LINKTYPE_IEEE802_11_RADIOTAP,
	WLANSNIFF_LINKTYPE_IEEE802_11_PRISM,
	WLANSNIFF_LINKTYPE_IEEE802_11_AVS
};

//	MAC Frame Formats
//	(What consists a 802.11 Frame of?)
//		Basic components
//		Each frame consists of the following basic components:
//			a) A  MAC  header,  which  comprises  frame  control,  duration,  address,  optional  sequence  control
//			information, optional QoS Control information (QoS data frames only), and optional HT Control
//			fields (+HTC frames only);
//				Further Information for the Header follows underneath
//			b) A variable-length frame body, which contains information specific to the frame type and subtype;
//			c) A FCS, which contains an IEEE 32-bit CRC.


struct IEEE80211_MAC_Frame_Header_V2{
	uint16_t FrameControl;
	uint16_t DurationID;
	uint8_t Addr1[6];
	uint8_t Addr2[6];//Holds the Source MAC Address
	uint8_t Addr3[6];
	uint8_t SequenceControl[6];
	uint16_t Addr4;
};
struct IEEE80211_MAC_Frame_Header{
	struct{
		uint8_t B1;
		uint8_t B2;
	}FrameControl;
	struct{
		uint8_t B1;
		uint8_t B2;
	}DurationID;
	uint8_t Addr1[6];
	uint8_t Addr2[6];//Holds the Source MAC Address
	uint8_t Addr3[6];
	uint8_t SequenceControl[2];
	union{
		struct{
			uint8_t Addr4[6];
		}Addr4;
		struct{
			uint8_t QoSControl[2];
		}QoS;
		struct{
			uint8_t HTControl[2];
		}HT;
		struct{
			uint8_t Addr4[6];
			uint8_t QoSControl[2];
		}Addr4_QoS;
		struct{
			uint8_t Addr4[6];
			uint8_t HTControl[2];
		}Addr4_HT;
		struct{
			uint8_t QoSControl[2];
			uint8_t HTControl[2];
		}QoS_HT;
		struct{
			uint8_t Addr4[6];
			uint8_t QoSControl[2];
			uint8_t HTControl[2];
		}Addr4_QoS_HT;
	}optional;
};
typedef uint32_t IEEE80211_FCS;// The Frame-Check-Sequence comes in every Frame right after the actual Header.
//========================
// INFO about the optional union:
//		Frame is QoS-Data-Frame, if
//			- Type: Data -> "10"
//			- Subtype Bit 1 -> "1". I.e. "1XXX"
//		Address 4 is only present, if
//			- To DS and From DS are both "1"
//		HTControl is present, if
//			- Order-Bit in FrameControl is set
//	E.g.:
//		- You got a frame with
//			|- Type "Data", Subtype with first Bit = '0', e.g. "0011"
//			|- (IEEE80211_FRAMECONTROL_TO_DS ## IEEE80211_FRAMECONTROL_FROM_DS) == "11"
//			|- IEEE80211_FRAMECONTROL_ORDER == '1'
//			== This gives you "optional.Addr4_HT"
//		- Otherwise, if you would have
//			|- Type "Data", Subtype == "1000", i.e. QoS Data (first Bit == '1')
//			|- (IEEE80211_FRAMECONTROL_TO_DS ## IEEE80211_FRAMECONTROL_FROM_DS) == "11"
//			|- IEEE80211_FRAMECONTROL_ORDER == '0'
//			== This gives you "optional.Addr4_QoS"
//========================
//=====================================================================================================																						//Hiden Info: http://stackoverflow.com/questions/12407145/interpreting-frame-control-bytes-in-802-11-wireshark-trace
// INFO: Shame on the 802.11 Standard and all this inconsistent endianess stuff -.-
// 		You thought at least the Bit-ordering inside Bytes should be straight forward?
// 		No way! The first Byte of the frame control isn't "Version|Type|Subtype" in reality...
// 		It is: "Subtype|Type|Version", but not just mirror switched... the bits inside a field stay straight -.-
// 		How stupidly inconsistent is this?
//  Don't get me wrong. I'm very familiar with all this 'basic' endianess fun. I know how to handle between all this
//  Network-Byte-Order, Architecture Byte Order, mixed with Big-Endian and little-Endian, communicate and convert
//  between them. Everything fine, no problem. There we have consistent rules and know how the Pony rides...
// 		But, really, THIS capricious, willfully flipping of 'Bitgroups' inside of Bytes goes to far...
//		C'mon! We take a group of four Bits and two groups of two Bits. Then we flip these Groups of different Size,
//		but let the order inside of this groups stay. This is ridiculous!
// So, let me show you a example:
// 	The ACK-Frame (Control):
// DEC	HEX		Subtype		Type	Version		Combined		What you (we) expected
// 212	D4		1101		01		00			1101 01 00		00 01 1101
//=====================================================================================================
//			FIELD									REALITY							||		802.11 Standard
#define IEEE80211_FRAMECONTROL_PROTO_V			0x03	// 0000 00XX | 0000 0000	||	 0xC0	// XX00 0000 | 0000 0000
#define IEEE80211_FRAMECONTROL_FRAME_TYPE		0x0C	// 0000 XX00 | 0000 0000	||	 0x30	// 00XX 0000 | 0000 0000
#define IEEE80211_FRAMECONTROL_FRAME_SUBTYPE	0xF0	// XXXX 0000 | 0000 0000	||	 0x0F	// 0000 XXXX | 0000 0000
//------------------------------------------------------------------------------
#define IEEE80211_FRAMECONTROL_TO_DS			0x01	// 0000 0000 | 0000 000X	||	 0x80	// 0000 0000 | X000 0000
#define IEEE80211_FRAMECONTROL_FROM_DS			0x02	// 0000 0000 | 0000 00X0	||	 0x40	// 0000 0000 | 0X00 0000
#define IEEE80211_FRAMECONTROL_MORE_FRAG		0x04	// 0000 0000 | 0000 0X00	||	 0x20	// 0000 0000 | 00X0 0000
#define IEEE80211_FRAMECONTROL_RETRY			0x08	// 0000 0000 | 0000 X000	||	 0x10	// 0000 0000 | 000X 0000
#define IEEE80211_FRAMECONTROL_PWR_MGT			0x10	// 0000 0000 | 000X 0000	||	 0x08	// 0000 0000 | 0000 X000
#define IEEE80211_FRAMECONTROL_MORE_DATA		0x20	// 0000 0000 | 00X0 0000	||	 0x04	// 0000 0000 | 0000 0X00
#define IEEE80211_FRAMECONTROL_PROTECTED		0x40	// 0000 0000 | 0X00 0000	||	 0x02	// 0000 0000 | 0000 00X0
#define IEEE80211_FRAMECONTROL_ORDER			0x80	// 0000 0000 | X000 0000	||	 0x01	// 0000 0000 | 0000 000X


// Not longer used like this:
//#define IEEE80211_FRAMECONTROL_PROTO_V			0xC000	// XX00 0000 | 0000 0000
//#define IEEE80211_FRAMECONTROL_FRAME_TYPE		0x3000	// 00XX 0000 | 0000 0000
//#define IEEE80211_FRAMECONTROL_FRAME_SUBTYPE	0x0F00	// 0000 XXXX | 0000 0000
//#define IEEE80211_FRAMECONTROL_TO_DS			0x0080	// 0000 0000 | X000 0000
//#define IEEE80211_FRAMECONTROL_FROM_DS			0x0040	// 0000 0000 | 0X00 0000
//#define IEEE80211_FRAMECONTROL_MORE_FRAG		0x0020	// 0000 0000 | 00X0 0000
//#define IEEE80211_FRAMECONTROL_RETRY			0x0010	// 0000 0000 | 000X 0000
//#define IEEE80211_FRAMECONTROL_PWR_MGT			0x0008	// 0000 0000 | 0000 X000
//#define IEEE80211_FRAMECONTROL_MORE_DATA		0x0004	// 0000 0000 | 0000 0X00
//#define IEEE80211_FRAMECONTROL_WEP				0x0002	// 0000 0000 | 0000 00X0
//#define IEEE80211_FRAMECONTROL_RSVD				0x0001	// 0000 0000 | 0000 000X


#define IEEE80211_FRAME_TYPE_MANAGEMENT 0x00
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__ASSOCIATION_REQUEST 0x00
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__ASSOCIATION_RESPONSE 0x10
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__REASSOCIATION_REQUEST 0x20
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__REASSOCIATION_RESPONSE 0x30
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__PROBE_REQUEST 0x40
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__PROBE_RESPONSE 0x50
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__BEACON 0x80
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__ATIM 0x90
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__DISASSOCIATION 0xA0
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__AUTHENTICATION 0xB0
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__DEAUTHENTICATION 0xC0
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_60 0x60
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_70 0x70
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_D0 0xD0
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_E0 0xE0
	#define IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_F0 0xF0
#define IEEE80211_FRAME_TYPE_CONTROL 0x04
	#define IEEE80211_FRAME_SUBTYPE_CONTROL__PS_POLL 0xA0
	#define IEEE80211_FRAME_SUBTYPE_CONTROL__RTS 0xB0
	#define IEEE80211_FRAME_SUBTYPE_CONTROL__CTS 0xC0
	#define IEEE80211_FRAME_SUBTYPE_CONTROL__ACK 0xD0
	#define IEEE80211_FRAME_SUBTYPE_CONTROL__CF_END 0xE0
	#define IEEE80211_FRAME_SUBTYPE_CONTROL__CF_ACK 0xF0
#define IEEE80211_FRAME_TYPE_DATA 0x08
	#define IEEE80211_FRAME_SUBTYPE_DATA__DATA 0x00
	#define IEEE80211_FRAME_SUBTYPE_DATA__DATA_CF_ACK 0x10
	#define IEEE80211_FRAME_SUBTYPE_DATA__DATA_CF_POLL 0x20
	#define IEEE80211_FRAME_SUBTYPE_DATA__DATA_CF_ACK_POLL 0x30
	#define IEEE80211_FRAME_SUBTYPE_DATA__NULL 0x40
	#define IEEE80211_FRAME_SUBTYPE_DATA__CF_ACK 0x50
	#define IEEE80211_FRAME_SUBTYPE_DATA__CF_POLL 0x60
	#define IEEE80211_FRAME_SUBTYPE_DATA__CF_ACK_POLL 0x70
	#define IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA 0x80
	#define IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA_CF_ACK 0x90
	#define IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA_CF_POLL 0xA0
	#define IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA_CF_ACK_POLL 0xB0
	#define IEEE80211_FRAME_SUBTYPE_DATA__QOS_NULL 0xC0
	#define IEEE80211_FRAME_SUBTYPE_DATA__QOS_CF_POLL_NODATA 0xE0
	#define IEEE80211_FRAME_SUBTYPE_DATA__QOS_CF_ACK_POLL_NODATA 0xF0
#define IEEE80211_FRAME_TYPE_RESERVED 0x0C

//-------------------------------------------------------------------
//		End Packages Sniffing / Parsing
//-------------------------------------------------------------------






//-------------------------------------------------------------------
//		Section for "Delivery of the sniffed Data"
//-------------------------------------------------------------------

struct WifiPackageParseData {
	char mac[6];//Hardware-Address of Sender
	int8_t rssi;//Received Signal Strength Indicator of received Signal
};

struct wlansniff_chain_start {
	unsigned int freq;
	double trafficstat;//Detected Packets per Second
	unsigned int count;
	struct WifiPackageParseData *start;
};

struct wlansniff_pack_stat{
	unsigned long long packc;//Number of packets altogether
	struct{//Management Frames
		unsigned long long packc;//Management Frames altogether
		unsigned long long packc_ass_req;
		unsigned long long packc_ass_resp;
		unsigned long long packc_reass_req;
		unsigned long long packc_reass_resp;
		unsigned long long packc_probe_req;
		unsigned long long packc_probe_resp;
		unsigned long long packc_reserved;
		unsigned long long packc_beacon;//Beacon Frames
		unsigned long long packc_atim;
		unsigned long long packc_disass;
		unsigned long long packc_auth;
		unsigned long long packc_deauth;
		unsigned long long packc_reserved2;
		struct{
			double average;
			double ave_beacon;
			double ave_no_beacon;
		}size;
	}man;
	struct{//Control Frames
		unsigned long long packc;//Control Frames altogether
		unsigned long long packc_reserved;
		unsigned long long packc_ps;
		unsigned long long packc_rts;
		unsigned long long packc_cts;
		unsigned long long packc_ack;
		unsigned long long packc_cf;
		unsigned long long packc_cf_ack;
		struct{
			double average;
		}size;
	}ctrl;
	struct{//Data Frames
		unsigned long long packc;//Data Frames altogether
		unsigned long long packc_data_actual;//"Real" Data Frames, i.e. Subtypes 'b0000','b0001','b0010','b0011'
		unsigned long long packc_data;
		unsigned long long packc_data_cf_ack;
		unsigned long long packc_data_cf_poll;
		unsigned long long packc_data_cf_ack_poll;
		unsigned long long packc_null;//Data Frames without Data
		unsigned long long packc_cf_ack;
		unsigned long long packc_cf_poll;
		unsigned long long packc_cf_ack_poll;
		unsigned long long packc_reserved;
		struct{
			double average;
			double ave_data_actual;
			double ave_data;
		}size;
	}data;
	unsigned long long packc_reserved;//Reserved Frames. Very likely not gonna be detected ;oP
};


//-------------------------------------------------------------------
//		End  "Delivery of the sniffed Data"
//-------------------------------------------------------------------










//-------------------------------------------------------------------
//		Section for "Taken from radiotap-parser from Johannes Berg"
//-------------------------------------------------------------------

/* Radiotap header iteration
 *   implemented in radiotap.c
 */

//struct radiotap_override {
//	uint8_t field;
//	uint8_t align:4, size:4;
//};
//
//struct radiotap_align_size {
//	uint8_t align:4, size:4;
//};
//
//struct ieee80211_radiotap_namespace {
//	const struct radiotap_align_size *align_size;
//	int n_bits;
//	uint32_t oui;
//	uint8_t subns;
//};
//
//struct ieee80211_radiotap_vendor_namespaces {
//	const struct ieee80211_radiotap_namespace *ns;
//	int n_ns;
//};

/**
 * struct ieee80211_radiotap_iterator - tracks walk thru present radiotap args
 * @this_arg_index: index of current arg, valid after each successful call
 *	to ieee80211_radiotap_iterator_next()
 * @this_arg: pointer to current radiotap arg; it is valid after each
 *	call to ieee80211_radiotap_iterator_next() but also after
 *	ieee80211_radiotap_iterator_init() where it will point to
 *	the beginning of the actual data portion
 * @this_arg_size: length of the current arg, for convenience
 * @current_namespace: pointer to the current namespace definition
 *	(or internally %NULL if the current namespace is unknown)
 * @is_radiotap_ns: indicates whether the current namespace is the default
 *	radiotap namespace or not
 *
 * @overrides: override standard radiotap fields
 * @n_overrides: number of overrides
 *
 * @_rtheader: pointer to the radiotap header we are walking through
 * @_max_length: length of radiotap header in cpu byte ordering
 * @_arg_index: next argument index
 * @_arg: next argument pointer
 * @_next_bitmap: internal pointer to next present u32
 * @_bitmap_shifter: internal shifter for curr u32 bitmap, b0 set == arg present
 * @_vns: vendor namespace definitions
 * @_next_ns_data: beginning of the next namespace's data
 * @_reset_on_ext: internal; reset the arg index to 0 when going to the
 *	next bitmap word
 *
 * Describes the radiotap parser state. Fields prefixed with an underscore
 * must not be used by users of the parser, only by the parser internally.
 */

//struct ieee80211_radiotap_iterator {
//	struct ieee80211_radiotap_header *_rtheader;
//	const struct ieee80211_radiotap_vendor_namespaces *_vns;
//	const struct ieee80211_radiotap_namespace *current_namespace;
//
//	unsigned char *_arg, *_next_ns_data;
//	uint32_t *_next_bitmap;
//
//	unsigned char *this_arg;
//	const struct radiotap_override *overrides;	/* Only for RADIOTAP_SUPPORT_OVERRIDES */
//	int n_overrides;				/* Only for RADIOTAP_SUPPORT_OVERRIDES */
//	int this_arg_index;
//	int this_arg_size;
//
//	int is_radiotap_ns;
//
//	int _max_length;
//	int _arg_index;
//	uint32_t _bitmap_shifter;
//	int _reset_on_ext;
//};

//-------------------------------------------------------------------
//		End Taken from Johannes Berg
//-------------------------------------------------------------------







#endif /* WLAN_SNIFF_H */
