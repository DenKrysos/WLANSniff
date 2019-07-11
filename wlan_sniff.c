/*
 * Authored by
 * Dennis Krummacker (03.06.14-)
 */

#define NO_WLAN_SNIFF_C_FUNCTIONS

#include <sys/socket.h>
#include </usr/include/linux/wireless.h>
#include </usr/include/linux/if_arp.h>
#include <ifaddrs.h>
#include <netinet/in.h>
//#include </usr/src/linux-headers-3.18.20.jessiemptcp/include/net/ieee80211_radiotap.h>
//-------END ioctl-------//
#include "libnetlink.h"

#include "radiotap/radiotap_iter.h"
#include "radiotap/platform.h"

#include "ollerus_globalsettings.h"
#include "ollerus.h"
#include "absint.h"
#include "absint_netf.h"
#include "ollerus.h"

#include "head/ollerus_extern_functions.h"



//-------------------------------------------------------------------
//		Section for "Taken from radiotap-parser from Johannes Berg" (and modified)
//-------------------------------------------------------------------
static int fcshdr = 0;

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
		printf("\tTSFT: %llu\n", le64toh(*(unsigned long long *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		printf("\tflags: %02x\n", *iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_RATE:
		printf("\trate: %lf\n", (double)*iter->this_arg/2);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		printf("\tDBM at Antenna: %d\n",*((int8_t *)(iter->this_arg)));
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		printf("\tChannel: %d ",*((uint16_t *)(iter->this_arg)));
		printf("\t| Flags: %02X %02X\n",*(((unsigned char *)(iter->this_arg))+2),*(((unsigned char *)(iter->this_arg))+3));
		break;
	case IEEE80211_RADIOTAP_ANTENNA:
		printf("\tAntenna: %d\n",*((uint8_t *)(iter->this_arg)));
		break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_TX_FLAGS:
		printf("\tAnd Index: %d\n",iter->this_arg_index);
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
		if (fcshdr) {
			printf("\tFCS in header: %.8x\n",
				le32toh(*(uint32_t *)iter->this_arg));
			break;
		}
		printf("\tRX flags: %#.4x\n",
			le16toh(*(uint16_t *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
		break;
		break;
	default:
		printf("\tBOGUS DATA\n");
		break;
	}
}

static void print_test_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case 0:
	case 52:
		printf("\t00:00:00-00|%d: %.2x/%.2x/%.2x/%.2x\n",
			iter->this_arg_index,
			*iter->this_arg, *(iter->this_arg + 1),
			*(iter->this_arg + 2), *(iter->this_arg + 3));
		break;
	default:
		printf("\tBOGUS DATA - vendor ns %d\n", iter->this_arg_index);
		break;
	}
}

//-------------------------------------------------------------------
//		End Taken from Johannes Berg
//-------------------------------------------------------------------







static char MAC_are_equal(char *mac1, char *mac2){
	int i;
	for(i=0;i<6;i++){
		if(mac1[i]!=mac2[i])
			return 0;
	}
	return 1;
}





static int extract_radiotap_namespace(struct ieee80211_radiotap_iterator *iter,struct wlansniff_chain_start *wlanp){
	int err;err=0;
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
//		printf("\tTSFT: %llu\n", le64toh(*(unsigned long long *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_FLAGS:
//		printf("\tflags: %02x\n", *iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_RATE:
//		printf("\trate: %lf\n", (double)*iter->this_arg/2);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
//		printf("\tDBM at Antenna: %d\n",*((int8_t *)(iter->this_arg)));
		(wlanp->start)[(wlanp->count)-1].rssi=*((int8_t *)(iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
//		printf("\tChannel: %d ",*((uint16_t *)(iter->this_arg)));
//		printf("\t| Flags: %02X %02X\n",*(((unsigned char *)(iter->this_arg))+2),*(((unsigned char *)(iter->this_arg))+3));
		break;
	case IEEE80211_RADIOTAP_ANTENNA:
//		printf("\tAntenna: %d\n",*((uint8_t *)(iter->this_arg)));
		break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_TX_FLAGS:
//		printf("\tAnd Index: %d\n",iter->this_arg_index);
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
//		if (fcshdr) {
//			printf("\tFCS in header: %.8x\n",
//				le32toh(*(uint32_t *)iter->this_arg));
//			break;
//		}
//		printf("\tRX flags: %#.4x\n",
//			le16toh(*(uint16_t *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
		break;
	default:
//		printf("\tBOGUS DATA\n");
		break;
	}
	return 0;
}




int printf_sniffed_wlan_packets(struct wlansniff_chain_start *wlanp){
	int err;err=0;

	int i,chan;
	chan=ieee80211_frequency_to_channel(wlanp->freq);
	printf("Sniffed Raw WLAN-Packets (#%d on %d MHz - Channel %d):\n",(wlanp->count),wlanp->freq,chan);
	for(i=0;i<wlanp->count;i++){
		printf("-> Packet %d\n",i+1);
		printf("\tMAC: ");printMAC((wlanp->start)[i].mac,6);printf("\n");
		printf("\tRSSI: %d\n",(wlanp->start)[i].rssi);
	}
	return err;
}



//Statt nur dem (static) global eine struct, die sämtliches enthält, was die signal-funktion braucht.
//static pcap_t *handlectrl;

struct sigkill_wlanmon_struct sigkill_wlanmon_stuff;


//"Eleganter" Control+C Handler
static void ctrl_c_pcap(){
	printf ("Exiting on User Desire.\n");
	pcap_breakloop (sigkill_wlanmon_stuff.handlectrl);  /* tell pcap_loop or pcap_dispatch to stop capturing */
	pcap_close(sigkill_wlanmon_stuff.handlectrl);
	exit (0);
}


static int iface_mode_cb(struct nl_msg* msg, void* arg) {
	struct nlmsghdr *got_hdr = nlmsg_hdr(msg);
	struct nlattr *got_attr[NL80211_ATTR_MAX + 1];
	int *iftype=((struct CallbackArgPass *)arg)->ArgPointer;
	if (got_hdr->nlmsg_type != expectedId) {
		// what is this??
		return NL_STOP;
	}
	struct genlmsghdr *gnlh = nlmsg_data(got_hdr);
	nla_parse(got_attr, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0), NULL);
	if (got_attr[NL80211_ATTR_IFTYPE])
		*iftype = nla_get_u32(got_attr[NL80211_ATTR_IFTYPE]);
	return 0;
}


//For other Bands than 2.4GHz (such as 5GHz), this function here and it's calls would need an adjustment.
int set_wlandevice_to_freq(char *dev,int freq,enum nl80211_chan_width chanwidth,struct nl80211_state *sktctr,struct CommandContainer *cmd){
	int err;err=0;

	static int ifId;
	static int sfreq;sfreq=freq;
	static enum nl80211_chan_width schanwidth;schanwidth=chanwidth;

	int chan=ieee80211_frequency_to_channel(freq);
	printf("--> Changing (Monitoring-)Frequency to %d MHz (Channel %d) - Dev %s\n",sfreq,chan,dev);

	ifId=if_nametoindex(dev);
	cmd->cmd = NL80211_CMD_SET_WIPHY;
	prepareAttribute(cmd, NL80211_ATTR_IFINDEX, &ifId);
	prepareAttribute(cmd, NL80211_ATTR_CHANNEL_WIDTH, &schanwidth);
	switch(chanwidth){
	case NL80211_CHAN_WIDTH_20_NOHT:
		break;
	case NL80211_CHAN_WIDTH_20:
		break;
	case NL80211_CHAN_WIDTH_40:
		prepareAttribute(cmd, NL80211_ATTR_CENTER_FREQ1, &sfreq);
		break;
	case NL80211_CHAN_WIDTH_80:
		prepareAttribute(cmd, NL80211_ATTR_CENTER_FREQ1, &sfreq);
		break;
	case NL80211_CHAN_WIDTH_80P80:
		prepareAttribute(cmd, NL80211_ATTR_CENTER_FREQ1, &sfreq);
		prepareAttribute(cmd, NL80211_ATTR_CENTER_FREQ2, &sfreq);//TODO: Real Value
		break;
	case NL80211_CHAN_WIDTH_160:
		prepareAttribute(cmd, NL80211_ATTR_CENTER_FREQ1, &sfreq);
		break;
	case NL80211_CHAN_WIDTH_5:
		break;
	case NL80211_CHAN_WIDTH_10:
		break;
	default:
		break;
	}
	prepareAttribute(cmd, NL80211_ATTR_WIPHY_FREQ, &sfreq);
	err = send_with_cmdContainer(sktctr, 0, NULL, cmd);
	return err;
}
int set_wlandevice_to_ifmode(char *dev,enum nl80211_iftype ifmode,struct nl80211_state *sktctr,struct CommandContainer *cmd){
	int err;err=0;

	static int ifId;
	ifId=if_nametoindex(dev);
	static int oldiftype;

	//Check, if Interface already is in Mode
	cmd->cmd = NL80211_CMD_GET_INTERFACE;
	cmd->callbackargpass=&oldiftype;
	prepareAttribute(cmd, NL80211_ATTR_IFINDEX, &ifId);
	cmd->nl_msg_flags = 0;
	cmd->callbackToUse = iface_mode_cb;
	err = send_with_cmdContainer(sktctr, 0, NULL, cmd);
	if(oldiftype==ifmode){
		return 0;
	}
	switch(ifmode){
	case NL80211_IFTYPE_MONITOR:
		printf("--> Going to change %s to Monitoring Infrastructure-Mode\n",dev);
		break;
	case NL80211_IFTYPE_ADHOC:
		printf("--> Going to change %s to Ad-hoc Infrastructure-Mode\n",dev);
		break;
	case NL80211_IFTYPE_STATION:
		printf("--> Going to change %s to Station Infrastructure-Mode\n",dev);
		break;
	case NL80211_IFTYPE_AP:
		printf("--> Going to change %s to Access-Point Infrastructure-Mode\n",dev);
		break;
	default:
		printf("--> Going to change Infrastructure-Mode of %s\n",dev);
		break;
	}

	char retry,retry2;
	//Change Device to Monitor-Mode
	char ipcmd[strlen("ip link set dev  down")+strlen(dev)+1];
	memset(ipcmd,0,sizeof(ipcmd));

	static enum nl80211_iftype iftype;
	iftype=ifmode;
	cmd->cmd = NL80211_CMD_SET_INTERFACE;
	prepareAttribute(cmd, NL80211_ATTR_IFINDEX, &ifId);
	prepareAttribute(cmd, NL80211_ATTR_IFTYPE, &iftype);
	err = send_with_cmdContainer(sktctr, 0, NULL, cmd);
	retry=0;retry2=0;
	SwitchAgain:
	if((retry>3) || (retry2>1)){//Restrict the Retries, to not run into difficulties of infinite loop.
		ANSICOLORSET(ANSI_COLOR_RED);
		printf("ERROR: ");
		ANSICOLORRESET;
		printf("Can't change WLAN Infrastructure Mode. Gave up after a few tries...\n");
		return OPERATION_ERR_UNSUCCESSFUL;
	}
	switch(err){
	case 0://Nice, the mode switch worked.
		break;
	case -16://Not that nice, Device is busy. Try with set down -> switch -> set up.
		prepareAttribute(cmd, NL80211_ATTR_IFINDEX, &ifId);
		prepareAttribute(cmd, NL80211_ATTR_IFTYPE, &iftype);
		snprintf(ipcmd,sizeof(ipcmd),"ip link set dev %s down",dev);
		ipcmd[sizeof(ipcmd)]='\0';
		system(ipcmd);
		err = send_with_cmdContainer(sktctr, 0, NULL, cmd);
		snprintf(ipcmd,sizeof(ipcmd),"ip link set dev %s up",dev);
		ipcmd[sizeof(ipcmd)]='\0';
		system(ipcmd);
		retry++;
		break;
	default://Hm, not really sure what's the problem. However, try with Device reset...
		err=-16;
		goto SwitchAgain;
		break;
	}
	//Check, if iftype really changed to monitor
	cmd->cmd = NL80211_CMD_GET_INTERFACE;
	cmd->callbackargpass=&oldiftype;
	prepareAttribute(cmd, NL80211_ATTR_IFINDEX, &ifId);
	cmd->nl_msg_flags = 0;
	cmd->callbackToUse = iface_mode_cb;
	err = send_with_cmdContainer(sktctr, 0, NULL, cmd);
	if(oldiftype!=ifmode){
		retry=0;retry2++;
		goto SwitchAgain;
	}
	return err;
}
/* On Call of the wifi_package_parse:
 * Check for the return of ERR_WLAN_SNIFF_BAD_DEVICE
 * Than you gave it a device, which isn't a WLAN Interface
 */
int wifi_package_parse(char *dev,int freq,struct wlansniff_chain_start **wlanp,double timeToMonitor,struct wlansniff_pack_stat *pack_stat){
#define WLAN_PACK_LEN_VAR 0
#define WLAN_PACK_LEN_MACRO 1
#define WLAN_PACK_LEN_METHOD WLAN_PACK_LEN_MACRO
#if (WLAN_PACK_LEN_METHOD==WLAN_PACK_LEN_VAR)
	int wlan_pack_len;
	int wlan_pack_caplen;
	#define WLAN_PACK_LEN wlan_pack_len
	#define WLAN_PACK_CAPLEN wlan_pack_caplen
#elif (WLAN_PACK_LEN_METHOD==WLAN_PACK_LEN_MACRO)
	#define WLAN_PACK_LEN ((header->len)-(((struct ieee80211_radiotap_header *)(packet))->it_len))
	#define WLAN_PACK_CAPLEN ((header->caplen)-(((struct ieee80211_radiotap_header *)(packet))->it_len))
#else
	#define WLAN_PACK_LEN
	#define WLAN_PACK_CAPLEN
#endif

#define PRINT_PCAP_TIMESTAMP printf("%ds %dµs",(int)((header->ts).tv_sec),(int)((header->ts).tv_usec));

	int err;err=0;
	int i;i=0;
//	time_t systime, systimeold;
	double realsystime, realsystimestart, timepassed;
//	double packpersec;//Not used. Stat is directly written inside the wlansniff_chain_start
	int packetcount;packetcount=0;

	static int ifId;
	ifId=if_nametoindex(dev);
	struct CommandContainer cmd;
	cmd.prepatt = NULL;
	struct nl80211_state sktctr; //contains the nl_socket
	err = nl80211_init_socket(&sktctr);
	expectedId = sktctr.nl80211_id;

	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_stat pcap_statistics;
	struct pcap_pkthdr *header=NULL;	/* The header that pcap gives us */
	const u_char *packet=NULL;		/* The actual packet */
	struct IEEE80211_MAC_Frame_Header* head80211=NULL;
	int head80211_headsize;

							/* The Device Lookup is done outside the Sniffer.
							 * Dev is passed to the Sniffer
							 * Just for Documentation:
							 * You could do something like either one of the two following:
							 * 1. Directly pass the Dev (pcap_lookupdev just takes the first found)
							 * 2. Find all devices with pcap_findalldevs and take of them
							 * 		-> Remember pcap_freealldevs(alldevs); after Opening Device for Sniffing
							char *dev;			// The device to sniff on
							dev = pcap_lookupdev(errbuf);
							if (dev == NULL) {
								fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
								return(2);
							}
							printf("Device: %s\n", dev);

							pcap_if_t *alldevs;
							pcap_if_t *d;
							// Retrieve the device list on the local machine
							if (pcap_findalldevs(&alldevs, errbuf) == -1){
								fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
								exit(1);
							}
							// Print the list
							for(d=alldevs; d; d=d->next){
								printf("%d. %s", ++i, d->name);
								if (d->description)
									printf(" (%s)\n", d->description);
								else
									printf(" (No description available)\n");
							}
							if(i==0){
								printf("\nNo interfaces found!\n");
								return -1;
							}
							*/

	int sizestart,sizelement;
	sizestart=sizeof(**wlanp);
	sizelement=sizeof(*((*wlanp)->start));
	if((*wlanp)){
		printfc(YELLOW,"WARNING WiFi-Sniffer: ");
		printf("The struct-Pointer to pass the sniffed Data back wasn't empty (maybe just not correct initialized?)\n\tForgive me, that i cleaned it up\n");
		//NOTE: If this get's a wrong Pointer (not initialized, wrong set or just any value), than it tries to
		//free at the wrong memory-location... You know what this means...
		//But better let the Program crash, than to risk a memory-overflow...
		free(*wlanp);
	}
	*wlanp=malloc(sizestart);
	(*wlanp)->count=0;
	(*wlanp)->start=NULL;
	(*wlanp)->freq=freq;
	(*wlanp)->trafficstat=0;

	ANSICOLORSET(ANSI_COLOR_YELLOW);
	printf("WiFi-Sniffer: ");
	ANSICOLORRESET;
	printf("Sniffing on Device: %s\n",dev);
	//First get the current iftype, to later on change back to it.
	static int oldiftype;//Misuse this to first pass the Interface ID. Saves one Variable and should work because ifID is used on nlmsg creation and after this, with the answer from this we store the iftype in it
	oldiftype=if_nametoindex(dev);
	cmd.cmd = NL80211_CMD_GET_INTERFACE;
	cmd.callbackargpass=&oldiftype;
	prepareAttribute(&cmd, NL80211_ATTR_IFINDEX, &oldiftype);
	cmd.nl_msg_flags = 0;
	cmd.callbackToUse = iface_mode_cb;
	err = send_with_cmdContainer(&sktctr, 0, NULL, &cmd);
	err=set_wlandevice_to_ifmode(dev,NL80211_IFTYPE_MONITOR,&sktctr,&cmd);
	err=set_wlandevice_to_freq(dev,freq,NL80211_CHAN_WIDTH_20,&sktctr,&cmd);
//	depr(freq_err," %d",err)
	//Set the error-string to zero-length
	errbuf[0] = 0;//On String =0 is equal to ='\0'
	signal(SIGINT, ctrl_c_pcap);
	sigkill_wlanmon_stuff.handlectrl = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//	pcap_set_buffer_size(sigkill_wlanmon_stuff.handlectrl,16777216);
	pcap_set_buffer_size(sigkill_wlanmon_stuff.handlectrl,65536);
	pcap_set_buffer_size(sigkill_wlanmon_stuff.handlectrl,4096);
	if (sigkill_wlanmon_stuff.handlectrl == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		nl80211_cleanup_socket(&sktctr);
		return(OPERATION_ERR_NOT_SUPPORTED);
	}
	if (strlen (errbuf) > 0){
		fprintf (stderr, "Warning: %s", errbuf);  // a warning was generated
		errbuf[0] = 0;    //re-set error buffer
	}
//	pcap_freealldevs(alldevs);

//	depr(2)
	switch(pcap_datalink(sigkill_wlanmon_stuff.handlectrl)){
	case DLT_EN10MB:
		printfc(YELLOW,"WARNING WiFi-Sniffer: ");
		printf("I got an Ethernet-Port. But i want to work on WLAN... ");
		printfc(RED,":(");printf("\n");
		nl80211_cleanup_socket(&sktctr);
		return(ERR_WLAN_SNIFF_BAD_DEVICE);
		break;
	case DLT_IEEE802_11_RADIO://Radiotap should be most common. Today something like the defacto standard
		RadiotapHeaderDecode:
//		time(&systimeold);
		realsystimestart=getRealTime();
			//There could be Packets buffered, so that after channel-switch pcap gives us packets from previous channels
			//For the sake of nice order in our Data-Structures skip them
			SkipPacket:
			Timeout:
		while(1){
//			time(&systime);
//			if(difftime(systime,systimeold)>1){
//				break;
//			}
			if(sigkill_wlanmon_stuff.cancel)
				break;
			realsystime=getRealTime();
			timepassed=realsystime-realsystimestart;
			if((timepassed)>timeToMonitor){
				break;
			}
			//Grab a packet
			err = pcap_next_ex(sigkill_wlanmon_stuff.handlectrl, &header, &packet);
			switch(err){
			case 1://Read without problem
				break;
			case 0://Live Capture and Timeout
//				printfc(YELLOW,"WiFi-Sniffer: ");
//				printf("Timeout while Packet Reading.\n");
				goto Timeout;
				break;
			case -1://Error while Reading
				printfc(red,"ERROR WiFi-Sniffer: ");
				printf("While Packet Reading:\n\t%s\n",pcap_geterr(sigkill_wlanmon_stuff.handlectrl));
				break;
			case -2://Read from "Savefile" and there are no more packets
				printfc(YELLOW,"WiFi-Sniffer: ");
				printf("End of Savefile\n");
				break;
			default:
				printfc(red,"WiFi-Sniffer: ");
				printf("Some undefined Error-Code while Packet Reading.\n");
				goto SkipPacket;
				break;
			}
//			packetcount++;
			//printf("Err: %d\n",err);
//			printf("Jacked a packet with length of [%d]\n", header->len);
//			printf("tap len %d\n",(struct ieee80211_radiotap_header *)packet->it_len);
			///////////////////////////
			//Process the Radiotap-Header (first the Initialization; Processing follows below MAC-Extraction)
			static const struct radiotap_align_size align_size_000000_00[] = {
				[0] = { .align = 1, .size = 4, },
				[52] = { .align = 1, .size = 4, },
			};
			static const struct ieee80211_radiotap_namespace vns_array[] = {
				{
					.oui = 0x000000,
					.subns = 0,
					.n_bits = sizeof(align_size_000000_00),
					.align_size = align_size_000000_00,
				},
			};
			static const struct ieee80211_radiotap_vendor_namespaces vns = {
				.ns = vns_array,
				.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
			};
			struct ieee80211_radiotap_iterator iter;
			err = ieee80211_radiotap_iterator_init(&iter, packet, header->len, &vns);
			if (err) {
//				nl80211_cleanup_socket(&sktctr);
				#ifdef DEBUG_WIFI_SNIFF
				printf("malformed radiotap header (init returns %d)... Skip Packet\n", err);
				#endif
//					#ifdef DEBUG
//					printf("\tPrevious pcap-errbuf: %s\n",errbuf);
//					#endif
//				return 3;
//				packetcount--;
				goto SkipPacket;
			}

			packetcount++;
			//Extract the MAC Address
			/*REMEMBER, if you want more Info out of the 802.11 WLAN Header or the Payload:
			 * Inside the Flags of the Frame Control Field is declared, which optional/additional Fields or
			 * Sub-Protocols are included. this gives the Header a variable Length and differing Positions of
			 * specific Fields and the Payload.
			 */
			//
			head80211=packet+(((struct ieee80211_radiotap_header *)(packet))->it_len);
			//
			//
			//
			//
			//
			//
			//
			//
			// The Packet Size Statistics:
			// Please Mind:
			// The length values (header->len,header->caplen) from the pcap header (struct pcap_pkthdr *header)
			// include the length of the accompanying radiotap header (((struct ieee80211_radiotap_header *)(packet))->it_len)
			if(pack_stat!=NULL){
				#define PRINT_DATA_FRAMES 4	// 0: No Print, 1: Print Subtypes, 2: Print general Type Frame Info, 3: Print both
											// 4: Prints only "real" Data-Frames
											// Any not mentioned Value prints nothing

				#if (WLAN_PACK_LEN_METHOD==WLAN_PACK_LEN_VAR)
					wlan_pack_len=(header->len)-(((struct ieee80211_radiotap_header *)(packet))->it_len);
					wlan_pack_caplen=(header->caplen)-(((struct ieee80211_radiotap_header *)(packet))->it_len);
				#endif
					#define BYTETOBINPATTERN_FRAME_CTRL_1 ANSI_COLOR_CYAN"%d%d%d%d"ANSI_COLOR_GREEN"%d%d"ANSI_COLOR_YELLOW"%d%d"ANSI_COLOR_RESET


		#define FRAME_80211_INFO_PRINT(SUBTYPE) printf("DataFrame (Sub "#SUBTYPE"):"); \
					/*printfc(green,"Packet Size:");printf(" %d (complete: %d) - caplen: %d | ",WLAN_PACK_LEN,header->len,WLAN_PACK_CAPLEN);*/ \
					printfc(green,"Packet Size:");printf(" %d",WLAN_PACK_LEN);printf(", without 80211-Head & FCS: %d, 802.11-Header-Size: %d",WLAN_PACK_LEN-head80211_headsize-(int)sizeof(IEEE80211_FCS),head80211_headsize); \
						printf(" - caplen: %d | ",WLAN_PACK_CAPLEN); \
					printf("FrameCtrl: "BYTETOBINPATTERN_FRAME_CTRL_1"-"BYTETOBINPATTERN" | ",BYTETOBIN( (head80211->FrameControl).B1 ),BYTETOBIN( (head80211->FrameControl).B2 )); \
					printf("time: ");PRINT_PCAP_TIMESTAMP \
					puts("");


//				printfc(green,"Packet Size:");printf(" %d - caplen: %d | ",WLAN_PACK_LEN,WLAN_PACK_CAPLEN);
//				printf("time: ");PRINT_PCAP_TIMESTAMP printf("\n");
//				printf("FrameControl: "BYTETOBINPATTERN_FRAME_CTRL_1"-"BYTETOBINPATTERN" - ",BYTETOBIN( (*((char *)(&(head80211->FrameControl)))) ),BYTETOBIN( (*(((char *)(&(head80211->FrameControl)))+1)) ));
//				printf("DurationID: %d - SequenceControl: %d",head80211->DurationID,head80211->SequenceControl);
//				printf(" | ");printMAC(head80211->Addr1,6);printf(" | ");printMAC(head80211->Addr2,6);printf(" | ");printMAC(head80211->Addr3,6);printf(" | ");printMAC(&(head80211->Addr4),2,1);
//				printf("\n");

//				if(WLAN_PACK_LEN==14){
//					printfc(green,"Packet Size:");printf(" %d - caplen: %d | ",WLAN_PACK_LEN,WLAN_PACK_CAPLEN);
//					printf("FrameControl: "BYTETOBINPATTERN_FRAME_CTRL_1"-"BYTETOBINPATTERN" - ",BYTETOBIN( (*((char *)(&(head80211->FrameControl)))) ),BYTETOBIN( (*(((char *)(&(head80211->FrameControl)))+1)) ));
//					puts("");
//				}

//				printfc(red,"sizeof head80211: %d, sizeof struct IEEE80211_MAC_Frame_Header: %d\n",sizeof(*head80211),sizeof(struct IEEE80211_MAC_Frame_Header));
//				printfc(red,"sizeof: %d, sizeof: %d\n",sizeof(head80211->optional),sizeof(head80211->optional.QoS));
//				head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);//The least basic Size of a 802.11 Header (completely without the optional fields). Not here, is done in one step inside the whole Size Calculation-Makro


				switch((head80211->FrameControl).B1 & IEEE80211_FRAMECONTROL_FRAME_TYPE){
				case IEEE80211_FRAME_TYPE_MANAGEMENT:// 0x00://Management (XXXX 00XX | XXXX XXXX)
//					printf("Management Frame:");
//					puts("");
					switch((head80211->FrameControl).B1 & IEEE80211_FRAMECONTROL_FRAME_SUBTYPE){
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__ASSOCIATION_REQUEST:// 0x00:// 0x00://Association Request
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__ASSOCIATION_RESPONSE:// 0x10:// 0x01://Association Response
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__REASSOCIATION_REQUEST:// 0x20:// 0x02://Reassociation Request
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__REASSOCIATION_RESPONSE:// 0x30:// 0x03://Reassociation Response
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__PROBE_REQUEST:// 0x40:// 0x04://Probe Request
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__PROBE_RESPONSE:// 0x50:// 0x05://Probe Response
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__BEACON:// 0x80:// 0x08://Beacon
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__ATIM:// 0x90:// 0x09://Announcement traffic indication message (ATIM)
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__DISASSOCIATION:// 0xA0:// 0x0A://Disassociation
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__AUTHENTICATION:// 0xB0:// 0x0B://Authentication
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__DEAUTHENTICATION:// 0xC0:// 0x0C://Deauthentication
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_60:// 0x60:// 0x06:
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_70:// 0x70:// 0x07:
//						printf("Reserved Management Frame Subtype.\n");
						break;
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_D0:// 0xD0:// 0x0D:
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_E0:// 0xE0:// 0x0E:
					case IEEE80211_FRAME_SUBTYPE_MANAGEMENT__RESERVED_F0:// 0xF0:// 0x0F:
//						printf("Reserved Management Frame Subtype.\n");
						break;
					default:
//						printf("Not recognized Management Frame Subtype. (Or reserved)\n");
						break;
					}
					break;
				case IEEE80211_FRAME_TYPE_CONTROL:// 0x04://Control (XXXX 01XX | XXXX XXXX
//					printf("Control Frame:");
//					puts("");
					switch((head80211->FrameControl).B1 & IEEE80211_FRAMECONTROL_FRAME_SUBTYPE){
					case IEEE80211_FRAME_SUBTYPE_CONTROL__PS_POLL:// 0xA0:// 0x0A://Power Save (PS)-Poll
						break;
					case IEEE80211_FRAME_SUBTYPE_CONTROL__RTS:// 0xB0:// 0x0B://Request to Send (RTS)
//						printf("RTS Frame:");
//						printfc(green,"Packet Size:");printf(" %d - caplen: %d | ",WLAN_PACK_LEN,WLAN_PACK_CAPLEN);
//						printf("time: ");PRINT_PCAP_TIMESTAMP
//						puts("");
						break;
					case IEEE80211_FRAME_SUBTYPE_CONTROL__CTS:// 0xC0:// 0x0C://Clear to Send (CTS)
//						printf("CTS Frame:");
//						printfc(green,"Packet Size:");printf(" %d - caplen: %d | ",WLAN_PACK_LEN,WLAN_PACK_CAPLEN);
//						printf("time: ");PRINT_PCAP_TIMESTAMP
//						puts("");
						break;
					case IEEE80211_FRAME_SUBTYPE_CONTROL__ACK:// 0xD0:// 0x0D://Acknowledgment (ACK)
//						printf("ACK Frame:");
//						printfc(green,"Packet Size:");printf(" %d - caplen: %d | ",WLAN_PACK_LEN,WLAN_PACK_CAPLEN);
//						printf("time: ");PRINT_PCAP_TIMESTAMP
//						puts("");
						break;
					case IEEE80211_FRAME_SUBTYPE_CONTROL__CF_END:// 0xE0:// 0x0E://Contention-Free (CF)-End
						break;
					case IEEE80211_FRAME_SUBTYPE_CONTROL__CF_ACK:// 0xF0:// 0x0F://CF-End + CF-Ack
						break;
					case 0x00:// 0x00:
					case 0x10:// 0x01:
					case 0x20:// 0x02:
					case 0x30:// 0x03:
					case 0x40:// 0x04:
					case 0x50:// 0x05:
					case 0x60:// 0x06:
					case 0x70:// 0x07:
					case 0x80:// 0x08:
					case 0x90:// 0x09:
						break;
//						printf("Reserved Control Frame Subtype.\n");
					default:
						printf("Not recognized Control Frame Subtype. (Or reserved)\n");
						break;
					}
					break;
				case IEEE80211_FRAME_TYPE_DATA:// 0x08://Data (XXXX 10XX | XXXX XXXX)
						//					puts("");
						//					uint16_t test;test=IEEE80211_FRAMECONTROL_FRAME_TYPE;
						//					printfc(blue,"Maske:")
						//					printf(" %X | ",test);
						//					printf(BYTETOBINPATTERN_FRAME_CTRL_1"-"BYTETOBINPATTERN" - ",BYTETOBIN( (*((char *)(&(test)))) ),BYTETOBIN( (*(((char *)(&(test)))+1)) ));
						//					puts("");puts("");
//					printfc(red,"Typ-Ausschnitt: %X | ",((head80211->FrameControl) & IEEE80211_FRAMECONTROL_FRAME_TYPE));
					#if (PRINT_DATA_FRAMES==2 || PRINT_DATA_FRAMES==3)
					printf("Data Frame:");
					printfc(green,"Packet Size:");printf(" %d (complete: %d) - caplen: %d | ",WLAN_PACK_LEN,header->len,WLAN_PACK_CAPLEN);
					printf("FrameControl: "BYTETOBINPATTERN_FRAME_CTRL_1"-"BYTETOBINPATTERN" - ",BYTETOBIN( (head80211->FrameControl).B1 ),BYTETOBIN( (head80211->FrameControl).B2 ));
					puts("");
					#endif
					switch((head80211->FrameControl).B1 & IEEE80211_FRAMECONTROL_FRAME_SUBTYPE){
					case IEEE80211_FRAME_SUBTYPE_DATA__DATA:// 0x00:// 0x00://Data
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(Data)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__DATA_CF_ACK://0x10:// 0x01://Data+CF-ACK
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(Data-CF-ACK)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__DATA_CF_POLL:// 0x20:// 0x02://Data+CF-Poll
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(Data-CF-Poll)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__DATA_CF_ACK_POLL:// 0x30:// 0x03://Data+CF-ACK&CF-Poll
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(Data-CF-ACK-Poll)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__NULL:// 0x40:// 0x04://Null function, No Data (XXXX 0100 | XXXX XXXX)
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(NULL)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__CF_ACK:// 0x50:// 0x05://CF-ACK (no data)
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(CF-ACK)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__CF_POLL:// 0x60:// 0x06://CF-Poll (no data)
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(CF-Poll)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__CF_ACK_POLL:// 0x70:// 0x07://CF-Ack+CF-Poll (no data)
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(CF-ACK-Poll)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA:// 0x80:// 0x08:// QoS Data
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.QoS);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.QoS);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(QoS-Data)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA_CF_ACK:// 0x90:// 0x09:// QoS Data + CF-Ack
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.QoS);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.QoS);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(QoS-Data-CF-ACK)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA_CF_POLL:// 0xA0:// 0x0A:// QoS Data + CF-Poll
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.QoS);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.QoS);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(QoS-Data-CF-Poll)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__QOS_DATA_CF_ACK_POLL:// 0xB0:// 0x0B:// QoS Data + CF-Ack + CF-Poll
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.QoS);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.QoS);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3 || PRINT_DATA_FRAMES==4)
						FRAME_80211_INFO_PRINT(QoS-Data-CF-ACK-Poll)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__QOS_NULL:// 0xC0:// 0x0C:// QoS Null (no data)
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.QoS);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.QoS);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(QoS-NULL)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__QOS_CF_POLL_NODATA:// 0xE0:// 0x0E:// QoS CF-Poll (no data)
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.QoS);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.QoS);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(QoS-CF-Poll)
						#endif
						break;
					case IEEE80211_FRAME_SUBTYPE_DATA__QOS_CF_ACK_POLL_NODATA:// 0xF0:// 0x0F:// QoS CF-Ack + CF-Poll (no data)
						if( FLAG_CHECK((head80211->FrameControl).B2, IEEE80211_FRAMECONTROL_TO_DS) &&
							FLAG_CHECK((head80211->FrameControl).B2,IEEE80211_FRAMECONTROL_FROM_DS) ){
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has Addr4 and HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has Addr4 but no HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4) + sizeof(head80211->optional.QoS);
							}
						}else{
							if ( ((head80211->FrameControl).B2) & IEEE80211_FRAMECONTROL_ORDER){
								//Here the Frame has No Addr4 but has HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.Addr4_HT) + sizeof(head80211->optional.QoS);
							}else{
								//Here the Frame has neither Addr4 nor HT-Control
								head80211_headsize = sizeof(*head80211) - sizeof(head80211->optional) + sizeof(head80211->optional.QoS);
							}
						}
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(QoS-CF-ACK-Poll)
						#endif
						break;
					case 0xD0:// 0x0D:// Reserved
						#if (PRINT_DATA_FRAMES==1 || PRINT_DATA_FRAMES==3)
						FRAME_80211_INFO_PRINT(Reserved)
						#endif
						break;
					default:
						printf("Not recognized Data Frame Subtype. (Or reserved)\n");
						break;
					}
					break;
				case IEEE80211_FRAME_TYPE_RESERVED:// 0x0C://Reserved (XXXX 11XX | XXXX XXXX)
//					printf("Reserved Frame:");
//					puts("");
					break;
				default:
					printfc(red,"ERR: ");printf("Didn't match any Frame-Type. ");
					printf("FrameControl: "BYTETOBINPATTERN_FRAME_CTRL_1"-"BYTETOBINPATTERN,BYTETOBIN( (*((char *)(&(head80211->FrameControl)))) ),BYTETOBIN( (*(((char *)(&(head80211->FrameControl)))+1)) ));
					puts("");
					break;
				}
					#undef BYTETOBINPATTERN_FRAME_CTRL_1
			}
			// Pack Size Stats End
			//
			//
			//
			//
			//
			//
			//
			//
			for(i=0;i<(*wlanp)->count;i++){
				if(MAC_are_equal((head80211->Addr2),(((*wlanp)->start)[i]).mac)){
					//Then a Packet from this source was caught already. Then we have the choice
					//Either skip it completely or check if this packet here has differing informations (which would be newer...)
					//Exchange the already caught information or do something like a moving average on the RSSI
					goto SkipPacket;
				}else {//Completely new Packet source: Allocate space for it and fill in the MAC/HW-Address.
				}
			}
			((*wlanp)->count)++;
			*wlanp=realloc(*wlanp,sizestart+sizelement*((*wlanp)->count));
			(*wlanp)->start=(void *)((uintptr_t)(*wlanp)+(uintptr_t)sizestart);
			memcpy(((*wlanp)->start)[((*wlanp)->count)-1].mac,(head80211->Addr2),6);
						//			printf("\tMAC: ");
						//			printMAC(&(head80211->Addr2),6);
						//			printf("\n");
			while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
				if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
					printf("\tvendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
						iter.this_arg[0], iter.this_arg[1],
						iter.this_arg[2], iter.this_arg[3],
						iter.this_arg_size - 6);
					for (i = 6; i < iter.this_arg_size; i++) {
						if (i % 8 == 6)
							printf("\t\t");
						else
							printf(" ");
						printf("%.2x", iter.this_arg[i]);
					}
					printf("\n");
				} else if (iter.is_radiotap_ns){
//					printf_radiotap_namespace(&iter);
					if ((iter.this_arg_index==IEEE80211_RADIOTAP_CHANNEL)&&
						((*((uint16_t *)(iter.this_arg)))!=freq)){
						//Then, first free the already allocated space for this packet, afterwards skip the rest processing of the packet.
						((*wlanp)->count)--;
						*wlanp=realloc(*wlanp,sizestart+sizelement*((*wlanp)->count));
						goto SkipPacket;
					}
					extract_radiotap_namespace(&iter,*wlanp);
				}
				else if (iter.current_namespace == &vns_array[0]){
//					print_test_namespace(&iter);
				}
			}
			if (err != -ENOENT) {
				printf("malformed radiotap data\n");
				nl80211_cleanup_socket(&sktctr);
				return 3;
			}
		}
		err=0;
		break;
	case DLT_IEEE802_11:
		printfc(YELLOW,"WARNING WiFi-Sniffer: ");
		printf("TODO: Std-802.11 Header Decoding...\n");
		printf("\tWorkaround: For now just try with Radiotap Decoding. Let's try how far we come.\n");
		goto RadiotapHeaderDecode;
		break;
	case DLT_IEEE802_11_RADIO_AVS:
		printfc(YELLOW,"WARNING WiFi-Sniffer: ");
		printf("TODO: AVS Header Decoding...\n");
		printf("\tWorkaround: For now just try with Radiotap Decoding. Let's try how far we come.\n");
		goto RadiotapHeaderDecode;
		break;
	case DLT_PRISM_HEADER:
		printfc(YELLOW,"WARNING WiFi-Sniffer: ");
		printf("TODO: Prism Header Decoding...\n");
		printf("\tWorkaround: For now just try with Radiotap Decoding. Let's try how far we come.\n");
		goto RadiotapHeaderDecode;
		break;
	default:
		ANSICOLORSET(ANSI_COLOR_RED);
		printf("ERROR WiFi-Sniffer: ");
		ANSICOLORRESET;
		printf("Device %s doesn't provide any Wireless headers - not supported.\n\tEither Radiotap, AVS, Prism nor Std-802.11.\n", dev);
		ANSICOLORSET(ANSI_COLOR_GREEN);
		printf("INFO WiFi-Sniffer: ");
		ANSICOLORRESET;
		printf("Supported is: %d\n",pcap_datalink(sigkill_wlanmon_stuff.handlectrl));
		nl80211_cleanup_socket(&sktctr);
		return(ERR_WLAN_SNIFF_BAD_DEVICE);
//		ANSICOLORSET(ANSI_COLOR_RED);
//		printf("ERROR WiFi-Sniffer: ");
//		ANSICOLORRESET;
//		printf("Someone gave me a completely different Port. I can't do anything with it o.O\n");
		break;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		errbuf[0]=0;
		net = 0;
		mask = 0;
	}

	err=pcap_stats(sigkill_wlanmon_stuff.handlectrl,&pcap_statistics);
	printfc(gray,"NOTE: ");printf("Dropped Packets (slow processing): %d, Dropped (by Interface): %d, Recvd Packs: %d\n",pcap_statistics.ps_drop,pcap_statistics.ps_ifdrop,pcap_statistics.ps_recv);

	//And close the session
	pcap_close(sigkill_wlanmon_stuff.handlectrl);
	signal(SIGINT, ctrl_c);

//	err=set_wlandevice_to_ifmode(dev,oldiftype,&sktctr,&cmd);

	nl80211_cleanup_socket(&sktctr);

	(*wlanp)->trafficstat=(double)packetcount/timepassed;

	return err;
#undef WLAN_PACK_LEN_VAR
#undef WLAN_PACK_LEN_MACRO
#undef WLAN_PACK_LEN_METHOD
#undef WLAN_PACK_LEN
#undef WLAN_PACK_CAPLEN
}




#undef NO_WLAN_SNIFF_C_FUNCTIONS
