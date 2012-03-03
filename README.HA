
	--------------------------------------------------------------
	This document describes the High Availability mode of Openswan
		     (C) 2004 Ulrich Weber - Astaro AG
	--------------------------------------------------------------

Requirements:	* Native IPSec with linux kernel 2.6.17 or higher
		* KLIPS, all kernel versions

Note: Aggressive Mode, Mode Config/XAUTH and Opportunistic Encryption
are not tested and might not work.

If you are using 2.6.17 to 2.6.20, please change XFRM_AEVENT_VERSION to 1
in src/include/linux/xfrm.h.


To enable the HA mode of Openswan a ha_interface has to be configured in
ipsec.conf. Please use a crossover wire to connect master with slave.
By default the sequence number of outbound ESP/AH connections will be
incremented by 1024 and inbound by 256. This values can be changed by
ha_seqdiff_out (Outbound) and ha_seqdiff_in (Inbound).

You don't have to update your inbound sequence numbers as often as you
update your outgoing sequnece numbers. But thats up to you.

Example:

	ha_interface=eth1
	ha_seqdiff_in=256
	ha_seqdiff_out=1024


The following commands are availible to switch between Master and Slave mode:

	ipsec whack --ha_mode=master
	ipsec whack --ha_mode=slave


A HA information has been added to "ipsec whack --status" to display the current
ha mode.

Attention: Pluto will not accept incomming IKE requests in Slave mode (Which is
the default mode if a ha_interface is configured)! So ensure there is always one
active Master around. You can use linux-ha or ucarp for that.


To see more verbose output and debugging information use "ipsec whack --debug-ha".


Known issues:

	- Pluto is not multithreaded. Therefore the Master system is unavailable
	  for a few secounds after a Slave requests an initial synchronisation
	  (This depends on the size of active IPSec connections). Depending on
	  the cpu its around 40 SA's per second.

	- Traffic between master and slave is not encrypted! Please use a
	  crossover wire between master and slave.


////////////////////////////////////////////////////////////////////////////////

Developer Information:

Default mode is slave if pluto is started and an ha_interface is configured. In
this mode incomming IKE traffic is droped by setting listening to FALSE.
Outgoing IKE traffic is blocked in send_packet().

All pluto ha mode messages are sent to multicast address 224.0.0.82 (default
ct_sync multicast address) and port 501. This values can be changed in sa_sync.h.

After a state changes in demux.c, a check is performed if the state is
IS_ISAKMP_SA_ESTABLISHED or IS_IPSEC_SA_ESTABLISHED. If one of them is true and
pluto is in HA Master the whole state struct will be send by multicast to the
slave. The appendant connection struct will be identified by the name string on
the slave side. In case of a roadwarrior the needed information to create a
connection instance with rw_instantiate is submitted as well. OE instances are
not supported so far, sorry.


State events are inserted like normal one on the slave. However a rekeying is
disabled in ipsecdoi_replace. The variable next_so (of state.c) has been moved
global to be kept in sync (master and slave use same state numbers). The
instance_serial variable of a CK_TEMPLATE connection struct will be kept in sync
as well.

There are no DPD events on the slave. If a master comes up all DPD events will
be inserted by insert_dpd_events(). If a master goes down all DPD events will be
removed by remove_dpd_events().

Another debug options has been added:
DBGOPT_HA which can be changed with --debug-ha

A pointer to the inherited state struct was added to the kernel_sa struct. This
is needed to use st->st_rpacket and st->st_tpacket for initial replay sequence
number.

In case of a bulk update every state struct in the state table will be
transmitted to the slave. In this case sa_sync_state is called with value
with_seqno=TRUE which means the actuel sequence number informations are
transmitted as well.

For KLIPS there are two new sysctl values:
net/core/xfrm_seqdiff_in and net/core/xfrm_seqdiff_out.
They are set by pluto on startup according to ha_seqdiff_in and ha_seqdiff_out.


