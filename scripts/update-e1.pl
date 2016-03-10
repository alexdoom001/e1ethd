#!/usr/bin/perl

use Vyatta::Config;
use Getopt::Long;

my $config = new Vyatta::Config;

my $base_iface = "pds0";
my $pfx = "pds";
my $base_mtu = 9000;
my $base_addr = "192.0.2.3";
my $base_mask = "255.255.255.224";
my $e1_conf_tool = "/usr/sbin/e1ethd_conf";
my $conf_file = "/cfg/etc/e1ethd.conf";
my $general_group = "e1ethd";
my $e1_daemon = "e1ethd";
my $curr_vid = 3;

my %keys = (
	'dst_addr' => 'dst_addr',
	'src_addr' => 'src_addr',
	'port' => 'port',
	'code' => 'code',
	'framing' => 'framing',
	'sync' => 'sync',
	'slot_begin' => 'slot_begin',
	'slot_end' => 'slot_end',
	'hdlc' => 'hdlc',
	'vid' => 'vid',
	'tract' => 'tracts',
	'channel' =>'channels'
);

sub set_val {
	my ($group, $key, @val) = @_;
	my $res = 0;

	unless (defined(@val)) {
		printf STDERR "$key is not defined\n";
		return 1;
	}

	$res = `$e1_conf_tool $conf_file $group $key @val`;

	if ($res) {
		return 1;
	}
}

sub set_tract_values {
	my ($tract) = @_;

	$config->setLevel("interfaces ds $tract");

	my $coding = $config->returnValue("e1-options coding");
	unless (defined($coding)) {
		print STDERR "No coding type selected.\n";
		return 1;
	}
	if (set_val($tract, $keys{"code"}, $coding)) {
		printf STDERR "Unable to apply selected coding type $code\n";
		return 1;
	}

	my $framing = $config->returnValue("e1-options framing");
	unless (defined($framing)) {
		print STDERR "No framing mode selected.\n";
		return 1;
	}
	if (set_val($tract, $keys{"framing"}, $framing)) {
		printf STDERR "Unable to apply selected frame mode $framing\n";
		return 1;
	}

	my $sync = $config->returnValue("e1-options clock");
	unless (defined($sync)) {
		print STDERR "Не установлен источник синхронизации.\n";
		return 1;
	}
	if (set_val($tract, $keys{"sync"}, $sync)) {
		printf STDERR "Unable to set sync type $sync\n";
		return 1;
	}

	my @channels = $config->listNodes("channel");
	if (scalar(@channels) == 0) {
		print STDERR "No channel settings $tract\n";
		return 1;
	}
#
	if (set_val($tract, $keys{"channel"}, @channels)) {
		printf STDERR "Unable to apply channel settings $tract\n";
		return 1;
	}
#
	foreach my $channel (@channels) {
		if (set_channel_values($tract, $channel, @channels)) {
			exit 1;
		}
	}

	return 0;
}

sub set_channel_values {
	my ($tract, $channel) = @_;

	$config->setLevel("interfaces ds $tract channel $channel");

	my $group = $tract . "_" . $channel;

	my $hdlc = $config->returnValue("encap");
	unless (defined($hdlc)) {
		printf STDERR "No HDLC type selected for channel $channel trunk $tract.\n";
		return 1;
	}
	if (set_val($group, $keys{"hdlc"}, $hdlc)) {
		printf STDERR "Unable to apply HDLC type $hdlc for channel $channel trunck $tract\n";
		return 1;
	}

	my $timeslot = $config->returnValue("time-slot");
	unless (defined($timeslot)) {
		printf STDERR "No timeslot selected: channel $channel, trunk: $tract\n";
		return 1;
	}
	my @slots = split(/-/, $timeslot, 2);
	unless (defined($slots[0])) {
		printf STDERR "No timeslots defined for channel $channel trunk $tract\n";
		return 1;
	}
	if (set_val($group, $keys{"slot_begin"}, $slots[0])) {
		printf STDERR "Error in setting timeslots for channel $channel trunk $tract\n";
		return 1;
	}
	if (defined($slots[1])) {
		if (set_val($group, $keys{"slot_end"}, $slots[1])) {
			printf STDERR "Error in setting timelots values for $channel trunk $tract\n";
			return 1;
		}
	} else {
		if (set_val($group, $keys{"slot_end"}, $slots[0])) {
			printf STDERR "Unable to set timelots values for channel $channel trunk $tract\n";
			return 1;
		}
	}

	my $ch_iface = "$pfx$tract.$channel";
	if (system("ip link add link $base_iface name $ch_iface type vlan id $curr_vid")) {
		printf STDERR "Unable to create interface $ch_iface\n";
		return 1;
	}

	my $addr = $config->returnValue("address");

	if (defined($addr)) {
		if (system("/usr/lib/avadata/if-address add $ch_iface $addr")) {
			printf STDERR "Не удалось установить адрес для интерфейса $ch_iface\n";
			return 1;
		}
	}

	my $mtu = $config->returnValue("mtu");

	if (defined($mtu)) {
		if (system("ifconfig $ch_iface mtu $mtu")) {
			printf STDERR "Unable to set mtu for interface $ch_iface\n";
			return 1;
		}
	}

	if (system("ifconfig $ch_iface up")) {
		printf STDERR "Unaable to run interface $ch_iface\n";
		return 1;
	}

	if (set_val($group, $keys{"vid"}, $curr_vid)) {
		printf STDERR "Unable to set VID=$curr_vid for channel $channel trunk $tract\n";
		system("ip link delete $ch_iface");
		return 1;
	}

	$curr_vid = $curr_vid + 1;

	return 0;
}

sub e1tracts_update {
	# Remove old iface links
	remove_ifaces();

	# Clean config file
	$res = `echo "" > $conf_file`;

	my @ifaces = $config->listNodes("interfaces ds");

	if (scalar(@ifaces) == 0) {
		system("killall $e1_daemon 2>/dev/null");
		return 0;
	}

	if (set_val($general_group, $keys{"tract"}, @ifaces)) {
		exit 1;
	}

	foreach my $iface (@ifaces) {
		if (set_tract_values($iface)) {
			return 1;
		}
	}

	system("killall $e1_daemon 2>/dev/null");
	$res = system("nohup $e1_daemon >/dev/null");

	if ($res) {
		printf STDERR "Unable to establich peer link\n";
		return 1;
	}

	return $res;
}

sub e1tracts_delete {
	# Clean config file
	$res = `echo "" > $conf_file`;

	return 0;
}

sub remove_ifaces {
	my @ch_ifaces = `ip link | grep -E -o "${pfx}[0-9].[0-9]{1,2}"`;
	foreach my $ch_iface (@ch_ifaces) {
		if (system("ip link delete $ch_iface")) {
			printf STDERR "Unable to delete interface $ch_iface\n";
			$res = 1;
			last;
		}
	}
}

#
# main
#

exit 1 if (!defined($config));

my $res = 0;

my @ifaces = $config->listNodes("interfaces ds");

if (scalar(@ifaces) == 0) {
	system("killall $e1_daemon 2>/dev/null");
	$res = `echo "" > $conf_file`;
	exit 0;
}

if (system("ifconfig $base_iface $base_addr netmask $base_mask mtu $base_mtu")) {
	printf STDERR "Unable to run interface $base_iface\n";
	exit 1;
}

$res = e1tracts_update();

if ($res) {
	remove_ifaces();
}

exit $res;
