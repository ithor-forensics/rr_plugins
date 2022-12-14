#----------------------------------------------------------------------------------------------------------------------------------
# advanced_ip_scanner.pl
# Plugin for Registry Ripper, NTUSER.DAT - Parses the registry information about the usage of Advanced IP Scanner. 
#
# Change history
#   20220803 - created
#
# References
#	Based on the info found at https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
# 
# # author: A. Azpiroz, ithor.forensics@gmail.com
#----------------------------------------------------------------------------------------------------------------------------------

package advanced_ip_scanner;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              category      => "program execution",
              hasDescr      => 0, 
              hasRefs       => 0, 
              osmask        => 22, 
              version       => 20220803); 

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's Advanced IP Scanner keys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {

	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching advanced_ip_scanner v.".$VERSION);
	::rptMsg("advanced_ip_scanner v.".$VERSION); # banner
	::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\famatech\\advanced_IP_scanner';
	my $key;
	
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("Advanced IP Scanner");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");		

		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				my $name = $v->get_name();
				my $data = $v->get_data();
				if ($name eq "locale") {
					::rptMsg("INFO: locale value defines the language settings of the user.");
					::rptMsg(sprintf "%-10s %-30s",$name,$data);
					::rptMsg("");
				} elsif ($name eq "locale_timestamp"){
					::rptMsg("INFO: locale_timestamp defines the first time the application has been started.");
					# Removing the last 3 epoch digits. 
					# Pending to find a way to make getDateFromEpoch work with miliseconds
					my $data_len10 = substr $data, 0, 10;
					::rptMsg(sprintf "%-10s %-30s",$name,::getDateFromEpoch($data_len10)."Z");
					::rptMsg("");					
				} elsif ($name eq "run"){
					::rptMsg("INFO: run shows the application version.");
					::rptMsg(sprintf "%-10s %-30s",$name,$data);
					::rptMsg("");					
				}
			}
		}	
		else {
			::rptMsg($key_path." has no values.");
		}

		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $sk (@subkeys) {
				my $skname = $sk->get_name();
				if ($skname eq "State") {
					::rptMsg("Advanced IP Scanner Status Key");
					::rptMsg('Software\\famatech\\advanced_IP_scanner\\State');
					::rptMsg("LastWrite Time ".::getDateFromEpoch($sk->get_timestamp())."Z");
					::rptMsg("");

					my @skvals = $sk->get_list_of_values();
					if (scalar(@skvals) > 0) {
						foreach my $y (@skvals) {
							my $skname = $y->get_name();
							my $skdata = $y->get_data();
								if ($skname eq "IpRangesMruList") {
									::rptMsg($skname);
									::rptMsg("INFO: IpRangesMruList shows all the ranges scanned by the tool. Prefix first digit indicates frequency. ");
									::rptMsg(sprintf "%-10s %-30s","Prefix","Range scanned");
									# Transform it into an array by new line separator
									my @skdata_iprangesmrulist = split ("\n", $skdata);
									for (my $i = 0; $i <= $#skdata_iprangesmrulist; $i++) {
										my $first_element = $skdata_iprangesmrulist[$i];
										$i++;
										my $second_element = $skdata_iprangesmrulist[$i];
										::rptMsg(sprintf "%-10s %-30s",$first_element,$second_element);
									}
									::rptMsg("");
								} elsif ($skname eq "LastRangeUsed") {
									::rptMsg($skname);
									::rptMsg("INFO: LastRangeUsed indicates last range/target scanned.");
									::rptMsg(sprintf "%-10s %-30s",$skname,$skdata);
									::rptMsg("");
								} elsif ($skname eq "SearchMruList") {
									::rptMsg($skname);
									::rptMsg("INFO: SearchMruList shows the IP addresses searched via the application GUI.");
									::rptMsg(sprintf "%-10s %-30s","Prefix","Term searched");
									# Transform it into an array by new line separator
									my @skdata_searchmrulist = split ("\n", $skdata);
									for (my $i = 0; $i <= $#skdata_searchmrulist; $i++) {
										my $first_element = $skdata_searchmrulist[$i];
										$i++;
										my $second_element = $skdata_searchmrulist[$i];
										::rptMsg(sprintf "%-10s %-30s",$first_element,$second_element);
									}
									::rptMsg("");
								} elsif ($skname eq "LAST_OFN_DIR"){
									::rptMsg($skname);
									::rptMsg("INFO: LAST_OFN_DIR is the last directory used for importing targets file or saving output scan.");
									::rptMsg(sprintf "%-10s %-30s",$skname,$skdata);
									::rptMsg("");
								}
						}
					}		
					else {
						::rptMsg('Software\\famatech\\advanced_IP_scanner\\State has no values.');
					}							
				}	
				else {
					::rptMsg($key_path." has no State subkey."); 
				}				
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}				
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;
