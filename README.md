# rr_plugins
List of Regripper plugins
- advanced_ip_scanner.pl
  - Parses the following keys and values of the NTUSER.DAT hive:
    - Key: Software\famatech\advanced_IP_scanner
      - Value: locale: User's language setting. 
      - Value: locale_timestamp: First time application is executed.
      - Value: run: Application version.
    - Key:  Software\famatech\advanced_IP_scanner\State
      - Value: IpRangesMruList: Shows all the ranges scanned by the tool. Prefix first digit indicates frequency.
      - Value: LastRangeUsed: Indicates last range/target scanned
      - Value: SearchMruList: Shows the values searched via the application GUI
      - Value: LAST_OFN_DIR: Last directory used for importing targets file or saving output scan
  - Reference: Based on the info found at https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox       

## HOW TO
- Place the plugin files in your regripper plugins folder, usually located at */usr/share/regripper/plugins/*
- Run the plugin with *rip.pl -p advanced_ip_scanner -r <NTUSER.DAT_file>*
