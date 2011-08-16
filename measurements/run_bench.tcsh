#! /bin/tcsh

foreach n ( 1 2 3 4 5 6 7 8 9 0 )
  foreach m ( 1 2 3 4 5 6 7 8 9 0 )
    ~/tmp/snort/bin/snort -c ./etc/snort_w_pps.conf -r ./srcfiles_thc/flood_router6_300pkts.pcap \
    |& fgrep 'Run time for packet processing' >> ./flood_router6_w_pps.log
  end
end

foreach n ( 1 2 3 4 5 6 7 8 9 0 )
  foreach m ( 1 2 3 4 5 6 7 8 9 0 )
    ~/tmp/snort/bin/snort -c ./etc/snort_wo_pps.conf -r ./srcfiles_thc/flood_router6_300pkts.pcap \
    |& fgrep 'Run time for packet processing' >> ./flood_router6_wo_pps.log
  end
end

foreach n ( 1 2 3 4 5 6 7 8 9 0 )
    ~/tmp/snort/bin/snort -c ./etc/snort_w_rules.conf -r ./srcfiles_thc/flood_router6_300pkts.pcap \
    |& fgrep 'Run time for packet processing' >> ./flood_router6_w_rules.log
end

