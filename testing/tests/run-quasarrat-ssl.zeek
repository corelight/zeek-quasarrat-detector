# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/09ffabf7-774a-43a3-8c97-68f2046fd385.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff notice.log
